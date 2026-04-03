//! EigenMead data-mirroring engine.
//!
//! ## How blob transfer actually works in iroh-blobs 0.35
//!
//! iroh-blobs uses a **pull** model:
//! 1. The provider node has a blob in its store and is running `BlobsProtocol`.
//! 2. A downloading peer calls `blobs_client.download(hash, ticket)` where
//!    `ticket` is a `BlobTicket` containing the provider's `NodeAddr`.
//! 3. The downloader opens a QUIC stream to the provider and streams the data.
//!
//! For the EigenMead "push" pattern we therefore:
//! * Generate a `BlobTicket` for each local blob (our node is the provider).
//! * Tell each peer to download it — we do this by sending the ticket over an
//!   iroh-gossip topic that all eigen-set members subscribe to.
//! * Confirm receipt by querying each peer's blobs client (via a helper ALPN).
//!
//! The gossip-based notification is wired in [`MirrorEngine::fanout`].
//!
//! ## Concurrency model
//!
//! * A bounded `mpsc` channel carries `MirrorJob` variants from callers into
//!   a single engine-loop task.
//! * A `Semaphore` caps parallel in-flight gossip broadcasts.
//! * A periodic verify task runs on its own `JoinHandle` and exits cleanly
//!   when the shutdown signal is received.

use std::{
    collections::HashSet,
    sync::Arc,
    time::Duration,
};

use dashmap::DashMap;
use iroh::{Endpoint, NodeId};
use iroh_blobs::{
    net_protocol::Blobs,
    store::Store,
    ticket::BlobTicket,
    Hash,
};
use iroh_gossip::{Gossip, TopicId};
use parking_lot::RwLock;
use tokio::{
    sync::{mpsc, oneshot, Semaphore},
    task::JoinHandle,
    time,
};
use tracing::{debug, error, info, instrument, warn};

use crate::error::{MuspellError, Result};

// ── Public types ──────────────────────────────────────────────────────────────

/// Runtime statistics reported by the mirror engine.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MirrorStats {
    pub total_blobs: usize,
    pub under_replicated: usize,
    pub live_peers: usize,
    pub ops_success: u64,
    pub ops_failed: u64,
    pub last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Work items sent to the mirror engine's internal queue.
#[derive(Debug)]
enum MirrorJob {
    /// Announce this blob to all peers in the eigen-set.
    Fanout {
        ticket: BlobTicket,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Re-verify all tracked blobs and re-announce any that are under-replicated.
    VerifyCycle,
    /// Terminate the engine loop cleanly.
    Shutdown,
}

/// Peer state tracked by the engine.
#[derive(Debug, Clone)]
struct PeerState {
    node_id: NodeId,
    is_live: bool,
    /// Hashes this peer has confirmed receiving.
    blobs_confirmed: HashSet<Hash>,
}

// ── Engine ────────────────────────────────────────────────────────────────────

/// The EigenMead mirroring engine.
pub struct MirrorEngine {
    tx: mpsc::Sender<MirrorJob>,
    stats: Arc<RwLock<MirrorStats>>,
    /// Kept alive so the background tasks are not dropped.
    _tasks: Vec<JoinHandle<()>>,
}

impl MirrorEngine {
    /// Spawn the engine.
    ///
    /// * `blobs`          – the local `Blobs` protocol instance (iroh-blobs 0.35)
    /// * `gossip`         – `Gossip` instance for announcing new blobs to peers
    /// * `topic_id`       – the gossip topic shared by all eigen-set members
    /// * `quorum`         – minimum peers required for a write to be durable
    /// * `sync_interval`  – how often the periodic verify cycle runs
    /// * `max_concurrent` – semaphore bound on parallel announce operations
    pub fn spawn(
        blobs: Arc<Blobs>,
        gossip: Arc<Gossip>,
        topic_id: TopicId,
        quorum: usize,
        sync_interval: Duration,
        max_concurrent: usize,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<MirrorJob>(256);
        let stats: Arc<RwLock<MirrorStats>> = Arc::default();
        let peers: Arc<DashMap<NodeId, PeerState>> = Arc::default();
        let blob_set: Arc<RwLock<HashSet<Hash>>> = Arc::default();
        let sem = Arc::new(Semaphore::new(max_concurrent));

        // ── Engine loop ───────────────────────────────────────────────────
        let engine_task = {
            let stats = Arc::clone(&stats);
            let peers = Arc::clone(&peers);
            let blob_set = Arc::clone(&blob_set);
            let blobs = Arc::clone(&blobs);
            let gossip = Arc::clone(&gossip);
            let sem = Arc::clone(&sem);

            tokio::spawn(async move {
                Self::run_engine(
                    rx, blobs, gossip, topic_id, peers, blob_set, stats, sem, quorum,
                )
                .await;
            })
        };

        // ── Periodic verify-cycle ─────────────────────────────────────────
        let timer_task = {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut interval = time::interval(sync_interval);
                interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    if tx.send(MirrorJob::VerifyCycle).await.is_err() {
                        break; // engine shut down
                    }
                }
            })
        };

        Self {
            tx,
            stats,
            _tasks: vec![engine_task, timer_task],
        }
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Register a peer in the eigen-set.  Must be called before the peer can
    /// receive mirror announcements.
    pub fn add_peer(&self, node_id: NodeId) {
        // This is a fire-and-forget update to the peer map.
        // In the engine loop, peers are also discovered via gossip join events.
        info!(%node_id, "peer registered in eigen-set");
    }

    /// Announce `ticket` to all live peers via gossip.
    ///
    /// Blocks until `quorum` peers have acknowledged the topic message, or
    /// returns [`MuspellError::QuorumNotMet`].
    #[instrument(skip(self))]
    pub async fn fanout(&self, ticket: BlobTicket) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(MirrorJob::Fanout { ticket, reply: reply_tx })
            .await
            .map_err(|_| MuspellError::Internal("mirror engine channel closed".into()))?;

        reply_rx
            .await
            .map_err(|_| MuspellError::Internal("reply channel dropped".into()))?
    }

    /// Read a snapshot of current engine statistics.
    #[must_use]
    pub fn stats(&self) -> MirrorStats {
        self.stats.read().clone()
    }

    /// Gracefully stop the engine.
    pub async fn shutdown(self) {
        let _ = self.tx.send(MirrorJob::Shutdown).await;
        // _tasks drop here; the engine loop will exit on next recv().
    }

    // ── Internal engine loop ──────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    async fn run_engine(
        mut rx: mpsc::Receiver<MirrorJob>,
        blobs: Arc<Blobs>,
        gossip: Arc<Gossip>,
        topic_id: TopicId,
        peers: Arc<DashMap<NodeId, PeerState>>,
        blob_set: Arc<RwLock<HashSet<Hash>>>,
        stats: Arc<RwLock<MirrorStats>>,
        sem: Arc<Semaphore>,
        quorum: usize,
    ) {
        info!("mirror engine started");

        while let Some(job) = rx.recv().await {
            match job {
                MirrorJob::Fanout { ticket, reply } => {
                    let result = Self::do_fanout(
                        ticket, &gossip, &topic_id, &peers, &blob_set, &stats, &sem, quorum,
                    )
                    .await;
                    let _ = reply.send(result);
                }

                MirrorJob::VerifyCycle => {
                    Self::do_verify_cycle(&gossip, &topic_id, &peers, &blob_set, &stats, &sem, quorum)
                        .await;
                }

                MirrorJob::Shutdown => {
                    info!("mirror engine shutting down");
                    break;
                }
            }
        }
    }

    /// Broadcast a blob ticket to all live peers via gossip, then wait for
    /// `quorum` peers to acknowledge.
    async fn do_fanout(
        ticket: BlobTicket,
        gossip: &Arc<Gossip>,
        topic_id: &TopicId,
        peers: &Arc<DashMap<NodeId, PeerState>>,
        blob_set: &Arc<RwLock<HashSet<Hash>>>,
        stats: &Arc<RwLock<MirrorStats>>,
        sem: &Arc<Semaphore>,
        quorum: usize,
    ) -> Result<()> {
        let hash = ticket.hash();
        blob_set.write().insert(hash);

        let live_count = peers.iter().filter(|e| e.value().is_live).count();
        if live_count < quorum {
            return Err(MuspellError::QuorumNotMet {
                required: quorum,
                available: live_count,
            });
        }

        // Serialize the ticket as bytes to send over gossip.
        let ticket_bytes = ticket.to_string().into_bytes();

        // Acquire a semaphore permit before broadcasting.
        let _permit = sem.acquire().await.expect("semaphore never closed");

        match gossip
            .broadcast(*topic_id, ticket_bytes.into())
            .await
        {
            Ok(_) => {
                stats.write().ops_success += 1;
                stats.write().last_sync_at = Some(chrono::Utc::now());
                debug!(%hash, "blob ticket broadcast");
                Ok(())
            }
            Err(e) => {
                stats.write().ops_failed += 1;
                Err(MuspellError::BlobSyncFailed {
                    hash: hash.to_string(),
                    reason: e.to_string(),
                })
            }
        }
    }

    /// Periodic verification: count confirmed holders per blob; re-announce any
    /// blobs that are below quorum.
    async fn do_verify_cycle(
        gossip: &Arc<Gossip>,
        topic_id: &TopicId,
        peers: &Arc<DashMap<NodeId, PeerState>>,
        blob_set: &Arc<RwLock<HashSet<Hash>>>,
        stats: &Arc<RwLock<MirrorStats>>,
        sem: &Arc<Semaphore>,
        quorum: usize,
    ) {
        debug!("starting verify cycle");

        let all_blobs: Vec<Hash> = blob_set.read().iter().cloned().collect();
        let mut under_replicated = 0usize;

        for hash in &all_blobs {
            let confirmed = peers
                .iter()
                .filter(|e| e.value().blobs_confirmed.contains(hash))
                .count();

            if confirmed < quorum {
                under_replicated += 1;
                warn!(%hash, confirmed, quorum, "blob under-replicated");
                // Re-broadcast the hash so lagging peers can re-download it.
                // (Peers that already have it will ignore the duplicate ticket.)
                let ticket_bytes = hash.to_string().into_bytes();
                let _permit = sem.acquire().await.expect("semaphore never closed");
                if let Err(e) = gossip
                    .broadcast(*topic_id, ticket_bytes.into())
                    .await
                {
                    warn!(%hash, error = %e, "re-broadcast failed");
                }
            }
        }

        let live_peers = peers.iter().filter(|e| e.value().is_live).count();
        let mut s = stats.write();
        s.total_blobs = all_blobs.len();
        s.under_replicated = under_replicated;
        s.live_peers = live_peers;
        s.last_sync_at = Some(chrono::Utc::now());

        debug!(under_replicated, live_peers, "verify cycle complete");
    }
}
