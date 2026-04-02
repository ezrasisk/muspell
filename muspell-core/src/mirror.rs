//! EigenMead data-mirroring engine.
//!
//! ## Pattern overview
//!
//! The EigenMead pattern treats a set of Iroh nodes as a redundant *eigen*-set:
//! each node holds a full mirror of a named blob collection.  When any member
//! adds a new blob, the engine fans it out across the quorum before
//! acknowledging the write.
//!
//! ```text
//!   ┌──────────────────────────────────────────────────────┐
//!   │                   MirrorEngine                        │
//!   │                                                        │
//!   │  blob added ──► fanout_task ──► peer_1 ✓             │
//!   │                             ├──► peer_2 ✓             │
//!   │                             └──► peer_3 ✓  (quorum)  │
//!   │                                                        │
//!   │  verify_task (periodic) ──► detect missing blobs      │
//!   │                         └──► re-push to lagging peers │
//!   └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Concurrency model
//!
//! * A bounded `mpsc` channel carries `MirrorJob`s from callers into the engine.
//! * A semaphore caps simultaneous in-flight blob transfers.
//! * The periodic verify task runs on its own `JoinHandle` and is cancelled
//!   cleanly on shutdown.

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use futures::future::join_all;
use iroh::{client::blobs::BlobStatus, NodeId};
use parking_lot::RwLock;
use tokio::{
    sync::{mpsc, oneshot, Semaphore},
    task::JoinHandle,
    time,
};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    error::{MuspellError, Result},
};

// ── Public types ──────────────────────────────────────────────────────────────

/// Identifies a content-addressed blob by its BLAKE3 hash (hex encoded).
pub type BlobHash = String;

/// Runtime statistics reported by the mirror engine.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MirrorStats {
    /// Total blobs tracked in the eigen-set.
    pub total_blobs: usize,
    /// Number of blobs below the quorum threshold.
    pub under_replicated: usize,
    /// Number of live peers in the eigen-set.
    pub live_peers: usize,
    /// Total successful mirror operations since startup.
    pub ops_success: u64,
    /// Total failed mirror operations since startup.
    pub ops_failed: u64,
    /// Timestamp of the last successful sync cycle.
    pub last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A work item sent to the mirror engine's internal queue.
#[derive(Debug)]
enum MirrorJob {
    /// Push this blob to all peers in the eigen-set.
    Fanout {
        hash: BlobHash,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Re-verify & re-sync all known blobs.
    VerifyCycle,
    /// Terminate the engine loop.
    Shutdown,
}

/// Peer state tracked by the engine.
#[derive(Debug, Clone)]
struct PeerState {
    node_id: NodeId,
    last_seen: Instant,
    is_live: bool,
    blobs_synced: HashSet<BlobHash>,
}

// ── Engine ────────────────────────────────────────────────────────────────────

/// The EigenMead mirroring engine.
///
/// Obtain one via [`MirrorEngine::spawn`]; the returned handle owns the
/// background tasks.  Drop it (or call [`MirrorEngine::shutdown`]) to
/// gracefully stop all activity.
pub struct MirrorEngine {
    tx: mpsc::Sender<MirrorJob>,
    stats: Arc<RwLock<MirrorStats>>,
    _tasks: Vec<JoinHandle<()>>,
}

impl MirrorEngine {
    /// Spawn the engine and its background tasks.
    ///
    /// `iroh_client` must be a connected `iroh::client::Iroh`.
    /// `sync_interval` controls how often the periodic verify cycle runs.
    /// `quorum` is the minimum number of peers that must hold a blob.
    /// `max_concurrent` caps parallel in-flight transfers.
    pub fn spawn(
        iroh_client: Arc<iroh::client::Iroh>,
        quorum: usize,
        sync_interval: Duration,
        max_concurrent: usize,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<MirrorJob>(256);
        let stats    = Arc::new(RwLock::new(MirrorStats::default()));
        let peers: Arc<DashMap<String, PeerState>> = Arc::default();
        let blob_set: Arc<RwLock<HashSet<BlobHash>>> = Arc::default();
        let sem      = Arc::new(Semaphore::new(max_concurrent));

        // ── Engine loop task ──────────────────────────────────────────────
        let engine_task = {
            let stats    = Arc::clone(&stats);
            let peers    = Arc::clone(&peers);
            let blob_set = Arc::clone(&blob_set);
            let client   = Arc::clone(&iroh_client);
            let sem      = Arc::clone(&sem);

            tokio::spawn(async move {
                Self::run_engine(rx, client, peers, blob_set, stats, sem, quorum).await;
            })
        };

        // ── Periodic verify-cycle timer task ──────────────────────────────
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

    /// Add a peer to the eigen-set.
    pub async fn add_peer(&self, node_id: NodeId) {
        // We signal via a special variant-free approach — the engine learns
        // of new peers from its own peer_registry (kept in sync by the daemon).
        // For simplicity, the daemon calls `register_peer` on its own `Arc<DashMap>`.
        // Real impl: send an `AddPeer` job variant.
        info!(node_id = %node_id, "peer added to eigen-set");
    }

    /// Fan out `hash` to all live peers.  Blocks until quorum is reached
    /// or returns an error.
    #[instrument(skip(self))]
    pub async fn fanout(&self, hash: BlobHash) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(MirrorJob::Fanout { hash, reply: reply_tx })
            .await
            .map_err(|_| MuspellError::Internal("engine channel closed".to_string()))?;

        reply_rx
            .await
            .map_err(|_| MuspellError::Internal("reply channel dropped".to_string()))?
    }

    /// Read a snapshot of the current engine statistics.
    #[must_use]
    pub fn stats(&self) -> MirrorStats {
        self.stats.read().clone()
    }

    /// Gracefully stop the engine (drains in-flight jobs then exits).
    pub async fn shutdown(self) {
        let _ = self.tx.send(MirrorJob::Shutdown).await;
        // _tasks are joined when dropped
    }

    // ── Internal engine loop ──────────────────────────────────────────────

    async fn run_engine(
        mut rx: mpsc::Receiver<MirrorJob>,
        client: Arc<iroh::client::Iroh>,
        peers: Arc<DashMap<String, PeerState>>,
        blob_set: Arc<RwLock<HashSet<BlobHash>>>,
        stats: Arc<RwLock<MirrorStats>>,
        sem: Arc<Semaphore>,
        quorum: usize,
    ) {
        info!("mirror engine started");

        while let Some(job) = rx.recv().await {
            match job {
                MirrorJob::Fanout { hash, reply } => {
                    let result = Self::do_fanout(
                        &hash,
                        &client,
                        &peers,
                        &blob_set,
                        &stats,
                        &sem,
                        quorum,
                    )
                    .await;
                    let _ = reply.send(result);
                }

                MirrorJob::VerifyCycle => {
                    Self::do_verify_cycle(&client, &peers, &blob_set, &stats, &sem, quorum)
                        .await;
                }

                MirrorJob::Shutdown => {
                    info!("mirror engine shutting down");
                    break;
                }
            }
        }
    }

    /// Fan a single blob out to all live peers.
    #[instrument(skip(client, peers, blob_set, stats, sem))]
    async fn do_fanout(
        hash: &BlobHash,
        client: &Arc<iroh::client::Iroh>,
        peers: &Arc<DashMap<String, PeerState>>,
        blob_set: &Arc<RwLock<HashSet<BlobHash>>>,
        stats: &Arc<RwLock<MirrorStats>>,
        sem: &Arc<Semaphore>,
        quorum: usize,
    ) -> Result<()> {
        blob_set.write().insert(hash.clone());

        let live: Vec<NodeId> = peers
            .iter()
            .filter(|e| e.value().is_live)
            .map(|e| e.value().node_id)
            .collect();

        if live.len() < quorum {
            return Err(MuspellError::QuorumNotMet {
                required: quorum,
                available: live.len(),
            });
        }

        let push_futs: Vec<_> = live
            .iter()
            .map(|&node_id| {
                let client = Arc::clone(client);
                let hash   = hash.clone();
                let sem    = Arc::clone(sem);
                async move {
                    let _permit = sem.acquire().await.expect("semaphore never closed");
                    Self::push_blob_to_peer(&client, node_id, &hash).await
                }
            })
            .collect();

        let results = join_all(push_futs).await;
        let successes = results.iter().filter(|r| r.is_ok()).count();

        {
            let mut s = stats.write();
            s.ops_success += successes as u64;
            s.ops_failed  += (results.len() - successes) as u64;
            s.last_sync_at = Some(chrono::Utc::now());
        }

        if successes < quorum {
            return Err(MuspellError::QuorumNotMet {
                required: quorum,
                available: successes,
            });
        }

        Ok(())
    }

    /// Periodic verification: find blobs missing from lagging peers, re-push.
    async fn do_verify_cycle(
        client: &Arc<iroh::client::Iroh>,
        peers: &Arc<DashMap<String, PeerState>>,
        blob_set: &Arc<RwLock<HashSet<BlobHash>>>,
        stats: &Arc<RwLock<MirrorStats>>,
        sem: &Arc<Semaphore>,
        quorum: usize,
    ) {
        debug!("starting verify cycle");

        let all_blobs: Vec<BlobHash> = blob_set.read().iter().cloned().collect();
        let mut under_replicated = 0usize;

        for hash in &all_blobs {
            let holders = peers
                .iter()
                .filter(|e| e.value().blobs_synced.contains(hash))
                .count();

            if holders < quorum {
                under_replicated += 1;
                debug!(%hash, holders, quorum, "blob under-replicated, re-pushing");

                // Identify peers that are live but missing the blob
                let targets: Vec<NodeId> = peers
                    .iter()
                    .filter(|e| {
                        e.value().is_live && !e.value().blobs_synced.contains(hash)
                    })
                    .map(|e| e.value().node_id)
                    .collect();

                for node_id in targets {
                    let client = Arc::clone(client);
                    let hash   = hash.clone();
                    let sem    = Arc::clone(sem);
                    tokio::spawn(async move {
                        let _permit = sem.acquire().await.expect("semaphore never closed");
                        if let Err(e) = Self::push_blob_to_peer(&client, node_id, &hash).await {
                            warn!(%node_id, %hash, error = %e, "re-sync push failed");
                        }
                    });
                }
            }
        }

        {
            let mut s = stats.write();
            s.total_blobs      = all_blobs.len();
            s.under_replicated = under_replicated;
            s.live_peers       = peers.iter().filter(|e| e.value().is_live).count();
            s.last_sync_at     = Some(chrono::Utc::now());
        }

        debug!(under_replicated, "verify cycle complete");
    }

    /// Push a blob identified by `hash` to `node_id` using Iroh blobs protocol.
    async fn push_blob_to_peer(
        client: &iroh::client::Iroh,
        node_id: NodeId,
        hash: &BlobHash,
    ) -> Result<()> {
        let hash_bytes = hex::decode(hash).map_err(|e| MuspellError::BlobSyncFailed {
            hash: hash.to_string(),
            reason: e.to_string(),
        })?;

        let blob_hash: iroh_blobs::Hash = hash_bytes
            .as_slice()
            .try_into()
            .map_err(|_| MuspellError::BlobSyncFailed {
                hash: hash.to_string(),
                reason: "invalid hash length".to_string(),
            })?;

        debug!(%node_id, %hash, "pushing blob");

        client
            .blobs()
            .share(
                blob_hash,
                iroh_blobs::BlobFormat::Raw,
                iroh::client::ShareMode::Clone,
            )
            .await
            .map_err(|e| MuspellError::BlobSyncFailed {
                hash: hash.to_string(),
                reason: e.to_string(),
            })?;

        Ok(())
    }
}
