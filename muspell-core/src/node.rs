//! [`MuspellNode`] — the top-level assembly that wires together Iroh,
//! the KNS discovery provider, and the mirror engine.
//!
//! Consumers (daemon, tests) should interact with this type rather than
//! touching submodules directly.

use std::{sync::Arc, time::Duration};

use iroh::{Endpoint, NodeId, RelayMode};
use tracing::{info, instrument};

use crate::{
    config::MuspellConfig,
    discovery::KnsDiscoveryProvider,
    error::{MuspellError, Result},
    kns::KnsClient,
    mirror::{BlobHash, MirrorEngine, MirrorStats},
    security::OwnershipValidator,
};

/// The fully-assembled Muspell node.
pub struct MuspellNode {
    /// Underlying Iroh endpoint (QUIC transport + multiplexing).
    pub endpoint: Endpoint,

    /// KNS-backed discovery provider registered with the endpoint.
    pub discovery: Arc<KnsDiscoveryProvider<KnsClient>>,

    /// EigenMead mirror engine.
    pub mirror: MirrorEngine,

    config: MuspellConfig,
}

impl MuspellNode {
    /// Build and start a node from the provided configuration.
    ///
    /// Steps performed:
    /// 1. Load (or generate) the node's Ed25519 secret key.
    /// 2. Validate any `owned_names` against KNS ownership records.
    /// 3. Stand up the Iroh endpoint with the KNS discovery provider.
    /// 4. Start the mirror engine.
    ///
    /// # Errors
    ///
    /// Returns a rich `MuspellError` for each failure mode. The daemon wraps
    /// this with `anyhow::Context` for stack-trace enrichment.
    #[instrument(skip(config))]
    pub async fn start(config: MuspellConfig) -> Result<Self> {
        // ── 1. Secret key ─────────────────────────────────────────────────
        let secret_key = Self::load_or_generate_key(&config).await?;
        let node_id    = NodeId::from(secret_key.public());

        info!(
            node_id = %node_id,
            "local node identity"
        );

        // ── 2. KNS client & discovery provider ───────────────────────────
        let kns_client = Arc::new(KnsClient::new(config.kns.clone())?);
        let discovery  = Arc::new(KnsDiscoveryProvider::new(Arc::clone(&kns_client)));

        // ── 3. Validate owned names (anti-spoofing) ───────────────────────
        let node_id_hex = hex::encode(node_id.as_bytes());
        for name in &config.node.owned_names {
            info!(name, "validating owned KNS name");
            let record = kns_client.resolve(name).await?;
            OwnershipValidator::validate(&record, &node_id_hex)?;
            discovery.register(node_id_hex.clone(), name.clone());
            info!(name, "KNS ownership confirmed");
        }

        // ── 4. Build Iroh endpoint ────────────────────────────────────────
        let relay_mode = if config.node.relay_urls.is_empty() {
            RelayMode::Default
        } else {
            RelayMode::Custom(
                config
                    .node
                    .relay_urls
                    .iter()
                    .map(|u| u.clone().into())
                    .collect(),
            )
        };

        let bind_addr: std::net::SocketAddr = config
            .node
            .bind_addr
            .parse()
            .map_err(|e: std::net::AddrParseError| MuspellError::Config(e.to_string()))?;

        let endpoint = Endpoint::builder()
            .secret_key(secret_key)
            .relay_mode(relay_mode)
            .bind_addr_v4(bind_addr.into())
            .discovery(Box::new({
                // Iroh requires a `Box<dyn Discovery>`, so we wrap a clone of
                // the Arc behind a newtype that forwards to the shared registry.
                DiscoveryForwarder(Arc::clone(&discovery))
            }))
            .bind()
            .await
            .map_err(|e| MuspellError::IrohNode(e.into()))?;

        info!(
            node_addr = ?endpoint.node_addr().await.ok(),
            "Iroh endpoint bound"
        );

        // ── 5. Mirror engine ──────────────────────────────────────────────
        let iroh_client = Arc::new(endpoint.client().clone());
        let sync_interval = Duration::from_secs(config.mirror.sync_interval_s);
        let mirror = MirrorEngine::spawn(
            iroh_client,
            config.mirror.quorum,
            sync_interval,
            config.mirror.max_concurrent_syncs,
        );

        Ok(Self { endpoint, discovery, mirror, config })
    }

    // ── Public helpers ────────────────────────────────────────────────────

    /// Fan out a blob to the mirror quorum.
    pub async fn mirror_blob(&self, hash: BlobHash) -> Result<()> {
        self.mirror.fanout(hash).await
    }

    /// Current mirror engine statistics.
    pub fn mirror_stats(&self) -> MirrorStats {
        self.mirror.stats()
    }

    /// The local Iroh `NodeId`.
    pub fn node_id(&self) -> NodeId {
        self.endpoint.node_id()
    }

    /// Gracefully stop the node.
    pub async fn shutdown(self) {
        info!("shutting down MuspellNode");
        self.mirror.shutdown().await;
        let _ = self.endpoint.close().await;
    }

    // ── Private ───────────────────────────────────────────────────────────

    async fn load_or_generate_key(
        config: &MuspellConfig,
    ) -> Result<iroh::SecretKey> {
        let path = &config.node.key_path;

        if path.exists() {
            let bytes = tokio::fs::read(path).await?;
            let key = iroh::SecretKey::try_from_openssh(&bytes)
                .map_err(|e| MuspellError::Config(format!("bad key file: {e}")))?;
            info!(path = %path.display(), "loaded existing node key");
            return Ok(key);
        }

        // Generate fresh key and persist it (mode 0600)
        let key = iroh::SecretKey::generate();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let openssh = key.to_openssh().map_err(|e| MuspellError::Config(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true).mode(0o600);
            use std::io::Write;
            let mut file = opts.open(path)?;
            file.write_all(openssh.as_bytes())?;
        }
        #[cfg(not(unix))]
        tokio::fs::write(path, openssh.as_bytes()).await?;

        info!(path = %path.display(), "generated new node key");
        Ok(key)
    }
}

// ── Discovery forwarder newtype ────────────────────────────────────────────────

/// Thin wrapper so we can hand a `Box<dyn Discovery>` to Iroh while keeping
/// the `Arc<KnsDiscoveryProvider>` alive elsewhere.
struct DiscoveryForwarder(Arc<KnsDiscoveryProvider<KnsClient>>);

impl iroh::discovery::Discovery for DiscoveryForwarder {
    fn resolve(
        &self,
        endpoint: iroh::Endpoint,
        node_id: NodeId,
    ) -> Option<iroh::discovery::BoxedFuture<iroh::discovery::BoxedStream<iroh::discovery::DiscoveryItem>>>
    {
        self.0.resolve(endpoint, node_id)
    }
}
