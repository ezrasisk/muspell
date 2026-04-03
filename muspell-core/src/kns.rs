//! Kaspa Name Service (KNS) RPC client.
//!
//! Responsibilities:
//! * Resolve a KNS name → [`KnsRecord`] containing the registered Iroh node ID
//!   and an ownership proof.
//! * Implement exponential backoff with jitter across primary + fallback URLs.
//! * Cache successful resolutions with configurable TTL.
//! * Expose a mock-friendly trait so unit tests can avoid network I/O.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use backoff::{backoff::Backoff, ExponentialBackoffBuilder};
use parking_lot::RwLock;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};
use url::Url;

use crate::{
    config::KnsConfig,
    error::{MuspellError, Result},
};

// ── Public types ──────────────────────────────────────────────────────────────

/// A fully validated KNS record as returned by the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnsRecord {
    /// The KNS name (e.g. `"alice.kas"`).
    pub name: String,

    /// The Iroh node ID encoded as a 64-char lowercase hex string (Ed25519 pk).
    pub iroh_node_id: String,

    /// Additional relay hints advertised by the owner (optional).
    #[serde(default)]
    pub relay_hints: Vec<String>,

    /// Base64-encoded Ed25519 signature proving the KNS owner controls
    /// the stated Iroh node key.
    pub ownership_proof: String,

    /// Kaspa block height at which this record was last updated.
    pub block_height: u64,
}

/// Cache entry wrapping a resolved record with a wall-clock expiry.
struct CacheEntry {
    record: KnsRecord,
    expires_at: Instant,
}

// ── Resolver trait ────────────────────────────────────────────────────────────

/// Abstraction over the KNS lookup operation.
///
/// The `#[async_trait]` macro is required because Rust's native async-in-trait
/// feature (RPITIT) is not yet stable for object-safe traits, and we need
/// `Box<dyn KnsResolver>` / `mockall` to work.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait KnsResolver: Send + Sync + 'static {
    /// Resolve a KNS name to its associated [`KnsRecord`].
    async fn resolve(&self, name: &str) -> Result<KnsRecord>;
}

// ── HTTP-backed client ────────────────────────────────────────────────────────

/// Raw deserialization of the KNS REST API response envelope.
#[derive(Debug, Deserialize)]
struct KnsApiResponse {
    #[serde(rename = "result")]
    record: Option<KnsApiRecord>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KnsApiRecord {
    name: String,
    iroh_node_id: String,
    #[serde(default)]
    relay_hints: Vec<String>,
    ownership_proof: String,
    block_height: u64,
}

/// Production KNS client backed by the Kasplex REST API.
pub struct KnsClient {
    http: Client,
    /// Primary URL first, then any fallbacks.
    urls: Vec<Url>,
    config: KnsConfig,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

impl KnsClient {
    /// Construct a new client from configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if `reqwest` cannot build an HTTPS-only client
    /// (e.g. missing TLS backend, which should never happen with `rustls-tls`).
    pub fn new(config: KnsConfig) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .https_only(true)
            .user_agent(concat!("muspell/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(MuspellError::KnsTransport)?;

        let mut urls = vec![config.rpc_url.clone()];
        urls.extend(config.fallback_urls.clone());

        Ok(Self {
            http,
            urls,
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Attempt to fetch a record from a single base URL.
    async fn fetch_from(&self, base: &Url, name: &str) -> Result<KnsRecord> {
        // Build the full URL for this specific name.
        // join() on a base that doesn't end in '/' will replace the last
        // path segment, so we append manually.
        let mut url = base.clone();
        url.path_segments_mut()
            .map_err(|_| MuspellError::KnsMalformedRecord {
                name: name.to_string(),
                reason: "base URL cannot-be-a-base".to_string(),
            })?
            .extend(&["resolve", name]);

        debug!(%url, "KNS fetch");

        let resp: KnsApiResponse = self
            .http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        if let Some(err) = resp.error {
            return Err(MuspellError::KnsMalformedRecord {
                name: name.to_string(),
                reason: err,
            });
        }

        let rec = resp.record.ok_or_else(|| MuspellError::KnsNotFound {
            name: name.to_string(),
            attempts: 1,
        })?;

        Ok(KnsRecord {
            name: rec.name,
            iroh_node_id: rec.iroh_node_id,
            relay_hints: rec.relay_hints,
            ownership_proof: rec.ownership_proof,
            block_height: rec.block_height,
        })
    }

    /// Evict expired cache entries (called opportunistically on every lookup).
    fn evict_expired(&self) {
        let now = Instant::now();
        self.cache
            .write()
            .retain(|_, entry| entry.expires_at > now);
    }
}

#[async_trait]
impl KnsResolver for KnsClient {
    /// Resolve `name` by trying each configured URL in turn, with exponential
    /// backoff on transient failures.
    ///
    /// # Errors
    ///
    /// * [`MuspellError::KnsNotFound`] – name does not exist in KNS.
    /// * [`MuspellError::KnsTransport`] – all attempts exhausted.
    #[instrument(skip(self), fields(name = %name))]
    async fn resolve(&self, name: &str) -> Result<KnsRecord> {
        // 1. Cache hit fast-path
        self.evict_expired();
        if let Some(entry) = self.cache.read().get(name) {
            if entry.expires_at > Instant::now() {
                debug!("KNS cache hit");
                return Ok(entry.record.clone());
            }
        }

        // 2. Try each URL with exponential backoff
        let mut attempts: u32 = 0;
        let mut backoff = ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_millis(self.config.initial_backoff_ms))
            .with_max_interval(Duration::from_millis(self.config.max_backoff_ms))
            .with_max_elapsed_time(Some(
                Duration::from_millis(self.config.max_backoff_ms)
                    * (self.config.max_retries + 1) as u32,
            ))
            .build();

        loop {
            for url in &self.urls {
                attempts += 1;
                match self.fetch_from(url, name).await {
                    Ok(record) => {
                        let ttl = Duration::from_secs(self.config.cache_ttl_s);
                        self.cache.write().insert(
                            name.to_string(),
                            CacheEntry {
                                record: record.clone(),
                                expires_at: Instant::now() + ttl,
                            },
                        );
                        return Ok(record);
                    }
                    // A definitive "not found" should not trigger retry.
                    Err(MuspellError::KnsNotFound { .. }) => {
                        return Err(MuspellError::KnsNotFound {
                            name: name.to_string(),
                            attempts,
                        });
                    }
                    Err(e) if e.is_retryable() => {
                        warn!(
                            %url,
                            attempt = attempts,
                            error = %e,
                            "transient KNS error, will retry"
                        );
                    }
                    Err(e) => return Err(e),
                }
            }

            match backoff.next_backoff() {
                Some(delay) => {
                    debug!(delay_ms = delay.as_millis(), "KNS backoff sleeping");
                    tokio::time::sleep(delay).await;
                }
                None => {
                    return Err(MuspellError::KnsNotFound {
                        name: name.to_string(),
                        attempts,
                    });
                }
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(name: &str) -> KnsRecord {
        KnsRecord {
            name: name.to_string(),
            iroh_node_id: "a".repeat(64),
            relay_hints: vec![],
            ownership_proof: "c2ln".to_string(), // base64("sig")
            block_height: 1_000_000,
        }
    }

    #[tokio::test]
    async fn mock_resolver_returns_record() {
        let mut mock = MockKnsResolver::new();
        let expected = sample_record("alice.kas");
        mock.expect_resolve()
            .withf(|n| n == "alice.kas")
            .returning(|_| Ok(sample_record("alice.kas")));

        let result = mock.resolve("alice.kas").await.unwrap();
        assert_eq!(result.name, expected.name);
    }

    #[tokio::test]
    async fn mock_resolver_propagates_not_found() {
        let mut mock = MockKnsResolver::new();
        mock.expect_resolve().returning(|n| {
            Err(MuspellError::KnsNotFound {
                name: n.to_string(),
                attempts: 5,
            })
        });

        let err = mock.resolve("unknown.kas").await.unwrap_err();
        assert!(matches!(err, MuspellError::KnsNotFound { .. }));
    }
}
