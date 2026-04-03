//! Structured, library-level error types for `muspell-core`.
//!
//! Design contract:
//! * All public API surface returns `Result<T, MuspellError>`.
//! * Callers (daemon, CLI) wrap these with `anyhow::Context` for richer traces.
//! * Every variant carries enough context to be actionable without reading
//!   source code.

use thiserror::Error;

/// Canonical `Result` alias used throughout the crate.
pub type Result<T, E = MuspellError> = std::result::Result<T, E>;

/// All error conditions that can originate inside `muspell-core`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MuspellError {
    // ── KNS resolution ────────────────────────────────────────────────────
    /// The KNS RPC endpoint returned a transport-level error.
    #[error("KNS transport error: {0}")]
    KnsTransport(#[from] reqwest::Error),

    /// A KNS name resolved to a record with an unexpected format or version.
    #[error("KNS record malformed for '{name}': {reason}")]
    KnsMalformedRecord { name: String, reason: String },

    /// The name was not found in KNS after exhausting all retry attempts.
    #[error("KNS name not found: '{name}' (tried {attempts} times)")]
    KnsNotFound { name: String, attempts: u32 },

    /// The KNS RPC call timed out.
    #[error("KNS RPC timed out after {timeout_ms}ms for name '{name}'")]
    KnsTimeout { name: String, timeout_ms: u64 },

    // ── Security / ownership ──────────────────────────────────────────────
    /// The Iroh node public key does not match the KNS ownership record.
    #[error("node key mismatch: KNS owner={kns_owner}, presented={presented}")]
    NodeKeyMismatch { kns_owner: String, presented: String },

    /// The ownership proof signature is invalid.
    #[error("invalid ownership proof signature for node '{node_id}'")]
    InvalidOwnershipProof { node_id: String },

    /// Ed25519 cryptographic operation failed.
    #[error("ed25519 error: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),

    // ── Iroh integration ──────────────────────────────────────────────────
    // NOTE: iroh::client::RpcError was removed in iroh 0.28 along with the
    // entire iroh::client module. Iroh errors are now surfaced as anyhow::Error
    // from protocol handlers and endpoint operations. We wrap them as strings
    // here to keep our library error enum self-contained.
    /// An Iroh endpoint or protocol operation failed.
    #[error("Iroh error: {0}")]
    Iroh(String),

    /// Could not connect to a peer discovered via KNS.
    #[error("failed to connect to peer '{node_id}': {reason}")]
    PeerConnectionFailed { node_id: String, reason: String },

    // ── Mirroring (EigenMead) ─────────────────────────────────────────────
    /// A blob sync operation failed.
    #[error("blob sync failed for hash '{hash}': {reason}")]
    BlobSyncFailed { hash: String, reason: String },

    /// The mirror quorum could not be reached (not enough live peers).
    #[error("mirror quorum not met: need {required}, have {available} live peers")]
    QuorumNotMet { required: usize, available: usize },

    // ── Configuration ─────────────────────────────────────────────────────
    /// Configuration parsing failed.
    #[error("configuration error: {0}")]
    Config(String),

    // ── I/O ───────────────────────────────────────────────────────────────
    /// Filesystem I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // ── Catch-all ────────────────────────────────────────────────────────
    /// Unexpected internal error (should never be surfaced to users in prod).
    #[error("internal error: {0}")]
    Internal(String),
}

impl MuspellError {
    /// Returns `true` if the error is likely transient and retrying makes sense.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            MuspellError::KnsTransport(_)
                | MuspellError::KnsTimeout { .. }
                | MuspellError::PeerConnectionFailed { .. }
                | MuspellError::BlobSyncFailed { .. }
        )
    }

    /// Wrap any error that came from an iroh endpoint/protocol call.
    pub fn iroh(e: impl std::fmt::Display) -> Self {
        MuspellError::Iroh(e.to_string())
    }
}
