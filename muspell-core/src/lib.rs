//! # muspell-core
//!
//! Production-grade library providing:
//! * KNS (Kaspa Name Service) resolution for Iroh `NodeId`s
//! * `StaticDiscovery`-backed peer injection (the recommended iroh 0.35 pattern
//!   for side-channel address provisioning)
//! * Ed25519 ownership-proof validation to prevent node spoofing
//! * EigenMead data mirroring via iroh-blobs + iroh-gossip
//!
//! ## Architecture overview
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                      muspell-core                         │
//! │                                                           │
//! │  ┌──────────────┐   ┌────────────────────────────────┐   │
//! │  │  KnsClient   │──▶│   KnsDiscoveryProvider         │   │
//! │  │  (reqwest +  │   │   wraps iroh::StaticDiscovery  │   │
//! │  │   backoff)   │   │   injects NodeAddr on resolve  │   │
//! │  └──────────────┘   └───────────────┬────────────────┘   │
//! │          │                          │                     │
//! │          ▼                          ▼                     │
//! │  ┌──────────────┐   ┌────────────────────────────────┐   │
//! │  │  Ownership   │   │   MirrorEngine  (EigenMead)    │   │
//! │  │  Validator   │   │   BlobTicket gossip fanout     │   │
//! │  │  (ed25519)   │   │   + periodic quorum verify     │   │
//! │  └──────────────┘   └────────────────────────────────┘   │
//! └──────────────────────────────────────────────────────────┘
//! ```

#![forbid(unsafe_code)]
#![warn(
    clippy::pedantic,
    clippy::cargo,
    missing_docs,
    rustdoc::broken_intra_doc_links
)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod discovery;
pub mod error;
pub mod kns;
pub mod mirror;
pub mod node;
pub mod security;

// Convenient top-level re-exports consumed by daemon / CLI.
pub use config::MuspellConfig;
pub use discovery::KnsDiscoveryProvider;
pub use error::{MuspellError, Result};
pub use kns::{KnsClient, KnsRecord, KnsResolver};
pub use mirror::{MirrorEngine, MirrorStats};
pub use node::MuspellNode;
pub use security::OwnershipValidator;
