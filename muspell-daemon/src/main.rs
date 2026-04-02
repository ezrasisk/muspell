//! `muspelld` — the Muspell background daemon.
//!
//! ## Process lifecycle
//!
//! ```text
//! main()
//!  ├─ parse CLI args (clap)
//!  ├─ init tracing subscriber
//!  ├─ load MuspellConfig (figment: TOML + env)
//!  ├─ spawn MuspellNode (Iroh + KNS + mirror engine)
//!  ├─ spawn health HTTP server (axum)
//!  ├─ spawn KNS refresh loop
//!  └─ await SIGTERM / SIGINT
//!      └─ broadcast shutdown → join all tasks → exit(0)
//! ```

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use clap::Parser;
use muspell_core::{MirrorStats, MuspellConfig, MuspellNode};
use serde::Serialize;
use tokio::{
    signal,
    sync::{broadcast, watch},
    task::JoinSet,
    time,
};
use tracing::{error, info, warn};

// ── CLI ───────────────────────────────────────────────────────────────────────

/// Muspell daemon — decentralized discovery and persistence for Iroh nodes.
#[derive(Debug, Parser)]
#[command(name = "muspelld", version, about, long_about = None)]
struct Cli {
    /// Path to TOML config file.
    #[arg(short, long, env = "MUSPELL_CONFIG", value_name = "FILE")]
    config: Option<PathBuf>,

    /// Override log level filter (e.g. "debug", "muspell=trace,warn").
    #[arg(short, long, env = "MUSPELL_LOG")]
    log: Option<String>,

    /// Override health endpoint bind address.
    #[arg(long, env = "MUSPELL_HEALTH_ADDR")]
    health_addr: Option<String>,
}

// ── Health endpoint ───────────────────────────────────────────────────────────

/// Data returned by `GET /health`.
#[derive(Debug, Clone, Serialize)]
struct HealthResponse {
    status: &'static str,
    node_id: String,
    mirror: MirrorStats,
    uptime_secs: u64,
}

/// Shared state for the health server.
#[derive(Clone)]
struct HealthState {
    node_id: String,
    started_at: std::time::Instant,
    mirror_stats: watch::Receiver<MirrorStats>,
}

async fn health_handler(
    State(state): State<HealthState>,
) -> (StatusCode, Json<HealthResponse>) {
    let mirror = state.mirror_stats.borrow().clone();
    let uptime = state.started_at.elapsed().as_secs();
    let status = if mirror.live_peers > 0 { "ok" } else { "degraded" };
    let code   = if mirror.live_peers > 0 { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };

    (
        code,
        Json(HealthResponse {
            status,
            node_id: state.node_id.clone(),
            mirror,
            uptime_secs: uptime,
        }),
    )
}

async fn readiness_handler(
    State(state): State<HealthState>,
) -> StatusCode {
    if state.mirror_stats.borrow().live_peers > 0 {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

// ── Tracing init ──────────────────────────────────────────────────────────────

fn init_tracing(level: &str, format: &str) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let registry = tracing_subscriber::registry().with(filter);

    match format {
        "json" => registry
            .with(fmt::layer().json())
            .init(),
        "compact" => registry
            .with(fmt::layer().compact())
            .init(),
        _ => registry
            .with(fmt::layer().pretty())
            .init(),
    }
}

// ── Graceful shutdown signal ───────────────────────────────────────────────────

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let sigterm = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c  => { info!("received Ctrl+C") },
        _ = sigterm => { info!("received SIGTERM") },
    }
}

// ── KNS refresh loop ──────────────────────────────────────────────────────────

/// Periodically refresh KNS records for the node's owned names and re-register
/// peer mappings in the discovery provider.
async fn kns_refresh_loop(
    node: Arc<MuspellNode>,
    interval: Duration,
    mut shutdown: broadcast::Receiver<()>,
) {
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => {
                info!("KNS refresh loop shutting down");
                break;
            }
            _ = ticker.tick() => {
                // In a real impl, iterate over config.node.owned_names and
                // re-resolve each one, updating the discovery provider.
                info!("KNS refresh cycle");
                // node.discovery.register(...)  // update stale entries
            }
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Config ────────────────────────────────────────────────────────────
    let mut config = MuspellConfig::load_or_default(cli.config.as_ref())
        .context("failed to load configuration")?;

    // CLI flags override config file
    if let Some(log) = &cli.log {
        config.observability.log_level = log.clone();
    }
    if let Some(addr) = &cli.health_addr {
        config.observability.health_addr = addr.clone();
    }

    // ── Tracing ───────────────────────────────────────────────────────────
    init_tracing(&config.observability.log_level, &config.observability.log_format);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config_log_level = %config.observability.log_level,
        "muspelld starting"
    );

    // ── Node ──────────────────────────────────────────────────────────────
    let node = Arc::new(
        MuspellNode::start(config.clone())
            .await
            .context("failed to start MuspellNode")?,
    );

    let node_id_hex = hex::encode(node.node_id().as_bytes());
    info!(node_id = %node_id_hex, "node started");

    // ── Mirror stats watch channel ────────────────────────────────────────
    let (stats_tx, stats_rx) = watch::channel(node.mirror_stats());

    let stats_node = Arc::clone(&node);
    let stats_updater = tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            let _ = stats_tx.send(stats_node.mirror_stats());
        }
    });

    // ── Health HTTP server ─────────────────────────────────────────────────
    let health_state = HealthState {
        node_id: node_id_hex.clone(),
        started_at: std::time::Instant::now(),
        mirror_stats: stats_rx,
    };

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/readyz", get(readiness_handler))
        .with_state(health_state)
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
        );

    let health_addr: SocketAddr = config
        .observability
        .health_addr
        .parse()
        .context("invalid health_addr")?;

    let health_server = tokio::spawn(async move {
        info!(%health_addr, "health server listening");
        axum::serve(
            tokio::net::TcpListener::bind(health_addr)
                .await
                .expect("failed to bind health addr"),
            app,
        )
        .await
        .expect("health server error");
    });

    // ── KNS refresh loop ───────────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let kns_node = Arc::clone(&node);
    let kns_task = tokio::spawn(kns_refresh_loop(
        kns_node,
        Duration::from_secs(config.kns.cache_ttl_s),
        shutdown_rx,
    ));

    // ── Await shutdown signal ──────────────────────────────────────────────
    shutdown_signal().await;
    info!("shutdown initiated");

    // Broadcast shutdown to all loops
    let _ = shutdown_tx.send(());

    // Abort background helpers
    health_server.abort();
    stats_updater.abort();

    // Give tasks a grace window
    let grace = Duration::from_secs(10);
    tokio::select! {
        _ = kns_task => {}
        _ = time::sleep(grace) => {
            warn!("grace period elapsed, forcing exit");
        }
    }

    // Drain the node cleanly
    Arc::try_unwrap(node)
        .map_err(|_| anyhow::anyhow!("node Arc still held during shutdown"))?
        .shutdown()
        .await;

    info!("muspelld exited cleanly");
    Ok(())
}
