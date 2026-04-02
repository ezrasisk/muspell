# Muspell — Architecture Reference

> **Muspell** (from Norse mythology: the realm of fire) is a decentralised
> discovery and persistence layer for [Iroh](https://iroh.computer) nodes,
> anchored to the **Kaspa Name Service (KNS)** for human-readable peer identity.

---

## 1. High-Level System Map

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              Muspell Workspace                              │
│                                                                             │
│  ┌─────────────────┐   ┌─────────────────────────┐   ┌──────────────────┐ │
│  │  muspell-cli    │   │    muspell-daemon        │   │  muspell-core    │ │
│  │  (binary)       │──▶│    (binary: muspelld)    │──▶│  (library)       │ │
│  │  clap CLI       │   │    tokio runtime         │   │  KNS + Iroh      │ │
│  │  HTTP client    │   │    axum health server    │   │  EigenMead       │ │
│  └─────────────────┘   │    SIGTERM handler       │   │  security        │ │
│                         └─────────────────────────┘   └──────────────────┘ │
└────────────────────────────────────────────────────────────────────────────┘
        │                           │
        │  HTTP /health             │  libp2p QUIC
        │  (status queries)         ▼
        │                 ┌─────────────────────┐
        │                 │   Iroh Endpoint      │
        │                 │   (QUIC transport)   │
        │                 └──────────┬──────────┘
        │                            │  NodeId lookup
        │                            ▼
        │                 ┌─────────────────────┐        ┌───────────────┐
        │                 │  KnsDiscoveryProv.  │───RPC──▶  KNS REST API │
        │                 │  (Iroh Discovery)   │        │  (Kasplex)    │
        │                 └──────────┬──────────┘        └───────────────┘
        │                            │  valid record
        │                            ▼
        │                 ┌─────────────────────┐
        └────────────────▶│  OwnershipValidator  │
                          │  (Ed25519 verify)   │
                          └──────────┬──────────┘
                                     │  verified peers
                                     ▼
                          ┌─────────────────────┐
                          │   MirrorEngine       │
                          │   (EigenMead)        │
                          │   fanout + verify    │
                          └─────────────────────┘
```

---

## 2. Component Breakdown

### 2.1 `muspell-core` (library)

| Module | Responsibility |
|--------|---------------|
| `config` | Layered config (TOML + env) via `figment` |
| `error` | `thiserror`-based error taxonomy with `is_retryable()` |
| `kns` | HTTP client, exponential backoff, TTL cache, mock trait |
| `security` | Ed25519 ownership-proof generation and constant-time verification |
| `discovery` | Iroh `Discovery` trait impl backed by KNS |
| `mirror` | EigenMead fanout engine with quorum tracking |
| `node` | Assembly: wires all modules into a single `MuspellNode` handle |

### 2.2 `muspell-daemon` (`muspelld`)

* Tokio multi-thread runtime.
* Loads config, calls `MuspellNode::start`.
* Spawns three independent tasks, all joined on shutdown:
  1. **Health server** — Axum on `127.0.0.1:9090` (`/health`, `/readyz`).
  2. **Stats watcher** — pushes mirror stats into a `watch` channel every 5 s.
  3. **KNS refresh loop** — re-resolves owned names on `cache_ttl_s` cadence.
* Catches `SIGTERM` and `Ctrl+C`, broadcasts shutdown, drains with a 10 s grace window.

### 2.3 `muspell-cli` (`muspell`)

```
muspell node info              # local NodeId
muspell node status            # HTTP GET /health on daemon
muspell kns resolve alice.kas  # raw KNS record
muspell kns verify  alice.kas  # + ownership proof check
muspell mirror add  <hash>     # request fanout to quorum
muspell mirror stats           # engine metrics
muspell config show            # effective merged config
muspell config validate        # parse-only check
```

---

## 3. KNS Discovery Flow

```
Iroh needs address for NodeId X
          │
          ▼
KnsDiscoveryProvider::resolve()
          │
          ├─ registry lookup: NodeId → KNS name
          │    (populated by daemon on startup / refresh)
          │
          ├─ KnsClient::resolve(name)
          │    ├─ cache hit? → return immediately
          │    └─ HTTP GET /v1/kns/resolve/{name}
          │         ├─ primary URL → exponential backoff
          │         └─ fallback URLs (if primary fails)
          │
          ├─ OwnershipValidator::verify_ownership_proof()
          │    ├─ decode node_id_hex → Ed25519 VerifyingKey
          │    ├─ decode proof_b64   → Ed25519 Signature
          │    └─ verify_strict(canonical_msg, sig)  ← constant-time
          │
          └─ convert relay_hints → Iroh AddrInfo stream
```

**Anti-spoofing guarantee**: A malicious relay cannot impersonate a node
because it cannot forge an Ed25519 signature over
`"muspell-ownership::<node_id>"` without the node's private key.

---

## 4. EigenMead Mirroring Pattern

```
New blob arrives (local write or peer gossip)
          │
          ▼
MirrorEngine::fanout(hash)
          │
          ├─ check live peers ≥ quorum  (else QuorumNotMet error)
          │
          ├─ for each live peer (concurrent, sem-limited):
          │    └─ iroh blobs::share(hash, Raw, Clone) → peer
          │
          ├─ collect results; count successes
          │
          └─ if successes < quorum → QuorumNotMet


Periodic verify cycle (default: every 60 s)
          │
          ├─ for each tracked blob hash:
          │    └─ count peers that hold it
          │         └─ if < quorum → spawn re-push to lagging peers
          │
          └─ update MirrorStats (live_peers, under_replicated, etc.)
```

### Quorum Semantics

A write is **durable** when `quorum` distinct peers have acknowledged receipt.
The default quorum of **3** tolerates up to 2 simultaneous node failures while
remaining writable.

---

## 5. Security Model

| Threat | Mitigation |
|--------|-----------|
| Node impersonation via relay | Ed25519 ownership proof validated on every KNS resolution |
| DNS/HTTP MITM against KNS API | `reqwest` with `https_only(true)` + `rustls` |
| Timing oracle on key comparison | `constant_time_eq` XOR fold in `security.rs` |
| Malformed KNS records | `KnsMalformedRecord` error; strict deserialization via `#[serde(deny_unknown_fields)]` |
| Runaway KNS hammering | Exponential backoff with jitter + in-memory TTL cache |

---

## 6. Observability

| Signal | Implementation |
|--------|---------------|
| Structured logs | `tracing` with `EnvFilter`; JSON mode for prod |
| Health check | `GET /health` → JSON (node_id, live_peers, uptime, mirror stats) |
| Readiness probe | `GET /readyz` → 200/503 |
| Metrics (future) | `tracing-opentelemetry` optional feature + Prometheus exporter |

---

## 7. Error Handling Strategy

```
Library (muspell-core)          Daemon / CLI
──────────────────────          ──────────────────────
thiserror enum variants         anyhow::Context wrapping
  + is_retryable() flag           + full backtrace
  + structured fields             + human-readable chain
```

Retryable errors (`KnsTransport`, `KnsTimeout`, `PeerConnectionFailed`,
`BlobSyncFailed`) are automatically retried by the backoff layer.
Non-retryable errors (`NodeKeyMismatch`, `InvalidOwnershipProof`) surface
immediately with a clear diagnostic.

---

## 8. Adding a New KNS Backend

1. Implement `KnsResolver` (the `async_trait` in `kns.rs`).
2. Pass it to `KnsDiscoveryProvider::new(Arc::new(your_impl))`.
3. No changes required in any other module.

The mock (`MockKnsResolver`) generated by `mockall` is already wired for
unit tests across the crate.
