# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is jälki

jälki is a programmable eBPF **fentry/fexit framework** for kernel and runtime evidence: hook any kernel function by implementing one Rust trait, and get structured FALSE Protocol records out. It is the kernel-observation layer of False Systems.

Two value planes run off one capture engine:

- **Direct / interpreted** — the `ask`/`watch`/`stream`/`list` CLI, the MCP server, the Python SDK, and an embedded knowledge base that *interprets* raw signals (e.g. "ESTABLISHED-state retransmit ⇒ network problem, not application"). For humans and agents debugging *now*.
- **Neutral evidence** — capture → normalize → `EvidenceSink`. Today's sinks are `stdout`/`file`/`composite`; the durable destination (the False Systems causality pipeline) is under active redesign — see **Design docs** below.

The three built-in TCP probes (`TcpConnect`, `TcpClose`, `TcpRetransmit`) are batteries-included defaults; the framework makes writing *any* fentry/fexit probe a matter of implementing the `Probe` trait.

> ⚠ **Do not trust the "jälki is an Ahti producer" framing in `docs/jalki/`.** That May-2026 pass had jälki writing directly to Ahti; that premise has been reversed (see Design docs). jälki does not write to Ahti directly.

## Crate Structure

```
jalki/
├── false-protocol/   # vendored FALSE Protocol types (Occurrence, Severity, …) — was ../ahti/false-protocol
├── jalki-common/     # no_std shared types — kernel + userspace
├── jalki-evidence/   # aya-free: typed KernelEvent, normalization, EvidenceBatch, EvidenceSink
├── jalki-ebpf/       # eBPF programs — NOT a workspace member (separate build target)
├── jalki/            # userspace daemon + library
├── jalki-codegen/    # runtime BPF program generation from BTF (no C, no clang)
├── jalki-mcp/        # MCP server (JSON-RPC 2.0 over stdin/stdout)
├── jalki-sdk-meta/   # source of truth for SDK types, wire protocol, conformance tests
├── jalki-sdk-python/ # Python SDK (NOT a workspace member — pyproject.toml)
├── xtask/            # build orchestration (eBPF compilation)
├── knowledge/        # JSON knowledge base — compiled into binary via include_str!
├── specs/            # Luotain-compatible requirement specs (tested by oracle)
├── helm/jalki/       # Helm chart for k8s deployment
└── eval/oracle/      # standalone contract test suite — NOT in workspace
```

Workspace members: `false-protocol`, `jalki-common`, `jalki-evidence`, `jalki`, `jalki-codegen`, `jalki-mcp`, `jalki-sdk-meta`, `xtask`.

Non-workspace (built separately): `jalki-ebpf`, `jalki-sdk-python`, `eval/oracle`.

`false-protocol` is **vendored in-repo** (`false-protocol/`). It was a path dep on `../ahti/false-protocol`, which Ahti deleted in its v1 datastore-only cleanup; it was recovered from `ahti@7bd55c8^` and vendored so jälki is self-contained. `jalki-evidence`/`jalki` depend on it via `workspace = true`.

## Architecture: the capture pipeline

The end-to-end data path is the thing that spans crates — trace it once and the layout makes sense:

```
kernel fn returns → #[fexit]/#[fentry] eBPF program (jalki-ebpf)
  → writes #[repr(C)] event to a per-probe 4MB ring buffer
  → Reader drains on a blocking thread, applies sample_rate          (jalki/src/reader.rs)
  → Probe::decode_event → KernelEvent (typed)                        (jalki-evidence/src/event.rs)
  → KernelEvent::normalize → EvidenceRecord{ Occurrence }            (jalki-evidence/src/normalize.rs)
  → record cloned into in-memory EventStore (for IPC/CLI queries)    (jalki/src/store.rs)
  → batched over an mpsc channel
  → Runtime sink loop wraps in EvidenceBatch → EvidenceSink::append_batch  (jalki/src/runtime.rs)
```

- `Runtime` (builder) assembles the daemon: load eBPF + attach via BTF (`loader.rs`), spawn one `Reader` per probe, build `DaemonHandle`, serve IPC, run the sink loop + Prometheus on `:9090`.
- `DaemonHandle::deploy_probe` is the runtime-attach path: precompiled probes take a fast path; otherwise `jalki-codegen` generates BPF bytecode from BTF and attaches it as a `GeneratedProbeReader`.
- **Self-filter**: jälki's own PID is inserted into the `PID_FILTER` BPF map *before* attach, so its own syscalls never enter the ring buffers.
- The map name ↔ probe binding is declarative (`Probe::ring_buffer_map()`), so the loader/reader are probe-agnostic — adding a probe needs no loader change.

## Build & Run

**Build order matters.** Always build eBPF first. Userspace will compile without it, but the daemon fails at runtime with a missing eBPF object.

```bash
# 1. eBPF first — always (requires nightly + Linux)
cargo run -p xtask -- build-ebpf [--release]

# 2. Userspace daemon (requires Linux — aya doesn't compile on macOS)
cargo build -p jalki

# 3. Regenerate SDK files if jalki-sdk-meta types/protocol changed
cargo run -p jalki-sdk-meta -- --lang python --out jalki-sdk-python/src/jalki/

# Run daemon (requires root or CAP_BPF + CAP_PERFMON)
sudo RUST_LOG=jalki=debug ./target/debug/jalki \
    --ebpf-path jalki-ebpf/target/bpfel-unknown-none/debug/jalki-ebpf \
    --sink stdout
```

### macOS Development

`cargo check --workspace` and `cargo test --workspace` **fail on macOS** because `aya` is Linux-only. The crates that depend on aya (`jalki`, `jalki-codegen`, `jalki-mcp`) cannot be compiled on macOS.

Crates that work on macOS:

```bash
cargo check -p jalki-common
cargo check -p jalki-sdk-meta
cargo check -p xtask
cargo test -p jalki-common                                     # event struct size tests
cargo test -p jalki-sdk-meta                                   # SDK meta tests
cargo test --manifest-path eval/oracle/Cargo.toml              # oracle contract tests (all 50 cases)
cargo test --manifest-path eval/oracle/Cargo.toml -- case_014  # single oracle case
cargo clippy -p jalki-common -p jalki-sdk-meta                 # lint what compiles
```

### Linux Development (full build)

```bash
cargo check --workspace
cargo test --workspace                          # all workspace tests
cargo test -p jalki-common                      # event struct size tests
cargo test -p jalki                             # userspace tests
cargo test --manifest-path eval/oracle/Cargo.toml  # oracle contract tests
```

## Key Crate Details

### jalki-common

- `no_std` — must stay no_std, shared with kernel space
- `#[repr(C)]` event structs: `TcpConnectEvent`, `TcpCloseEvent`, `TcpRetransmitEvent`
- Feature `userspace` enables `aya::Pod` impls
- Size tests lock down the BPF ABI — do not change struct sizes without updating tests

### jalki-evidence

- **aya-free by design** — uses a *direct* path dep on `jalki-common` (no `userspace`/aya feature) so it compiles and unit-tests on macOS, unlike `jalki`/`jalki-codegen`/`jalki-mcp`. (Currently blocked from building only by the unresolved `false-protocol` dep — see Known Constraints.)
- The capture→output layer between raw bytes and durable output:
  - `event.rs` — typed `KernelEvent` + `from_bytes` decode of the `#[repr(C)]` structs.
  - `normalize.rs` — `KernelEvent` → FALSE Protocol `Occurrence` (one event may yield several `EvidenceRecord`s).
  - `evidence.rs` — `EvidenceRecord`/`EvidenceBatch`, `ProducerMetadata`/`ProbeMetadata`; `into_occurrences()` projects metadata into `Occurrence.labels` at sink time.
  - `sink.rs` — the `EvidenceSink` trait (replaced the old `Emitter`) + `StdoutSink`/`FileSink`/`CompositeSink`.
- `SinkError` deliberately distinguishes retryable (`Unavailable`/`Timeout`/`Backpressure`) from terminal (`Rejected`/`Unauthorized`/`InvalidRecord`) — sinks **MUST NOT** collapse them into one opaque error.
- `observed_at` (kernel CLOCK_BOOTTIME) and ingest time are never conflated.

### jalki-ebpf

- Separate build target: `bpfel-unknown-none`, requires nightly Rust
- NOT in the workspace Cargo.toml — has its own
- Build with: `cargo run -p xtask -- build-ebpf [--release]`
- Three programs: `fexit/tcp_connect`, `fexit/tcp_close`, `fentry/tcp_retransmit_skb`
- Four BPF maps: three ring buffers (one per probe, 4MB each) + `PID_FILTER` HashMap

### jalki (userspace)

- Library + binary in one crate
- **Daemon mode** (no subcommand): loads eBPF, attaches probes, drains events, emits, serves IPC
- **CLI subcommands**:
  - `ask "question"` — KB search → auto-deploy → collect → interpret → answer
  - `watch <function>` — deploy probe, collect for N seconds, print events
  - `stream [function]` — live ndjson event stream
  - `list [--layer tcp]` — browse the knowledge base
  - `status` — show attached probes, event counts, drops
- Key types: `Probe` trait, `EvidenceSink` trait (in `jalki-evidence`), `Runtime` (builder API), `DaemonHandle` (shared state), `Loader`, `Reader`, `KnowledgeBase`, `ProbeRegistry`, `EventStore`
- IPC: Unix socket at `/run/jalki/jalki.sock`. **Binary frame protocol**: `[frame_len: u32 BE][msg_type: u8][flags: u8][msgpack payload]`, `frame_len = payload.len() + 2`. Encoded via `rmpv`. Wire constants live in `jalki-sdk-meta/src/protocol.rs` — single source of truth, do not hardcode message-type bytes elsewhere. `ipc::call()` is the client used by CLI and MCP.

### jalki-codegen

- Generates BPF ELF bytecode at runtime from a `ProbeSpec` — no C, no clang
- Flow: `ProbeSpec → BTF resolution → BPF instructions → ELF → aya::Ebpf::load()`
- Used by daemon's `deploy_descriptor` IPC method for SDK-defined probes

### jalki-sdk-meta

- Single source of truth for SDK types, wire protocol framing, and conformance tests
- Workflow: change types here → run `cargo run -p jalki-sdk-meta -- --lang python --out jalki-sdk-python/src/jalki/` → all SDKs update.
- **Never hand-edit any file with a `# GENERATED by jalki-sdk-meta` header** (e.g. `jalki-sdk-python/src/jalki/types.py`, `protocol.py`). Edit `jalki-sdk-meta/src/` and regenerate.

### jalki-mcp

- MCP server: JSON-RPC 2.0 over stdin/stdout
- Tools: `jalki_find_probe`, `jalki_deploy_probe`, `jalki_get_events`, `jalki_explain_event`, `jalki_probe_status`, `jalki_deploy_descriptor`
- `find_probe` and `explain_event` run locally (KB compiled in); others forward to daemon via IPC

## Specs and Oracle

### Requirement specs (`specs/`)

Luotain-compatible markdown specs. Each file defines testable requirements in natural language.

### Oracle (`eval/oracle/`)

Standalone Rust binary. Validates jälki's public contract by reading data files from disk. Never imports jalki code.

**Rules:**
- The oracle tests requirements, not implementation
- When an oracle case fails, fix the system or the data — not the test
- The oracle must not be modified as a side effect of modifying the system

**50 cases by domain:** 001-010 KB schema, 011-020 KB semantics, 021-030 MCP contract, 031-040 event schema, 041-050 interpretation accuracy, 051-055 cross-layer consistency, 060-065 probe counts, 070-072 find relevance, 080-082 ask interpretations, 090-091 SDK types, 095-096 specs structure.

## Adding a New Probe

Four steps, in order:

1. **Define the event struct** in `jalki-common/src/events.rs` — `#[repr(C)]`, pad to 8-byte alignment, add size test, add `aya::Pod` impl under `#[cfg(feature = "userspace")]`
2. **Write the eBPF program** in `jalki-ebpf/src/` — register ring buffer map, check `PID_FILTER`, wire up in `main.rs`
3. **Implement the `Probe` trait** in `jalki/src/probes/` — the only required method is `decode_event` (raw bytes → `KernelEvent`); `to_evidence`/`probe_metadata` are provided defaults that normalize via `jalki-evidence`. Add the matching `KernelEvent` variant + its `normalize` in `jalki-evidence`. `program_name()` must exactly match the `#[fentry]`/`#[fexit]` function name in `jalki-ebpf`.
4. **Add a knowledge base entry** in `knowledge/{layer}.json` (existing layers: `tcp`, `fs`, `memory`, `process`, `sched`). The oracle validates the entry on the next test run. Do not add KB entries you are not certain about — wrong interpretations mislead agents.

### fentry vs fexit

- **fexit** — fires after the function returns. Use when the question involves success/failure/errno or a return value (e.g. `tcp_connect`, `tcp_sendmsg`, `inet_csk_accept`).
- **fentry** — fires before execution. Use when the question is just "did this happen" (e.g. `tcp_retransmit_skb`).

## Core Traits

```rust
pub trait Probe: Send + Sync + 'static {
    fn attachments(&self) -> &[Attachment];
    fn name(&self) -> &str;
    fn program_name(&self) -> &str;         // must match #[fentry]/#[fexit] fn name in jalki-ebpf
    fn ring_buffer_map(&self) -> &str;
    fn decode_event(&self, raw: &[u8]) -> Result<KernelEvent, ProbeError>;   // only required conversion
    // provided defaults: probe_version, family, probe_metadata, sample_rate (1.0),
    // and to_evidence (decode_event + KernelEvent::normalize → NormalizedEvidence)
    fn sample_rate(&self) -> f64 { 1.0 }
}

#[async_trait]
pub trait EvidenceSink: Send + Sync {
    fn name(&self) -> &str;
    async fn append_batch(&self, batch: EvidenceBatch) -> Result<AppendResult, SinkError>;
    async fn health(&self) -> HealthStatus;
}
```

## Conventions

- No `.unwrap()` in userspace code — use `?` or handle errors
- No `println!` in library code — use `tracing`
- `thiserror` for library errors, `anyhow` for binary entry points
- eBPF code is necessarily unsafe — document why each unsafe block is correct
- Size tests in jalki-common are mandatory for every event struct

## Known Constraints

- **Struct offsets** — `__sk_common` offsets verified on kernel 6.x via pahole. Check with `pahole -C tcp_sock /sys/kernel/btf/vmlinux` on other kernels.
- **dst_ip 0.0.0.0 on Cilium-managed connections** — `skc_daddr` reads 0 when Cilium drops before destination resolution. Not fixable from jälki.
- **src_port 0 on tcp_close** — kernel clears `skc_num` before `tcp_close` returns. Correlate by 4-tuple with `tcp_connect` events.
- **tcp_sock offsets hardcoded** — bytes_sent (1608) and bytes_received (1808) verified on kernel 6.19.9.
- **Self-filter** — jälki's own PID is always excluded. This is correct behavior, not a bug.
- **`false-protocol` is vendored** (`false-protocol/`), recovered from `ahti@7bd55c8^` after Ahti deleted its copy. Note Polku's `false-protocol` crate is a *different, incompatible* shape (nested `context`, `data: Value`, no `NetworkEventData`/`ProcessEventData`/`labels`/`new_id`) — do **not** repoint to it without rewriting `jalki-evidence/normalize.rs`.

## Design docs

`docs/jalki/` contains a May-2026 design pass plus `adr/0001`. **⚠ Partially stale — under active reconciliation.** That pass framed jälki as a *direct Ahti producer* (jälki authenticates to Ahti and writes records to the `jalki` namespace). That premise has been reversed:

- Evidence routes **`jälki → Polku → Vartio → Ahti`**. jälki does **not** write to Ahti directly; Vartio interprets the evidence (normalize → chains → decisions) and writes the product records to Ahti.
- jälki **keeps** its product surface (`ask`/MCP/SDK/KB/interpretation) — the old plan to demote `ask` to a Lähde shim and move the KB out of the binary is dropped.
- ADR-0001's interpretation reversal ("jälki MAY interpret") still holds; its D2 routing (`PolkuSink`/`AhtiSink` → Ahti) does not.

Until a superseding ADR lands, treat the storage/routing claims in these docs as wrong. The fentry/fexit framework, the `Probe` trait, and the eBPF crates are accurate and preserved.

- `docs/jalki/README.md` — start here, document map and the "design sentence to preserve"
- `docs/jalki/product-boundaries.md` — what jälki MUST and MUST NOT do
- `docs/jalki/v0-scope.md` — the first implementation slice
- `docs/jalki/ahti-record-mapping.md` — how every concept maps to Ahti's record kinds
- `docs/jalki/runtime-evidence-model.md` — per-evidence-type definitions
- `docs/jalki/probe-definitions.md` — probe plan templates as Ahti definition records
- `docs/jalki/local-agent-state.md` — what stays on the node vs. what reaches Ahti

For architectural changes, write a design doc first (MUST/SHOULD/MAY discipline) and get sign-off before implementing.

## Part of False Systems

```
jälki     kernel observation (fentry/fexit framework)
TAPIO     k8s observation
RAUTA     L7 gateway
POLKU     event transport
AHTI      causality correlation
syva      enforcement
rauha     container runtime
```
