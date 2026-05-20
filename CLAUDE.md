# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is jälki

jälki is an Ahti producer for kernel and runtime evidence. It has four pieces:

- **SDK** — `jalki-sdk-meta` (source of truth) plus language SDKs (`jalki-sdk-python`, future Go/Rust). Defines types and the wire protocol.
- **API** — daemon IPC over `/run/jalki/jalki.sock`, MCP server, and the producer contract with Ahti.
- **Logic** — the `Probe` trait, eBPF programs, BTF resolution, ring buffer management, self-filtering, and the embedded knowledge base. Turns raw kernel signals into validated evidence.
- **Ahti** — where evidence lives durably. Jälki MUST NOT keep a parallel datastore.

The three built-in TCP probes (`TcpConnect`, `TcpClose`, `TcpRetransmit`) are batteries-included defaults — the logic layer makes writing *any* fentry/fexit probe a matter of implementing one trait.

Current code implements logic + SDK + local API. The Ahti producer path is the v0 work in `docs/jalki/v0-scope.md`.

## Crate Structure

```
jalki/
├── jalki-common/     # no_std shared types — kernel + userspace
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

Workspace members: `jalki-common`, `jalki`, `jalki-codegen`, `jalki-mcp`, `jalki-sdk-meta`, `xtask`.

Non-workspace (built separately): `jalki-ebpf`, `jalki-sdk-python`, `eval/oracle`.

External dependency: `false-protocol` is a path dependency from `../ahti/false-protocol`.

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
3. **Implement the `Probe` trait** in `jalki/src/probes/` — convert raw ring buffer bytes to FALSE Protocol `Occurrence`. `program_name()` must exactly match the `#[fentry]`/`#[fexit]` function name in `jalki-ebpf`.
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
    fn to_occurrence(&self, raw: &[u8], cluster: &str) -> Result<Occurrence, ProbeError>;
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

## Design docs

`docs/jalki/` contains a 7-document design pass (May 2026) that reframes jälki as a producer for Ahti — the agent stops being its own product surface, evidence becomes Ahti records, and Lähde/Vartio interpret. **Design-only, no code yet.** Read these before making architectural changes; the fentry/fexit framework is preserved but the output, storage, and CLI/MCP boundaries change.

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
