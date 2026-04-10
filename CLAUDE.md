# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is jälki

jälki is to kernel functions what POLKU is to gRPC — a programmable framework.

You define a probe in Rust. jälki handles BTF loading, fentry/fexit attachment, ring buffer management, self-filtering, serialization, and emission. You get structured FALSE Protocol Occurrences out. You never touch the BPF verifier directly.

The three built-in TCP probes (`TcpConnect`, `TcpClose`, `TcpRetransmit`) are the batteries-included default. They are not what jälki *is*. jälki is the framework that makes writing any fentry/fexit probe a matter of implementing one trait.

```
your probe (Rust)
    ↓
jälki framework
    ↓
FALSE Protocol Occurrence JSON
    ↓
stdout / file / gRPC (POLKU)
```

## Crate Structure

```
jalki/
├── jalki-common/     # no_std shared types — kernel + userspace
├── jalki-ebpf/       # eBPF programs — NOT a workspace member (separate build target)
├── jalki/            # userspace daemon + library
├── jalki-mcp/        # MCP server (JSON-RPC 2.0 over stdin/stdout)
├── xtask/            # build orchestration (eBPF compilation)
└── eval/oracle/      # standalone contract test suite — NOT in workspace
```

Workspace members: `jalki-common`, `jalki`, `jalki-mcp`, `xtask`. The eBPF crate and oracle are built separately.

External dependency: `false-protocol` is a path dependency from `../ahti/false-protocol`.

### jalki-common

- `no_std` — must stay no_std, shared with kernel space
- `#[repr(C)]` event structs: `TcpConnectEvent`, `TcpCloseEvent`, `TcpRetransmitEvent`
- Feature `userspace` enables `aya::Pod` impls
- Size tests lock down the BPF ABI — do not change struct sizes without updating tests

### jalki-ebpf

- Separate build target: `bpfel-unknown-none`
- Requires nightly Rust (aya eBPF programs)
- NOT in the workspace Cargo.toml — has its own
- Build with: `cargo run -p xtask -- build-ebpf [--release]`
- Three programs: `fexit/tcp_connect`, `fexit/tcp_close`, `fentry/tcp_retransmit_skb`
- Four BPF maps: three ring buffers (one per probe, 4MB each) + `PID_FILTER` HashMap
- Self-filter: daemon PID is inserted into `PID_FILTER` before any probe attaches

### jalki (userspace)

- Library + binary in one crate
- Key types:
  - `Probe` trait — converts raw ring buffer bytes to `Occurrence`
  - `Emitter` trait — sends `Occurrence` somewhere
  - `Runtime` — builder API: `.attach(probe).emit_to(emitter).run().await`
  - `Loader` — loads eBPF object, populates self-filter, attaches probes via BTF
  - `Reader` — spawns blocking tasks to drain ring buffers
  - `KnowledgeBase` — embeds `knowledge/*.json` via `include_str!()`, searchable by question/keywords
  - `ProbeRegistry` — runtime attach/detach, tracks probe status
  - `EventStore` — in-memory ring buffer of recent Occurrences per probe
  - `Metrics` — Prometheus on :9090
- Built-in emitters: `StdoutEmitter`, `FileEmitter`, `GrpcEmitter` (stub in v0.1)
- Built-in probes: `TcpConnect`, `TcpClose`, `TcpRetransmit`

### jalki-mcp

- MCP server: JSON-RPC 2.0 over stdin/stdout
- Tools: `jalki_find_probe`, `jalki_deploy_probe`, `jalki_get_events`, `jalki_explain_event`, `jalki_probe_status`, `jalki_deploy_descriptor`
- Holds `JalkiState` with `KnowledgeBase` + `EventStore`

## Build & Run

```bash
# Build eBPF programs first (requires nightly)
cargo run -p xtask -- build-ebpf

# Build userspace daemon
cargo build -p jalki

# Run (requires root or CAP_BPF + CAP_PERFMON)
sudo RUST_LOG=jalki=debug ./target/debug/jalki \
    --ebpf-path jalki-ebpf/target/bpfel-unknown-none/debug/jalki-ebpf \
    --emit stdout

# Release build
cargo run -p xtask -- build-ebpf --release
cargo build --release -p jalki
```

## Tests & Checks

```bash
# Quick validation (no eBPF hardware needed)
cargo check --workspace
cargo test --workspace                          # all workspace tests

# Single crate
cargo test -p jalki-common                      # event struct size tests
cargo test -p jalki                             # userspace tests

# Oracle — standalone contract tests (NOT in workspace)
cargo test --manifest-path eval/oracle/Cargo.toml           # all cases
cargo test --manifest-path eval/oracle/Cargo.toml -- case_014  # single case
```

The oracle validates the public contract (knowledge base JSON, FALSE Protocol schema, MCP tool inventory). It must never import jalki crates. When an oracle case fails, fix the system or the data — not the test.

## Adding a New Probe

This is the core operation. Three steps.

### Step 1: Define the event struct in jalki-common

```rust
// jalki-common/src/events.rs
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MyEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    // ... your fields
}

// Add size test
#[test]
fn test_my_event_size() {
    assert_eq!(core::mem::size_of::<MyEvent>(), 16); // lock the ABI
}
```

Add `#[cfg(feature = "userspace")]` aya::Pod impl in the userspace feature block.

### Step 2: Write the eBPF program in jalki-ebpf

```rust
// jalki-ebpf/src/my_probe.rs
use aya_ebpf::macros::fentry; // or fexit
use aya_ebpf::programs::FEntryContext;
use jalki_common::MyEvent;

#[fentry(function = "some_kernel_function")]
pub fn my_probe(ctx: FEntryContext) -> i32 {
    // check PID_FILTER first
    // read kernel struct fields
    // write to ring buffer
    0
}
```

Register the ring buffer map and wire up in `jalki-ebpf/src/main.rs`.

### Step 3: Implement the Probe trait in jalki

```rust
// jalki/src/probes/my_probe.rs
use crate::probe::Probe;
use crate::emitter::Occurrence;
use jalki_common::MyEvent;

pub struct MyProbe;

impl Probe for MyProbe {
    fn name(&self) -> &str { "my_probe" }

    fn attachments(&self) -> &[Attachment] {
        &[Attachment::Fentry { function: "some_kernel_function" }]
    }

    fn ring_buffer_map(&self) -> &str { "MY_EVENTS" }

    fn to_occurrence(&self, raw: &[u8]) -> Result<Occurrence, ProbeError> {
        let event = unsafe { *(raw.as_ptr() as *const MyEvent) };
        // convert to FALSE Protocol Occurrence
        Ok(Occurrence {
            source: "jalki/my_probe".into(),
            occurrence_type: "kernel.my.event".into(),
            // ...
        })
    }
}
```

Wire up in the runtime:
```rust
jalki::run(|probes| {
    probes
        .attach(MyProbe::new())
        .emit_to(StdoutEmitter::new())
})
.await
```

That's it. jälki handles everything else.

## The Probe Trait

```rust
pub trait Probe: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn attachments(&self) -> &[Attachment];
    fn ring_buffer_map(&self) -> &str;
    fn to_occurrence(&self, raw: &[u8]) -> Result<Occurrence, ProbeError>;
    fn sample_rate(&self) -> f64 { 1.0 }  // default: all events
}

pub enum Attachment {
    Fentry { function: &'static str },
    Fexit  { function: &'static str },
}
```

## The Emitter Trait

```rust
#[async_trait]
pub trait Emitter: Send + Sync {
    fn name(&self) -> &str;
    async fn emit(&self, occurrences: &[Occurrence]) -> Result<(), EmitError>;
    async fn health(&self) -> HealthStatus;
}
```

Implement this to send events anywhere. POLKU gRPC, Kafka, a Unix socket, anything.

## FALSE Protocol Output

Every probe emits a FALSE Protocol Occurrence. The schema:

```json
{
  "id": "01JWXYZ...",
  "timestamp": "2026-04-08T14:32:01.123456789Z",
  "source": "jalki/tcp_connect",
  "type": "kernel.tcp.connect",
  "severity": "info",
  "outcome": "success",
  "correlation_keys": ["10.0.0.1:54321->10.0.0.2:8080"],
  "network_data": {
    "src_ip": "10.0.0.1",
    "src_port": 54321,
    "dst_ip": "10.0.0.2",
    "dst_port": 8080,
    "protocol": "tcp"
  },
  "process_data": {
    "pid": 1234,
    "command": "nginx"
  }
}
```

`correlation_keys` is the 4-tuple string. AHTI uses this to join jälki events with RAUTA (HTTP) and TAPIO (k8s) events.

## Kernel Requirements

- Kernel 5.5+ x86, 6.0+ ARM64
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_BPF_JIT=y`
- BTF at `/sys/kernel/btf/vmlinux`
- Root or `CAP_BPF` + `CAP_PERFMON`

## Known Constraints

- **Struct offsets** — `__sk_common` offsets are verified on kernel 6.x via pahole. Other kernels may differ. Always check with `pahole -C tcp_sock /sys/kernel/btf/vmlinux` before assuming offsets.
- **IPv4 only** — IPv6 in v0.2
- **bytes_sent/bytes_received** — emit 0 in v0.1, requires `tcp_sock` offset validation
- **gRPC emitter** — stub in v0.1, returns error on emit. Use stdout or file.
- **No hot-reload** — adding probes requires restart
- **Self-filter** — jälki's own PID is always excluded. This is correct behavior, not a bug.

## What jälki Is Not

- Not a security tool — no blocking, no enforcement (that's syva/rauha)
- Not a storage layer — events flow out, AHTI stores
- Not a replacement for metrics — use Prometheus for rates, jälki for per-event causality
- Not coupled to POLKU — stdout is a valid production destination

## Oracle (`eval/oracle/`)

Standalone ground-truth test binary. Validates jälki's public contract — knowledge base schema, semantic correctness, interpretation accuracy, MCP tool inventory, FALSE Protocol compliance.

**The oracle MUST NOT depend on any jalki crate.** It reads knowledge base JSON files from disk and makes assertions. It never imports jalki code. If you need a jalki type to write a test, you're testing code, not contract. The oracle tests requirements, not implementation.

The oracle must not be modified as a side effect of modifying the system. When an oracle case fails, fix the system or the data — not the test.

## Conventions

- No `.unwrap()` in userspace code — use `?` or handle errors
- No `println!` in library code — use `tracing`
- `thiserror` for library errors, `anyhow` for binary entry points
- Workspace lints: `unsafe_code = "deny"` (userspace only), `unwrap_used = "warn"`
- eBPF code is necessarily unsafe — document why each unsafe block is correct
- Size tests in jalki-common are mandatory for every event struct

## The Vision: Democratizing fentry

Writing an fentry probe today requires knowing BTF, aya, ring buffers, CO-RE, the BPF verifier, and kernel struct offsets. It's a week of work before you see a single event. Maybe a few hundred people in the world can do this comfortably.

jälki changes that. Implementing a probe is one trait. The framework handles everything else.

This matters most for AI agents. An agent that needs to debug a network problem can now:

1. Identify the kernel function to hook (`tcp_retransmit_skb`)
2. Write the probe definition
3. Deploy it via jälki
4. Consume the structured events
5. Reason about root cause

No human eBPF expertise in the loop. The agent asks the kernel a question and gets a structured answer.

### SDK Roadmap

The Rust trait is the foundation. The goal is to make probe authorship accessible from any language:

```
v0.1  Rust trait (current)
v0.2  Rust macro — simpler ergonomics, less boilerplate
v0.3  Python SDK
v0.4  Go SDK
```

The Python SDK is the most important for agent use cases. The target API:

```python
@jalki.probe(fexit="tcp_connect")
def on_connect(src_ip, dst_ip, src_port, dst_port, pid, comm, ret):
    return jalki.occurrence(
        type="kernel.tcp.connect",
        severity="warning" if ret < 0 else "info",
        outcome="failure" if ret < 0 else "success",
        network_data={
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
        },
        process_data={"pid": pid, "command": comm},
    )
```

An agent writes 8 lines of Python and gets kernel-level visibility into every TCP connection on the node. No C. No BTF knowledge. No verifier. Just: "i want to see this kernel function, here's what to do with the data."

When building the Python SDK, the pattern is:
- jälki daemon runs as usual (Rust, privileged)
- Python SDK communicates with the daemon over a Unix socket or gRPC
- Probe definitions are sent as descriptors — function name, fields to extract, output schema
- The daemon compiles and loads the eBPF program on behalf of the SDK
- Events flow back as FALSE Protocol Occurrence JSON

The Rust trait stays the primary interface for production probes. The Python SDK is for agents and rapid iteration.

## Knowledge Base

jälki ships with a built-in knowledge base of kernel functions. it tells you:
- which function to hook for a given question
- what fields you get back
- how to interpret the events

the knowledge base is JSON, compiled into the binary, queryable via MCP tools.

### How to Use It

**you have a question. work backwards to a kernel function.**

```
question
    ↓
what layer does the answer live in?
    ↓
which function in that layer answers it?
    ↓
fentry or fexit?
    ↓
deploy probe, collect events, interpret
```

### Layer Map

| question about | layer | example functions |
|----------------|-------|-------------------|
| connection failures, timeouts, refused | tcp | tcp_connect, tcp_retransmit_skb |
| packet loss, slow connections | tcp | tcp_retransmit_skb |
| connection lifetime, churn | tcp | tcp_close, tcp_connect |
| send/receive throughput | tcp | tcp_sendmsg, tcp_recvmsg |
| incoming connection acceptance | tcp | inet_csk_accept |
| memory pressure, OOM | memory | mm_page_alloc, oom_kill_process |
| file access, what touched a file | fs | vfs_open, vfs_write |
| CPU scheduling, runqueue latency | sched | finish_task_switch |
| process execution | process | do_execve |

### fentry vs fexit

**use fexit when you need the return value.** fexit gives you both input arguments AND the return value. this is usually what you want for tcp_connect (did it succeed? what errno?), tcp_sendmsg (how many bytes?), inet_csk_accept (did accept succeed?).

**use fentry when you only need entry state.** fentry fires before the function executes. use for tcp_retransmit_skb — you want to know a retransmit is happening, not what it returned.

rule of thumb: if the question involves success/failure/errno → fexit. if the question is "did this happen" → fentry.

### The TCP State Field

tcp_retransmit_skb carries a `tcp_state` field. this is the most important field in the knowledge base. it tells you what KIND of problem you have:

| state | value | what it means |
|-------|-------|---------------|
| SYN_SENT | 2 | initial handshake failing — remote unreachable, firewall, or host down |
| ESTABLISHED | 1 | active connection losing packets — network congestion or path issue |
| CLOSE_WAIT | 7 | application hung, not reading from socket |
| FIN_WAIT1 | 4 | normal teardown, usually not critical |

**SYN_SENT retransmit = not an application problem.** the connection never established. check the network path.

**ESTABLISHED retransmit = network problem, not application.** the app is fine, the network between the nodes is losing packets.

### MCP Tools

```
jalki_find_probe(question: str)
    → returns matching ProbeKnowledge entries from the knowledge base
    → use this first — always ask the knowledge base before deploying anything

jalki_deploy_probe(function: str, sample_rate: float = 1.0)
    → loads and attaches the probe at runtime
    → returns probe_id

jalki_get_events(probe_id: str, filter: object, last_seconds: int = 60)
    → returns FALSE Protocol Occurrences from this probe
    → filter supports: src_ip, dst_ip, src_port, dst_port, pid, command

jalki_explain_event(event: object)
    → looks up the event against the knowledge base interpretations
    → returns the matching interpretation with conclusion and action

jalki_list_functions(filter: str = "")
    → lists all hookable kernel functions matching filter
    → uses /sys/kernel/btf/vmlinux — shows real available functions on this kernel

jalki_probe_status()
    → shows all attached probes, event counts, drop counts
```

### Workflow: Question to Answer

**example: "why is api-server slow connecting to postgres?"**

```
1. jalki_find_probe(question="slow connections to a backend")
   → suggests tcp_retransmit_skb + tcp_connect

2. jalki_deploy_probe(function="tcp_retransmit_skb")
   → probe_id: "probe_001"

3. jalki_deploy_probe(function="tcp_connect")
   → probe_id: "probe_002"

4. wait 30-60 seconds

5. jalki_get_events(probe_id="probe_001", filter={dst_port: 5432})
   → [{ tcp_state: 1, src_ip: "10.42.1.15", dst_ip: "10.42.2.8", ... }]

6. jalki_explain_event(event=...)
   → "ESTABLISHED retransmit: network is losing packets between nodes.
      this is a network problem, not an application bug.
      check network path between 10.42.1.15 and 10.42.2.8."
```

**always use jalki_find_probe first.** do not guess function names.

**always check tcp_state on retransmit events.** it tells you whether the problem is network reachability (SYN_SENT) or in-flight packet loss (ESTABLISHED).

**combine probes on the same 4-tuple.** tcp_connect + tcp_retransmit_skb on the same connection gives you the full picture.

**high-frequency probes need sampling.** tcp_sendmsg fires thousands per second. use sample_rate: 0.1. tcp_connect and tcp_retransmit_skb are low-frequency — run at 1.0.

### Knowledge Base Format

the knowledge base lives in `knowledge/tcp.json` (and future memory.json, fs.json, sched.json, process.json). it is compiled into the binary at build time.

to add a new interpretation: edit the JSON file, run `cargo build`. if it compiles, the entry is valid.

do not add entries you are not certain about. a wrong interpretation misleads every agent that reads it.

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

jälki is the deepest layer. it sees what the kernel sees.
