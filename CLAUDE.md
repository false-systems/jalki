# CLAUDE.md

This file provides guidance to Claude Code when working with jälki.

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
├── jalki-ebpf/       # eBPF programs — NOT a workspace member
└── jalki/            # userspace daemon + library
```

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
  - `Metrics` — Prometheus on :9090
- Built-in emitters: `StdoutEmitter`, `FileEmitter`, `GrpcEmitter` (stub in v0.1)
- Built-in probes: `TcpConnect`, `TcpClose`, `TcpRetransmit`

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

## Conventions

- No `.unwrap()` in userspace code — use `?` or handle errors
- No `println!` in library code — use `tracing`
- `thiserror` for library errors, `anyhow` for binary entry points
- Workspace lints: `unsafe_code = "deny"` (userspace only), `unwrap_used = "warn"`
- eBPF code is necessarily unsafe — document why each unsafe block is correct
- Size tests in jalki-common are mandatory for every event struct

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
