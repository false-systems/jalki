# Jälki

**Programmable fentry/fexit framework for Linux. One trait, one kernel function, structured events out.**

You define a probe in Rust. Jälki handles BTF loading, fentry/fexit attachment, ring buffer management, self-filtering, and emission. You get [FALSE Protocol](https://github.com/false-systems) Occurrences — structured, machine-readable events that an AI can reason about.

The three built-in TCP probes are the batteries-included default. They are not what Jälki *is*. Jälki is the framework that makes writing any fentry/fexit probe a matter of implementing one trait.

One binary. No runtime dependencies. No kernel headers. Deploy per node, point at an output, done.

> *Jälki* (Finnish) — footprint, trace, track.

---

## What You Get

Every kernel function you care about becomes a stream of structured events:

```json
{
  "source": "jalki/tcp_retransmit",
  "type": "kernel.tcp.retransmit",
  "severity": "warning",
  "outcome": "failure",
  "correlation_keys": ["10.42.1.15:48210->10.42.2.8:5432"],
  "network_data": {
    "src_ip": "10.42.1.15",
    "dst_ip": "10.42.2.8",
    "src_port": 48210,
    "dst_port": 5432,
    "protocol": "tcp"
  },
  "process_data": {
    "pid": 1847,
    "command": "api-server"
  },
  "labels": {
    "tcp_state": "ESTABLISHED"
  }
}
```

Your API server is retransmitting to Postgres on an established connection. The kernel knows this. Now you know it too.

---

## Built for AI

Jälki is the kernel layer in a stack designed for AI-driven root cause analysis:

```
 ┌─────────────────────────────────────────────────────────────┐
 │                      AHTI                                   │
 │            AI correlation engine                            │
 │                                                             │
 │  "api-server latency spike at 14:32:01 was caused by       │
 │   TCP retransmits to postgres (10.42.2.8:5432).             │
 │   3 retransmits in ESTABLISHED state = network issue,       │
 │   not application. Check switch between nodes."             │
 │                                                             │
 └────────────┬─────────────────┬────────────────┬─────────────┘
              │                 │                │
      ┌───────▼──────┐  ┌──────▼───────┐  ┌─────▼──────┐
      │    Jälki     │  │    RAUTA     │  │   TAPIO    │
      │              │  │              │  │            │
      │  kernel TCP  │  │  L7 HTTP     │  │  k8s       │
      │  connect     │  │  status      │  │  events    │
      │  close       │  │  latency     │  │  deploys   │
      │  retransmit  │  │  headers     │  │  restarts  │
      │              │  │              │  │            │
      └──────────────┘  └──────────────┘  └────────────┘
```

AHTI joins events across all three layers on the 4-tuple (`src_ip:src_port → dst_ip:dst_port`). Jälki's `correlation_keys` field is designed for this join.

An AI reading Jälki events can distinguish:

- **Retransmit in SYN_SENT** → remote isn't reachable (firewall, host down)
- **Retransmit in ESTABLISHED** → network is losing packets (switch, congestion)
- **ECONNREFUSED** → port isn't listening (crashed process, wrong config)
- **ETIMEDOUT** → host exists but isn't responding (overloaded, hung)

Different problems, different fixes. The kernel knows which one it is. Jälki makes that knowledge available as structured events.

---

## The Framework

```
your probe (Rust)
    ↓
jälki framework
    ↓
FALSE Protocol Occurrence JSON
    ↓
stdout / file / gRPC (POLKU)
```

### Probe Trait

```rust
pub trait Probe: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn program_name(&self) -> &str;
    fn attachments(&self) -> &[Attachment];
    fn ring_buffer_map(&self) -> &str;
    fn to_occurrence(&self, raw: &[u8], cluster: &str) -> Result<Occurrence, ProbeError>;
    fn sample_rate(&self) -> f64 { 1.0 }
}
```

Implement this trait. Jälki handles eBPF loading, BTF attachment, ring buffer management, self-filtering, sampling, batching, and emission. You never touch the BPF verifier.

### Emitter Trait

```rust
#[async_trait]
pub trait Emitter: Send + Sync {
    fn name(&self) -> &str;
    async fn emit(&self, occurrences: &[Occurrence]) -> Result<(), EmitError>;
    async fn health(&self) -> HealthStatus;
}
```

Send events anywhere. Built-in: stdout (ndjson), file (ndjson), gRPC (POLKU, v0.2).

### Runtime API

```rust
jalki::run(|rt| {
    rt.attach(TcpConnect::new())
      .attach(TcpClose::new())
      .attach(TcpRetransmit::new())
      .emit_to(StdoutEmitter::new())
}).await
```

---

## How It Works

```
 ┌─────────────────────────────────────────────────────────────┐
 │                       kernel space                          │
 │                                                             │
 │  tcp_connect()  ──► fentry trampoline ──► eBPF program ──┐ │
 │  tcp_close()    ──► fentry trampoline ──► eBPF program    │ │
 │  tcp_retransmit_skb() ──► fentry ──────► eBPF program     │ │
 │                                                            │ │
 │  PID_FILTER map: skip events from jälki's own PID          │ │
 │                                                            │ │
 │            per-probe ring buffers (4MB each)  ◄────────────┘ │
 └─────────────────────────────────┬───────────────────────────┘
                                   │
 ┌─────────────────────────────────▼───────────────────────────┐
 │                    jälki daemon (userspace)                  │
 │                                                             │
 │  loader  ──► reads Probe metadata, attaches via BTF         │
 │  reader  ──► drain ring buffers (one thread per probe)      │
 │  probe   ──► convert raw bytes → FALSE Protocol Occurrence  │
 │  emitter ──► send to stdout / file / gRPC                   │
 │  metrics ──► Prometheus on :9090                            │
 │                                                             │
 └─────────────────────────────────────────────────────────────┘
```

**fentry/fexit** — BPF trampolines, not kprobes. Near-zero overhead when idle. Safe to run 24/7 on production nodes.

**Self-filter** — Jälki's own PID is excluded in kernel space. If Jälki emits to a gRPC endpoint, those `tcp_connect` calls never generate events.

**CO-RE** — Compile Once, Run Everywhere. aya + BTF. One binary, any kernel 5.5+ with BTF enabled.

**Probe-driven loader** — the loader reads probe metadata (`program_name()`, `attachments()`), no hardcoded program names. Add a probe, implement the trait, it gets attached automatically.

---

## Built-in Probes

| Probe | Attachment | Event Type | What It Gives You |
|-------|-----------|-----------|-------------------|
| `TcpConnect` | `fexit/tcp_connect` | `kernel.tcp.connect` | Connection attempt: 4-tuple, success/failure, errno |
| `TcpClose` | `fexit/tcp_close` | `kernel.tcp.close` | Connection teardown: 4-tuple, process info |
| `TcpRetransmit` | `fentry/tcp_retransmit_skb` | `kernel.tcp.retransmit` | Retransmission: 4-tuple, TCP state |

These three, joined on the 4-tuple, answer: *which backends are being connected to, which connections are failing, which are retransmitting, and what the TCP state was when it happened.*

---

## Installation

### Prerequisites

- Linux kernel 5.5+ (fentry requires BPF trampoline)
- `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_JIT=y`
- BTF at `/sys/kernel/btf/vmlinux`
- Root or `CAP_BPF` + `CAP_PERFMON`

### Build

```bash
# eBPF programs (requires nightly Rust)
cargo run -p xtask -- build-ebpf --release

# Userspace daemon
cargo build --release -p jalki
```

### Run

```bash
# Emit to stdout
sudo jalki --emit stdout

# Emit to file
sudo jalki --emit /var/log/jalki/events.ndjson --cluster prod-east-1

# Custom eBPF object path
sudo jalki --ebpf-path /opt/jalki/jalki-ebpf --emit stdout
```

Environment variables: `JALKI_EBPF_PATH`, `JALKI_EMIT`, `JALKI_CLUSTER`.

### Kubernetes DaemonSet

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: jalki
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      containers:
        - name: jalki
          image: jalki:latest
          securityContext:
            privileged: true
          env:
            - name: JALKI_EMIT
              value: "grpc://polku.observability.svc:50051"
            - name: JALKI_CLUSTER
              value: "prod-east-1"
          volumeMounts:
            - name: bpffs
              mountPath: /sys/fs/bpf
            - name: debugfs
              mountPath: /sys/kernel/debug
      volumes:
        - name: bpffs
          hostPath: { path: /sys/fs/bpf }
        - name: debugfs
          hostPath: { path: /sys/kernel/debug }
```

---

## Self-Observability

Prometheus metrics on `:9090/metrics`:

```
jalki_events_total{probe="tcp_connect"}      48201
jalki_events_total{probe="tcp_close"}        47892
jalki_events_total{probe="tcp_retransmit"}   34
jalki_ring_buffer_drops{probe="tcp_connect"} 0
jalki_emit_errors{emitter="stdout"}          0
```

Ring buffer drops are also emitted as `jalki.probe.events_dropped` Occurrences through the same pipeline — so AHTI can distinguish "no events happened" from "events happened but were dropped."

---

## Architecture

```
 jalki/
 ├── jalki-common/     shared types (no_std, kernel + userspace)
 │                     #[repr(C)] event structs, size-locked with tests
 │
 ├── jalki-ebpf/       eBPF programs (bpfel-unknown-none, nightly)
 │                     probes + BPF maps + self-filter
 │                     NOT a workspace member (independent toolchain)
 │
 └── jalki/            userspace daemon + library
                       Probe trait, Emitter trait, runtime, loader
```

| Crate | What it is |
|-------|------------|
| `jalki-common` | `#[repr(C)]` event structs shared between kernel and userspace. `no_std`. |
| `jalki-ebpf` | eBPF programs + BPF maps. Separate build targeting `bpfel-unknown-none`. |
| `jalki` | Daemon binary + library. `Probe` and `Emitter` traits for extensibility. |

---

## The Vision

Writing an fentry probe today requires knowing BTF, aya, ring buffers, CO-RE, the BPF verifier, and kernel struct offsets. Maybe a few hundred people in the world can do this comfortably.

Jälki makes it one trait. The framework handles everything else.

This matters most for AI agents. An agent that needs to debug a network problem can identify the kernel function to hook, write the probe definition, deploy it via Jälki, consume the structured events, and reason about root cause. No human eBPF expertise in the loop.

```
v0.1  Rust trait (current)
v0.2  Rust macro — simpler ergonomics
v0.3  Python SDK — 8 lines to observe a kernel function
v0.4  Go SDK
```

The target:

```python
@jalki.probe(fexit="tcp_connect")
def on_connect(src_ip, dst_ip, src_port, dst_port, pid, comm, ret):
    return jalki.occurrence(
        type="kernel.tcp.connect",
        severity="warning" if ret < 0 else "info",
        network_data={"src_ip": src_ip, "dst_ip": dst_ip},
        process_data={"pid": pid, "command": comm},
    )
```

An agent writes 8 lines of Python and gets kernel-level visibility. No C. No BTF knowledge. No verifier.

---

## Limitations

- **Hardcoded offsets** — `__sk_common` field offsets verified on kernel 6.19. No self-test validation yet.
- **IPv4 only** — IPv6 in v0.2.
- **No bytes/duration on tcp_close** — emit 0 in v0.1, requires `tcp_sock` offset walking.
- **No netns enrichment** — emitted as 0. Container-aware enrichment in v0.2.
- **gRPC emitter is a stub** — returns error on emit. Use stdout or file for v0.1.
- **No probe hot-reload** — adding probes requires restart.
- **Privileged required** — BPF program loading needs `CAP_BPF` + `CAP_PERFMON` at minimum.

---

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

Jälki is the deepest layer. It sees what the kernel sees.

---

*false systems, berlin, 2026*
*apache 2.0*
