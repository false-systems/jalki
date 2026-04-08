# Jälki

**Your kernel knows what TCP actually did. Jälki turns that into structured events an AI can reason about.**

Applications lie. A service reports "healthy" while its TCP layer is retransmitting every third packet. A load balancer says "all backends up" while connections to one backend time out silently. HTTP metrics say "200 OK" but can't tell you the connect took 800ms because of three SYN retransmits.

Jälki attaches to kernel functions — `tcp_connect`, `tcp_close`, `tcp_retransmit_skb` — and emits a structured event every time they fire. No sampling. No aggregation. Every connection attempt, every teardown, every retransmit. The output is machine-readable [FALSE Protocol](https://github.com/false-systems) Occurrences that flow into AHTI for causal correlation.

One binary. No runtime dependencies. No kernel headers. Deploy per node, point at an output, done.

> *Jälki* (Finnish) — footprint, trace, track.

---

## Why This Exists

Prometheus tells you `tcp_retransmits_total` went up. It doesn't tell you *which* connection, *to where*, *from which process*, *in what TCP state*. You're left correlating timestamps across dashboards.

Jälki gives you the event itself:

```json
{
  "source": "jalki/tcp_retransmit",
  "type": "kernel.tcp.retransmit",
  "severity": "warning",
  "outcome": "failure",
  "network_data": {
    "src_ip": "10.42.1.15",
    "dst_ip": "10.42.2.8",
    "src_port": 48210,
    "dst_port": 5432
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

Your API server is retransmitting to Postgres on an established connection. That's a network-layer problem, not an application bug. No dashboard can show you this — only the kernel knows.

---

## Built for AI Correlation

Jälki doesn't exist in isolation. It's the kernel layer in a three-layer observability stack designed for AI-driven root cause analysis:

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

AHTI joins events across all three layers on the 4-tuple (`src_ip:src_port → dst_ip:dst_port`). Jälki's `correlation_keys` field is designed for this join. When RAUTA sees a slow HTTP request and Jälki sees retransmits on the same connection, AHTI concludes "network problem" — not "application problem."

An AI reading Jälki events can distinguish what no application-level telemetry can:

- **Retransmit in SYN_SENT** → the remote isn't reachable (firewall, host down)
- **Retransmit in ESTABLISHED** → the network is losing packets (switch, congestion)
- **ECONNREFUSED** → the port isn't listening (crashed process, wrong config)
- **ETIMEDOUT** → the host exists but isn't responding (overloaded, hung)

These are different problems with different fixes. The kernel knows which one it is. Jälki makes that knowledge available.

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
 │  reader ──► drain ring buffers (one thread per probe)       │
 │  probe  ──► convert raw bytes → FALSE Protocol Occurrence   │
 │  emitter ──► send to stdout / file / gRPC                   │
 │  metrics ──► Prometheus on :9090                            │
 │                                                             │
 └─────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┼──────────────┐
            ▼                 ▼              ▼
         stdout            file           gRPC
        (ndjson)         (ndjson)        (POLKU)
```

**fentry/fexit** — not kprobes. BPF trampolines patch a NOP at the function entry. Near-zero overhead when idle. No breakpoint trap, no `int3`, no context switch penalty. Safe to run 24/7 on production nodes.

**Self-filter** — Jälki's own PID is inserted into a BPF HashMap before any probes attach. Every probe checks this map first, in kernel space. If Jälki emits to a gRPC endpoint, those `tcp_connect` calls never generate events. Zero userspace overhead for self-filtering.

**CO-RE** — Compile Once, Run Everywhere. Built with aya + BTF. One binary runs on any kernel 5.5+ with BTF enabled. No C toolchain, no LLVM, no kernel headers at runtime.

---

## Three Probes

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
# Userspace daemon
cargo build --release -p jalki

# eBPF programs (requires nightly Rust)
cargo run -p xtask -- build-ebpf --release
```

### Run

```bash
# Emit to stdout (development)
sudo jalki --emit stdout

# Emit to file (production)
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

## Observability About Itself

Jälki exposes Prometheus metrics on `:9090/metrics`:

```
jalki_events_total{probe="tcp_connect"}      48201
jalki_events_total{probe="tcp_close"}        47892
jalki_events_total{probe="tcp_retransmit"}   34
jalki_ring_buffer_drops{probe="tcp_connect"} 0
jalki_emit_errors{emitter="stdout"}          0
```

A probe that silently drops events is worse than no probe. Drops are always visible.

---

## Architecture

```
 jalki/
 ├── jalki-common/     shared types (no_std, kernel + userspace)
 │                     #[repr(C)] event structs, size-locked with tests
 │
 ├── jalki-ebpf/       eBPF programs (bpfel-unknown-none, nightly)
 │                     3 probes, 4 BPF maps, self-filter
 │                     NOT a workspace member (independent toolchain)
 │
 └── jalki/            userspace daemon + library
                       Probe trait, Emitter trait, runtime, loader
```

| Crate | What it is |
|-------|------------|
| `jalki-common` | `#[repr(C)]` event structs shared between kernel and userspace. `no_std`. Feature `userspace` enables `aya::Pod` impls. |
| `jalki-ebpf` | Three eBPF programs + BPF maps. Separate build targeting `bpfel-unknown-none`. |
| `jalki` | Daemon binary + library. `Probe` and `Emitter` traits for extensibility. |

The `Probe` trait converts raw ring buffer bytes to FALSE Protocol Occurrences. The `Emitter` trait sends them somewhere. Both are public — write your own probes, write your own emitters.

---

## Limitations

**Hardcoded offsets.** `__sk_common` field offsets are verified on kernel 6.19 via pahole. Other kernels may need different offsets. No self-test validation yet (planned — same pattern as Syva/Rauha).

**IPv4 only.** IPv6 support is planned for v0.2.

**No bytes/duration on tcp_close.** `bytes_sent`/`bytes_received` require reading `tcp_sock` fields whose offsets vary per kernel. Connection duration requires stashing a timestamp at `tcp_connect` in a BPF map. Both emit 0 in v0.1.

**No netns enrichment.** Network namespace inode is emitted as 0. Container-aware enrichment (netns → pod name) is planned for v0.2.

**gRPC emitter is a stub.** Returns an error on every emit. Use stdout or file for v0.1. Full POLKU integration requires the POLKU proto definitions.

**No probe hot-reload.** Adding or removing probes requires a restart.

**Privileged required.** BPF program loading needs `CAP_BPF` + `CAP_PERFMON` at minimum. Same constraint as Cilium, Tetragon, and the Datadog agent.

---

## What Jälki Is Not

**Not a security tool.** Jälki observes. It does not block, enforce, or deny. That's Syva and Rauha.

**Not a storage layer.** Events flow out. AHTI stores and correlates.

**Not a replacement for metrics.** Jälki gives you per-event causality data. If you want `tcp_retransmits/minute`, scrape Prometheus. If you want *which specific connection retransmitted and in what TCP state*, use Jälki.

**Not coupled to POLKU.** POLKU is the default transport. Jälki emits to any `Emitter`. Stdout is a valid production destination.

---

## License

Apache-2.0
