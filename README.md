# jälki

**The kernel knows what's wrong. jälki lets you ask it.**

---

Today, asking the Linux kernel "why is this connection slow?" requires eBPF expertise that maybe a few hundred people in the world have. You need to know BTF, aya, ring buffers, CO-RE, the BPF verifier, kernel struct offsets, and how to interpret raw tracing data. It's a week of work before you see a single structured event.

jälki removes that barrier. You ask a question. jälki hooks the right kernel function, collects the events, and interprets them:

```
❯ jalki ask "why is postgres slow"

Probes selected:
  tcp_connect (fexit/kernel.tcp.connect)
  tcp_retransmit_skb (fentry/kernel.tcp.retransmit)
  attached tcp_connect → probe_001
  attached tcp_retransmit_skb → probe_002
Collecting events for 5s...
Collected 47 events. Interpreting...

# Question: why is postgres slow

## Events observed (47 total in 5s)
  jalki/tcp_connect: 12 events
  jalki/tcp_retransmit: 35 events

## Interpretation

**tcp_retransmit_skb** (warning)

  packets are being lost on an active connection — network congestion,
  switch issue, or physical layer problem between nodes

  Action: check network path between 10.42.1.15 and 10.42.2.8.
  this is a network problem, not application.
```

The kernel knew the answer all along. 35 retransmits in ESTABLISHED state on the path to Postgres. Network problem, not application. jälki just made that knowledge accessible.

---

## Why this matters

**For humans**: Network debugging is dark magic. When connections are slow, you guess. You restart things. You blame the application. The kernel has the answer — retransmit counts, TCP states, connection errnos — but that data is locked behind eBPF expertise. jälki unlocks it with a single command.

**For AI agents**: An agent debugging a production issue can now ask the kernel directly. No human eBPF expertise in the loop. The agent identifies the right kernel function, deploys a probe, reads structured events, and reasons about root cause. This is the foundation for autonomous infrastructure debugging.

**For the eBPF ecosystem**: Writing a new fentry/fexit probe is one Rust trait. jälki handles BTF loading, program attachment, ring buffer management, self-filtering, sampling, serialization, and emission. The framework does the hard parts so you can focus on what to observe and how to interpret it.

---

## How it works

```
                    kernel space
   ┌────────────────────────────────────────────────┐
   │  tcp_connect()      → fexit  → eBPF program ──┐│
   │  tcp_close()        → fexit  → eBPF program   ││
   │  tcp_retransmit_skb → fentry → eBPF program   ││
   │                                                ││
   │  PID_FILTER: skip jälki's own syscalls         ││
   │  per-probe ring buffers (4MB each) ◄───────────┘│
   └────────────────────┬───────────────────────────┘
                        │
                    userspace
   ┌────────────────────▼───────────────────────────┐
   │  jälki daemon                                   │
   │                                                 │
   │  loader     → attach probes via BTF metadata    │
   │  reader     → drain ring buffers → EventStore   │
   │  probes     → raw bytes → FALSE Protocol JSON   │
   │  emitters   → stdout / file / gRPC              │
   │  IPC server → /run/jalki/jalki.sock             │
   │  metrics    → Prometheus :9090                  │
   └────────────────────┬───────────────────────────┘
                        │
   ┌────────────────────▼───────────────────────────┐
   │  CLI / MCP / agents                             │
   │                                                 │
   │  jalki ask   → question → probes → interpret    │
   │  jalki watch → collect events from one probe    │
   │  jalki-mcp   → AI agent tool interface          │
   └────────────────────────────────────────────────┘
```

**fentry/fexit** — BPF trampolines, not kprobes. Near-zero overhead. Safe for production 24/7.

**CO-RE** — Compile Once, Run Everywhere. One binary, any kernel 5.5+ with BTF.

**Self-filter** — jälki's own PID is excluded in kernel space. No feedback loops.

---

## Quick start

```bash
# Build
cargo run -p xtask -- build-ebpf --release
cargo build --release -p jalki

# Terminal 1: start the daemon (needs root for eBPF)
sudo ./target/release/jalki --emit stdout --cluster dev

# Terminal 2: ask a question
./target/release/jalki ask "why are connections failing"

# Or explore
./target/release/jalki list --layer tcp
./target/release/jalki status
./target/release/jalki watch tcp_connect --seconds 10
./target/release/jalki stream tcp_retransmit_skb
```

`jalki ask` works without a daemon too — it falls back to a knowledge base analysis showing which probes to deploy and what to look for.

---

## CLI

| Command | What it does |
|---------|-------------|
| `jalki` (no subcommand) | Daemon mode — load eBPF, attach probes, emit events |
| `jalki ask "question"` | KB search → auto-deploy → collect → interpret → answer |
| `jalki watch <function>` | Deploy probe, collect for N seconds, print events |
| `jalki stream [function]` | Live ndjson event stream |
| `jalki list [--layer tcp]` | Browse the knowledge base |
| `jalki status` | Show attached probes, event counts, drops |

---

## What you get

Every kernel function you care about becomes a structured event:

```json
{
  "source": "jalki/tcp_retransmit",
  "type": "kernel.tcp.retransmit",
  "severity": "warning",
  "correlation_keys": ["10.42.1.15:48210->10.42.2.8:5432"],
  "network_data": {
    "src_ip": "10.42.1.15",
    "dst_ip": "10.42.2.8",
    "dst_port": 5432,
    "protocol": "tcp"
  },
  "process_data": {
    "pid": 1847,
    "command": "api-server"
  }
}
```

Your API server is retransmitting to Postgres. The kernel knows this. Now you know it too.

---

## The knowledge base

jälki ships a built-in knowledge base of kernel functions — which function to hook for a given question, what fields matter, and how to interpret the events.

The TCP state field on `tcp_retransmit_skb` is the most important signal:

| State | Value | What it means |
|-------|-------|---------------|
| SYN_SENT | 2 | Handshake failing — remote unreachable, firewall, host down |
| ESTABLISHED | 1 | Active connection losing packets — network congestion |
| CLOSE_WAIT | 7 | Application hung, not reading from socket |

**SYN_SENT retransmit = not an application problem.** The connection never established.

**ESTABLISHED retransmit = network problem, not application.** The packets are being lost in transit.

Different problems, different fixes. The kernel knows which one it is.

---

## The framework

jälki is a framework, not just a tool. The three TCP probes are batteries-included. Adding your own probe is one trait:

```rust
impl Probe for MyProbe {
    fn name(&self) -> &str { "my_probe" }
    fn program_name(&self) -> &str { "jalki_my_probe" }
    fn attachments(&self) -> &[Attachment] {
        &[Attachment::Fentry { function: "some_kernel_function" }]
    }
    fn ring_buffer_map(&self) -> &str { "MY_EVENTS" }
    fn to_occurrence(&self, raw: &[u8], cluster: &str) -> Result<Occurrence, ProbeError> {
        // convert raw ring buffer bytes to a FALSE Protocol Occurrence
    }
}
```

jälki handles eBPF loading, BTF attachment, ring buffer management, self-filtering, sampling, batching, and emission. You describe what to observe and how to interpret it. The framework does the rest.

---

## MCP server

`jalki-mcp` exposes kernel observability to AI agents via the Model Context Protocol:

```
jalki_find_probe("why are connections slow")  → tcp_retransmit_skb, tcp_connect
jalki_deploy_probe("tcp_retransmit_skb")      → probe_001
jalki_get_events("probe_001", filter={...})   → [Occurrence, ...]
jalki_explain_event(function, tcp_state=1)    → "network problem, not application"
jalki_probe_status()                          → attached probes + counts
```

An agent asks the knowledge base before guessing. Deploys probes. Reads events. Gets interpretations. No eBPF expertise required.

---

## Built-in probes

| Probe | Hook | What it gives you |
|-------|------|-------------------|
| `TcpConnect` | `fexit/tcp_connect` | Connection attempts — 4-tuple, success/failure, errno |
| `TcpClose` | `fexit/tcp_close` | Connection teardown — 4-tuple, process info |
| `TcpRetransmit` | `fentry/tcp_retransmit_skb` | Retransmissions — 4-tuple, TCP state |

These three, joined on the 4-tuple, answer: which backends are being connected to, which connections are failing, which are retransmitting, and what the TCP state was when it happened.

---

## Kubernetes

Helm chart in `helm/jalki/`. Deploys as a DaemonSet with `hostPID`, `hostNetwork`, and privileged access for eBPF.

```bash
helm install jalki helm/jalki/ --set cluster=prod-east-1 --set emit=stdout
```

---

## Requirements

- Linux kernel 5.5+ x86, 6.0+ ARM64
- `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_JIT=y`
- BTF at `/sys/kernel/btf/vmlinux`
- Root or `CAP_BPF` + `CAP_PERFMON`

---

## Part of False Systems

```
jälki     kernel observation (this)
TAPIO     k8s observation
RAUTA     L7 gateway
POLKU     event transport
AHTI      causality correlation
syva      enforcement
rauha     container runtime
```

jälki is the deepest layer. It sees what the kernel sees.

---

> *jälki* (Finnish) — footprint, trace, track.

*false systems · berlin · 2026 · apache 2.0*
