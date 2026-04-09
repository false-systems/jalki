# jälki — Next Session Prompt

You are working on jälki, a programmable fentry/fexit framework for Linux. Read CLAUDE.md fully before touching any code.

## Context

jälki is to kernel functions what POLKU is to gRPC. You define a probe, jälki handles everything else. The skeleton is working — real kernel events are flowing from `tcp_connect`, `tcp_close`, and `tcp_retransmit_skb` to stdout as FALSE Protocol Occurrences. The foundation is solid. Now we build the framework that makes jälki a revolution.

## What Exists

- `jalki-common/` — no_std shared event structs, size-locked, aya::Pod impls
- `jalki-ebpf/` — three working eBPF programs, ring buffers, PID_FILTER self-filter
- `jalki/` — Probe trait, Emitter trait, Loader, Reader, Runtime builder, StdoutEmitter, FileEmitter, GrpcEmitter stub, Prometheus metrics on :9090
- `knowledge/tcp.json` — TCP layer knowledge base (tcp_connect, tcp_close, tcp_retransmit_skb, tcp_sendmsg, inet_csk_accept)

## What To Build

Build these in order. Each one is a prerequisite for the next.

---

### 1. In-Memory Event Store

The daemon needs to buffer recent events so agents can query them. Right now events flow out and are gone.

```rust
pub struct EventStore {
    // per probe, ring buffer of last N occurrences
    // N is configurable, default 10_000
    // thread-safe, lock-free reads preferred
}

impl EventStore {
    pub fn push(&self, probe_name: &str, occurrence: Occurrence);
    pub fn query(&self, probe_name: &str, filter: EventFilter) -> Vec<Occurrence>;
    pub fn query_all(&self, filter: EventFilter) -> Vec<Occurrence>;
}

pub struct EventFilter {
    pub last_seconds: Option<u64>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub pid: Option<u32>,
    pub command: Option<String>,
    pub limit: Option<usize>,  // default 100
}
```

Wire the Reader to push every occurrence into the EventStore before emitting.

---

### 2. Hot-Reload — Runtime Probe Attachment

The daemon must be able to attach a new probe without restart. This is the core capability that makes the MCP server real.

The eBPF object contains all compiled probes. At startup, only the configured probes attach. At runtime, any probe in the object can be activated by name.

```rust
pub struct ProbeRegistry {
    // tracks attached probes
    // tracks event counts and drop counts per probe
    // allows runtime attachment of pre-compiled probes
}

impl ProbeRegistry {
    pub fn attach(&mut self, function: &str) -> Result<ProbeId, JalkiError>;
    pub fn detach(&mut self, probe_id: &ProbeId) -> Result<(), JalkiError>;
    pub fn status(&self) -> Vec<ProbeStatus>;
    pub fn is_attached(&self, function: &str) -> bool;
}

pub struct ProbeStatus {
    pub probe_id: String,
    pub function: String,
    pub attached_since: DateTime<Utc>,
    pub events_total: u64,
    pub ring_buffer_drops: u64,
    pub sample_rate: f64,
}
```

All compiled eBPF programs ship in the binary. The agent activates them by function name. No restart required.

---

### 3. Knowledge Base

Load the knowledge base from JSON at startup. Fall back to embedded default if no file found.

```rust
pub struct KnowledgeBase {
    probes: Vec<ProbeKnowledge>,
}

impl KnowledgeBase {
    pub fn load() -> Self;  // loads from /etc/jalki/knowledge/ or embedded default
    pub fn find(&self, question: &str) -> Vec<&ProbeKnowledge>;  // semantic search
    pub fn get(&self, function: &str) -> Option<&ProbeKnowledge>;
    pub fn interpret(&self, event: &Occurrence) -> Option<Interpretation>;
}
```

The `find` method does keyword matching against `answers` and `keywords` fields. Not AI — simple token overlap scoring. Good enough.

The `interpret` method matches an event against the `interpretations` array for its function. Match on tcp_state, errno, patterns. Returns the best matching interpretation.

Rust deserializes the JSON at compile time via `include_str!` + `serde_json`. If the JSON is malformed, the binary fails to compile. The Rust types ARE the schema.

```rust
// jalki/src/knowledge/mod.rs
const TCP_KNOWLEDGE: &str = include_str!("../../../knowledge/tcp.json");
```

---

### 4. Interpreter

Given an occurrence, return the matching interpretation from the knowledge base.

```rust
pub fn interpret(kb: &KnowledgeBase, event: &Occurrence) -> InterpretationResult {
    InterpretationResult {
        function: String,
        conclusion: String,
        severity: Severity,
        action: String,
        confidence: f64,  // 0.0 - 1.0
        not: Option<String>,  // common misdiagnosis to avoid
    }
}
```

For tcp_retransmit_skb, extract `tcp_state` from `event.data.labels` and match against the interpretations table. This is the most important interpreter — getting SYN_SENT vs ESTABLISHED right is the core value.

---

### 5. MCP Server

Stdio JSON-RPC MCP server. Same pattern as luotain-mcp — hand-rolled, no dependencies. Study luotain-mcp/src/main.rs for the pattern.

Five tools:

**`jalki_find_probe`**
```json
input:  { "question": "why is api-server slow connecting to postgres" }
output: {
  "matches": [
    {
      "function": "tcp_retransmit_skb",
      "why": "retransmits in ESTABLISHED state = network packet loss, not application bug",
      "confidence": "high",
      "attachment": "fentry",
      "combine_with": ["tcp_connect"]
    }
  ]
}
```

**`jalki_deploy_probe`**
```json
input:  { "function": "tcp_retransmit_skb", "sample_rate": 1.0 }
output: { "probe_id": "probe_001", "status": "attached", "function": "tcp_retransmit_skb" }
```

**`jalki_get_events`**
```json
input:  { "probe_id": "probe_001", "last_seconds": 60, "filter": { "dst_port": 5432 } }
output: { "events": [...occurrences...], "total": 14, "dropped": 0 }
```

**`jalki_explain_event`**
```json
input:  { "event": { ...occurrence... } }
output: {
  "conclusion": "ESTABLISHED retransmit: network is losing packets between nodes",
  "severity": "error",
  "action": "check network path between 10.42.1.15 and 10.42.2.8",
  "not": "this is not an application bug — the application is fine"
}
```

**`jalki_probe_status`**
```json
input:  {}
output: {
  "probes": [
    {
      "probe_id": "probe_001",
      "function": "tcp_retransmit_skb",
      "events_total": 34,
      "drops": 0,
      "attached_since": "2026-04-09T14:32:01Z"
    }
  ]
}
```

The MCP server binary is `jalki-mcp`. It connects to the running jalki daemon via Unix socket or shared state. The daemon exposes an internal API; the MCP server is a thin translation layer.

---

### 6. Probe Descriptor — Foundation for SDK

Define the probe descriptor format that will power the Python/Go SDKs. This is not the SDK itself — it's the wire format that SDKs will generate.

```rust
#[derive(Serialize, Deserialize)]
pub struct ProbeDescriptor {
    pub function: String,           // kernel function name
    pub attachment: Attachment,     // fentry or fexit
    pub fields: Vec<String>,        // which fields to extract
    pub filter: Option<ProbeFilter>,// kernel-side filter (pid, port, etc)
    pub sample_rate: f64,           // 1.0 = all events
    pub event_type: String,         // FALSE Protocol type string
}

pub struct ProbeFilter {
    pub dst_port: Option<u16>,
    pub src_ip: Option<String>,
    pub pid: Option<u32>,
    pub command: Option<String>,
}
```

The daemon must accept a `ProbeDescriptor` and activate the matching pre-compiled probe with the specified filter. This is the bridge between the static pre-compiled probes and the dynamic SDK.

Add a sixth MCP tool:

**`jalki_deploy_descriptor`**
```json
input: {
  "function": "tcp_retransmit_skb",
  "attachment": "fentry",
  "fields": ["src_ip", "dst_ip", "src_port", "dst_port", "tcp_state", "pid", "command"],
  "filter": { "dst_port": 5432 },
  "sample_rate": 1.0,
  "event_type": "kernel.tcp.retransmit"
}
output: { "probe_id": "probe_002", "status": "attached" }
```

This is what the Python SDK will call. The Python decorator:

```python
@jalki.probe(fexit="tcp_connect")
def on_connect(src_ip, dst_ip, dst_port, pid, comm, ret):
    return jalki.occurrence(type="kernel.tcp.connect", ...)
```

compiles to a ProbeDescriptor JSON and calls `jalki_deploy_descriptor`. The daemon looks up the pre-compiled program for `tcp_connect`, applies the field filter and port filter, loads it. No compiler on the node.

---

### 7. Full Codegen — The Revolution

This is the hardest piece and the one that makes jälki truly open. An agent should be able to hook ANY kernel function, not just the pre-compiled ones.

The approach: runtime eBPF bytecode generation in Rust. No LLVM dependency. No C toolchain. The daemon generates BPF bytecode directly from a ProbeDescriptor + BTF.

Steps:
1. Read function signature from `/sys/kernel/btf/vmlinux` using aya's BTF API
2. Determine field offsets for requested fields
3. Generate BPF bytecode that extracts those fields at those offsets
4. Load the bytecode via aya
5. Attach to the function

This bypasses the verifier concern because the generated program has hardcoded offsets — the verifier sees concrete values, not map lookups.

This is what Tetragon does in Go. We do it in Rust with aya. Study how Tetragon's `GenericKprobe` works conceptually — the idea, not the code.

The minimal bytecode generator:

```rust
pub struct ProbeCodegen {
    btf: Btf,  // loaded from /sys/kernel/btf/vmlinux
}

impl ProbeCodegen {
    pub fn generate(&self, descriptor: &ProbeDescriptor) -> Result<Vec<u8>, CodegenError>;
    // returns raw BPF bytecode ready for aya to load
}
```

When this exists, `jalki_deploy_descriptor` stops looking up pre-compiled programs and generates bytecode on the fly. Every kernel function becomes hookable. No pre-compilation required.

This is v0.3 territory but design it now so nothing in v0.2 blocks it.

---

### 8. Helm Chart

```
jalki/
└── helm/
    └── jalki/
        ├── Chart.yaml
        ├── values.yaml
        └── templates/
            ├── daemonset.yaml
            ├── serviceaccount.yaml
            ├── clusterrole.yaml
            ├── clusterrolebinding.yaml
            └── service.yaml       ← exposes MCP server as ClusterIP
```

DaemonSet with:
- `hostPID: true`
- `hostNetwork: true`
- `privileged: true`
- `bpffs` and `debugfs` volume mounts
- MCP server exposed as ClusterIP service on port 7777

```bash
helm install jalki ./helm/jalki \
  --set cluster=prod-east-1 \
  --set emit=grpc://polku.observability.svc:50051
```

Agent connects to `jalki.observability.svc:7777` via MCP. Done.

---

### 9. Knowledge Base — Fill It In

Once everything above works, fill in the remaining knowledge base layers. The TCP layer is done. Add:

- `knowledge/memory.json` — mm_page_alloc, oom_kill_process, vm_mmap, do_mmap
- `knowledge/fs.json` — vfs_open, vfs_write, vfs_read, do_sys_openat2
- `knowledge/sched.json` — finish_task_switch, try_to_wake_up, schedule
- `knowledge/process.json` — do_execve, do_exit, copy_process

Same schema as tcp.json. Same level of detail on interpretations. Be precise — a wrong interpretation misleads every agent that reads it.

---

## Architecture After This Session

```
jalki-mcp (stdio)
    ↓
jalki daemon
    ├── ProbeRegistry (hot-reload, status)
    ├── EventStore (in-memory ring buffer)
    ├── KnowledgeBase (find, interpret)
    ├── ProbeCodegen (BTF → bytecode, v0.3)
    └── Emitters (stdout, file, gRPC)
        ↓
    eBPF programs (kernel space)
        ↓
    ring buffers
```

---

## The Vision — Write This In Your Head Before Coding

An agent is investigating "why is api-server slow."

```
agent → jalki_find_probe("slow connections to postgres")
      ← [tcp_retransmit_skb, tcp_connect]

agent → jalki_deploy_probe("tcp_retransmit_skb")
      ← probe_id: "probe_001"

agent → wait 30 seconds

agent → jalki_get_events("probe_001", filter={dst_port: 5432})
      ← [{ tcp_state: "ESTABLISHED", src: "10.42.1.15", dst: "10.42.2.8:5432", pid: 1847, command: "api-server" }]

agent → jalki_explain_event(event)
      ← "ESTABLISHED retransmit: network is losing packets between 10.42.1.15 and 10.42.2.8.
         This is NOT an application bug. The network path between these nodes is degraded.
         Action: check switch between these nodes."
```

No human eBPF expertise. No dashboards. No log parsing. The kernel told us directly.

That is what jälki is for. Build accordingly.

---

## Constraints

- No `.unwrap()` in userspace — use `?` or handle errors explicitly
- No `println!` in library code — use `tracing`
- eBPF code is unsafe by necessity — document every unsafe block
- Size tests in jalki-common are mandatory and must not be broken
- The knowledge base JSON must compile — Rust types are the schema
- Self-filter must always be active — jälki never observes itself
- The MCP server follows the same stdio JSON-RPC pattern as luotain-mcp
- Single binary — no runtime deps, no LLVM, no kernel headers (until codegen)

## Do Not

- Do not add dependencies without a clear reason
- Do not break the existing working probes
- Do not write the Python SDK yet — ProbeDescriptor is enough for now
- Do not implement full codegen yet — design the interface, stub the implementation
- Do not add a database — EventStore is in-memory only
