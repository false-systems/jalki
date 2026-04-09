# jälki — Next Session Prompt

You are working on jälki, a programmable fentry/fexit framework for Linux. Read CLAUDE.md fully before touching any code.

## Context

jälki is to kernel functions what POLKU is to gRPC. You define a probe, jälki handles everything else. The skeleton is working — real kernel events are flowing from `tcp_connect`, `tcp_close`, and `tcp_retransmit_skb` to stdout as FALSE Protocol Occurrences. The foundation is solid. Now we build the framework that makes jälki a revolution.

## What Exists

- `jalki-common/` — no_std shared event structs, size-locked, aya::Pod impls
- `jalki-ebpf/` — three working eBPF programs, ring buffers, PID_FILTER self-filter
- `jalki/` — Probe trait, Emitter trait, Loader, Reader, Runtime builder, StdoutEmitter, FileEmitter, GrpcEmitter stub, Prometheus metrics on :9090, EventStore (in-memory), ProbeRegistry (runtime attach/detach), ProbeDescriptor (wire format), KnowledgeBase (5 layers, 11 functions)
- `jalki-mcp/` — MCP server with 6 tools (find_probe, deploy_probe, get_events, explain_event, probe_status, deploy_descriptor) — tools have correct interfaces but MCP↔daemon IPC is stubbed
- `knowledge/` — tcp.json, memory.json, fs.json, sched.json, process.json
- `helm/jalki/` — DaemonSet + MCP Service on :7777
- `eval/oracle/` — 34 blackbox test cases, zero jalki dependencies
- 81 total tests, all green

## What's Missing — Build In Order

### 1. Wire MCP ↔ Daemon IPC

The critical path. EventStore, ProbeRegistry, and KnowledgeBase exist but jalki-mcp returns stubs. Wire them together via shared state or Unix socket so deploy_probe, get_events, and probe_status return real data.

### 2. Wire EventStore into Pipeline

Reader needs to push events into Arc<EventStore> before emitting. Runtime needs to hold the store and pass it to readers.

### 3. Wire ProbeRegistry into Runtime

Runtime needs to hold Ebpf + Btf + ProbeRegistry and expose an API for runtime attachment. Hot-reload must actually work.

### 4. CLI — `jalki watch`, `jalki ask`, `jalki stream`

```bash
jalki watch tcp_connect --seconds 10
jalki ask "why is my postgres connection slow" --seconds 30
jalki stream tcp_retransmit --filter dst_port=5432
jalki list probes --layer tcp
jalki status
```

The `ask` command is the killer feature — knowledge base search → auto-attach → collect → interpret → one answer.

CLI talks to daemon via Unix socket if running, falls back to standalone mode (attaches probes directly).

### 5. Standalone Emitters

```bash
jalki --emit datadog --dd-api-key $DD_API_KEY
jalki --emit loki://loki:3100
jalki --emit webhook://https://my-collector.example.com/events
jalki --emit otlp://otel-collector:4317
```

DatadogEmitter, LokiEmitter, WebhookEmitter, OtelEmitter. Works without False Systems stack.

### 6. Dockerfile

Single binary, distroless, under 20MB. eBPF object as separate file.

### 7. Enhanced Helm Chart

Add configmap for knowledge base override, emit type selection (stdout/grpc/datadog/loki/webhook/otlp), default probe list, resource limits.

### 8. Python SDK Stub

Interface defined, methods raise NotImplementedError. The decorator example:

```python
@client.probe(fexit="tcp_connect")
def on_connect(event):
    if event.ret < 0:
        return jalki.occurrence(type="kernel.tcp.connect", severity="warning")
```

### 9. Knowledge Base Expansion

Add more functions to reach ~30: tcp_recvmsg, vfs_read, do_sys_openat2, try_to_wake_up, schedule, copy_process, mm_page_alloc, vm_mmap, do_mmap.

### 10. Codegen Stub (v0.3 prep)

Design the ProbeCodegen interface. BTF → BPF bytecode. Don't implement — stub it so nothing blocks it later.

## Constraints

- No `.unwrap()` in userspace — use `?` or handle errors explicitly
- No `println!` in library code — use `tracing`
- eBPF code is unsafe by necessity — document every unsafe block
- Size tests in jalki-common are mandatory and must not be broken
- The knowledge base JSON must compile — Rust types are the schema
- Self-filter must always be active — jälki never observes itself
- The MCP server follows the same stdio JSON-RPC pattern as luotain-mcp
- Single binary — no runtime deps, no LLVM, no kernel headers (until codegen)
- Oracle must not depend on any jalki crate

## Do Not

- Do not add dependencies without a clear reason
- Do not break the existing working probes
- Do not write the Python SDK implementation — stub only
- Do not implement full codegen — design the interface, stub
- Do not add a database — EventStore is in-memory only
