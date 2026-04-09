# jälki — Session 4

Read CLAUDE.md fully before touching any code. Understand the codebase before changing it.

## State

The skeleton works. 81 tests green. Real kernel events flowing on Fedora 43 / kernel 6.19.9. The framework is built. The MCP server has the right interface. The knowledge base is compiled in.

**Nothing talks to anything yet.** The MCP tools are stubs. The EventStore exists but nobody pushes to it. The ProbeRegistry exists but isn't wired into the Runtime. Hot-reload doesn't work end to end.

This session makes it real. One goal: `jalki ask "why is postgres slow"` returns a real interpretation from a real kernel.

Everything else is secondary to that goal.

---

## Critical Path — Do These In Order

Do not skip steps. Do not work on anything not on this list until the list is done.

---

### Step 1 — Wire EventStore into pipeline

The EventStore exists. The Reader discards events after emitting. Fix this.

In the reader, after converting raw bytes to an Occurrence, push to EventStore before emitting. The Runtime must hold an Arc<EventStore> and pass it to the Reader.

### Step 2 — Wire ProbeRegistry into Runtime

The ProbeRegistry exists. The Runtime doesn't expose it for runtime attachment.

The Runtime must hold the loaded Ebpf object, BTF, and ProbeRegistry. When deploy_probe is called: look up the function, attach via BTF, register, start a new Reader task, return probe_id.

### Step 3 — Unix socket IPC

The daemon needs to expose an internal API. Unix socket at /run/jalki/jalki.sock.

Protocol: newline-delimited JSON. Request → Response.

Methods: deploy_probe, detach_probe, get_events, get_all_events, probe_status, find_probe, explain_event.

### Step 4 — Wire MCP server to Unix socket

jalki-mcp connects to the daemon socket. Each MCP tool call translates to a socket request. Clear error if daemon not running.

### Step 5 — CLI: `jalki ask` and `jalki watch`

`jalki ask` is the killer feature. Knowledge base search → auto-attach → collect → interpret → one answer.

`jalki watch` — one-shot collection. `jalki stream` — live ndjson. `jalki list` — discovery. `jalki status` — what's running.

Standalone mode: if no daemon socket, watch/stream attach probes directly.

### Step 6 — Dockerfile

Two-stage build. Distroless runtime. Under 20MB. Both jalki and jalki-mcp binaries.

---

## Definition of Done

```bash
# terminal 1
sudo jalki --emit stdout --cluster dev

# terminal 2
jalki ask "why is k3s connecting to things slowly"
```

Real interpretation from real kernel events.

## What Not To Touch

- Do not break the 81 passing tests
- Do not implement Python SDK
- Do not implement codegen
- Do not add knowledge base entries until steps 1-5 are done
- Do not refactor what works
