# Jälki — Design

> Jälki observes the kernel and interprets what it sees. Polku routes the evidence. Ahti stores it. Lähde and Vartio reason across producers. Syvä enforces later.

> **Amended by [ADR-0001](./adr/0001-evidence-sinks-and-probe-intelligence.md) (2026-05-20).** The original pass made Jälki strictly observe-only with all interpretation in Lähde. ADR-0001 supersedes that for probe intelligence: Jälki now plans probes, correlates, and emits authoritative interpretations as `jalki.diagnosis.*` occurrences — while the datastore boundary (no Jälki datastore; Polku routes; Ahti stores) is unchanged. Read the ADR before relying on any "MUST NOT interpret" clause below.

This directory contains the design documents for Jälki in the new False Systems architecture. When the design is approved, implementation will follow in separate PRs against the existing crate layout (see top-level `CLAUDE.md`).

## What Jälki is

Jälki is a runtime/kernel evidence layer. It runs on every node and produces structured evidence of what the kernel and the container runtime are doing — process exec, file open, network connect, TCP retransmit, scheduler latency, block IO — and writes that evidence as Ahti records.

Jälki is to **kernel functions** what an OTel collector is to userspace spans, with one critical difference: Jälki does not own a datastore, a dashboard, an alert engine, or a root-cause interpreter. It produces evidence and hands it to Ahti.

## What Jälki is not

Jälki **MUST NOT** become:

- A durable datastore. Ahti is the datastore.
- An observability product. Lähde is the observability layer.
- An incident or Actor-attribution engine. Vartio interprets operational chains.
- A policy or enforcement engine. Syvä will enforce later.
- A causality engine. Ahti and Lähde interpret causality; Jälki only emits supporting evidence.

The full does/does-not contract is in [`product-boundaries.md`](./product-boundaries.md).

## The False Systems layering

```
   Jälki        kernel/runtime evidence producer  (this repo)
   Ahti         append-first structured datastore (substrate)
   Vartio       non-human Actor / operational chain attribution
   Lähde        observability interpretation
   Syvä         kernel/runtime enforcement (future)
```

Data flow:

```
  kernel + container runtime
        │  (eBPF, tracepoints, fentry/fexit, cgroup metadata)
        ▼
   Jälki agent (per node)
        │  buffers locally, normalizes evidence
        ▼
   Ahti  (append-first record store)
        │
        ├──► Lähde   (interprets observability)
        ├──► Vartio  (attributes operational Actor chains)
        └──► Syvä    (later: enforces decisions near the kernel)
```

The boundaries are deliberate:

- Jälki **MUST** write durable evidence to Ahti. It **MUST NOT** keep a parallel durable store.
- Lähde, Vartio, and Syvä **MUST** read Jälki evidence through Ahti, not directly from the agent. The agent is not a query surface for products.
- Vartio decides Actor attribution. Jälki **MUST NOT** assert that a process belongs to an Actor envelope.
- Lähde decides observability meaning ("MySQL latency is network-related"). Jälki **MUST NOT** assert root cause.
- Syvä will decide policy. Jälki **MUST NOT** enforce.

## Document map

| Document | Purpose |
|---|---|
| [`adr/0001-evidence-sinks-and-probe-intelligence.md`](./adr/0001-evidence-sinks-and-probe-intelligence.md) | The architectural gate for implementation: `EvidenceSink`, Polku/Ahti routing, and the probe-intelligence reversal. Read before the boundary docs. |
| [`product-boundaries.md`](./product-boundaries.md) | The does/does-not contract. Read first when in doubt — but note §2.2/§2.3/§2.5 are amended by ADR-0001. |
| [`ahti-record-mapping.md`](./ahti-record-mapping.md) | How every Jälki concept maps to one of Ahti's 7 core record kinds, using Ahti's actual field names. |
| [`runtime-evidence-model.md`](./runtime-evidence-model.md) | Per-evidence-type definitions: process_exec, file_open, network_connect, tcp_retransmit, etc. Source mechanism, required/optional fields, Ahti binding. |
| [`probe-definitions.md`](./probe-definitions.md) | How Jälki represents probe plan templates, kernel hook references, and sampling policies as Ahti `definition` / `reference` records. Ahti stores; agents execute. |
| [`local-agent-state.md`](./local-agent-state.md) | What lives on the agent (BPF maps, ring buffers, caches, retry buffer) vs. what must reach Ahti. Offline buffering, gap representation, time semantics, producer auth. |
| [`v0-scope.md`](./v0-scope.md) | First implementation slice. Explicit schemas, explicit non-goals, consolidated open questions, implementation implications. |

## Durable vs local state — the headline rule

> Jälki's durable evidence, definitions, references, and artifacts **MUST** live in Ahti.
> A Jälki agent **MAY** keep short-lived local state (BPF maps, ring buffers, metadata caches, retry buffers) for operational reasons.
> If a Jälki agent cannot reach Ahti, it **MUST** either buffer with a declared bound and a declared loss policy, or emit explicit gap records when buffering ends. Continuous evidence **MUST NOT** be implied when the agent was offline.

Details in [`local-agent-state.md`](./local-agent-state.md).

## The design sentence to preserve

> *"Jälki asks the kernel questions, emits structured evidence, and says what it likely means. Polku routes it. Ahti preserves it. Lähde and Vartio reason across producers."*

When any future design choice conflicts with this sentence, the design choice is wrong, not the sentence. (The earlier sentence — which placed *all* interpretation in Lähde — was deliberately replaced by [ADR-0001](./adr/0001-evidence-sinks-and-probe-intelligence.md). Changing this sentence requires an ADR, not an edit.)

## Relationship to today's repo

Today's `jalki` repo already implements:

- A programmable fentry/fexit framework (`Probe` trait, `jalki-ebpf`, `jalki-codegen`).
- Three built-in TCP probes emitting **FALSE Protocol Occurrences** to stdout / file / a stub gRPC sink.
- A local knowledge base and `ask`/`watch`/`stream`/`list`/`status` CLI surface.
- An MCP server exposing kernel observability to AI agents.

This design refactors the **output and storage model**: the agent stops being its own product surface and becomes an Ahti producer. The fentry/fexit framework, the probe trait, and the eBPF crates are preserved. The CLI / MCP / knowledge-base layers are reframed in [`product-boundaries.md`](./product-boundaries.md) — some belong with Jälki, others move to Lähde or Vartio, and the durable storage path goes to Ahti.

The v0 slice ([`v0-scope.md`](./v0-scope.md)) is intentionally small and back-pressure-safe.
