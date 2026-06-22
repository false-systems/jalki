# Jälki — Design

> Jälki observes the kernel and answers questions about it. Polku transports its evidence to Vartio. Vartio interprets it and writes to Ahti. Lähde and Vartio reason across producers. Syvä enforces later.

> **⚠ Superseded in part by [ADR-0002](./adr/0002-evidence-through-polku-to-vartio.md) (2026-06-22) — read this first.** This directory's May-2026 pass framed Jälki as a *direct Ahti producer*. That is reversed: evidence flows `jälki → Polku → Vartio → Ahti`; **Jälki never writes to Ahti** (Vartio does); and Jälki **keeps** its product surface (`ask`/MCP/SDK/KB). Every doc here carries a banner noting what survives.
>
> **Amended by [ADR-0001](./adr/0001-evidence-sinks-and-probe-intelligence.md) (2026-05-20).** ADR-0001 reversed the "all interpretation in Lähde" boundary so Jälki may interpret; ADR-0002 keeps that but scopes interpretation to Jälki's *direct* surface (it is not written to Ahti). Read both ADRs before relying on any "MUST"/"MUST NOT" clause below.

This directory contains the design documents for Jälki in the new False Systems architecture. When the design is approved, implementation will follow in separate PRs against the existing crate layout (see top-level `CLAUDE.md`).

## What Jälki is

Jälki is a runtime/kernel evidence layer. It runs on every node and produces structured evidence of what the kernel and the container runtime are doing — process exec, file open, network connect, TCP retransmit, scheduler latency, block IO — and hands that evidence to Polku for delivery to Vartio.

Jälki is to **kernel functions** what an OTel collector is to userspace spans, with one critical difference: Jälki does not own a datastore, a dashboard, an alert engine, or a root-cause interpreter. It produces evidence and hands it to Polku → Vartio (which interprets and writes to Ahti).

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
        │  captures, enriches (cgroup→container→pod), normalizes — neutral evidence
        ▼
   Polku   (event transport)
        ▼
   Vartio  (interprets: ObservedEvent → operational chains → decisions)
        ▼
   Ahti    (append-first record store; Vartio is the writer)
        │
        └──► Lähde / Vartio reason across producers; Syvä enforces later
```

The boundaries are deliberate:

- Jälki **MUST** hand its evidence to Polku → Vartio. It **MUST NOT** write to Ahti directly, and **MUST NOT** keep a parallel durable store.
- Vartio interprets Jälki's evidence and is the writer of the resulting records to Ahti.
- Vartio decides Actor attribution. Jälki **MUST NOT** assert that a process belongs to an Actor envelope.
- Lähde decides observability meaning ("MySQL latency is network-related"). Jälki **MUST NOT** assert root cause on the evidence it ships (it MAY interpret on its own `ask`/MCP surface).
- Syvä will decide policy. Jälki **MUST NOT** enforce.

## Document map

| Document | Purpose |
|---|---|
| [`adr/0002-evidence-through-polku-to-vartio.md`](./adr/0002-evidence-through-polku-to-vartio.md) | **Current architecture — read first.** Evidence routes `jälki → Polku → Vartio → Ahti`; Jälki never writes Ahti; product surface kept. Supersedes the Ahti-producer framing across every doc below. |
| [`adr/0001-evidence-sinks-and-probe-intelligence.md`](./adr/0001-evidence-sinks-and-probe-intelligence.md) | The architectural gate for the `EvidenceSink` seam and the probe-intelligence reversal. Its Polku/Ahti *routing* (§D2) and Ahti-records interpretation (§D4) are superseded by ADR-0002. |
| [`product-boundaries.md`](./product-boundaries.md) | The does/does-not contract. Read first when in doubt — but note §2.2/§2.3/§2.5 are amended by ADR-0001. |
| [`ahti-record-mapping.md`](./ahti-record-mapping.md) | How every Jälki concept maps to one of Ahti's eight record kinds, using Ahti's actual field names. |
| [`runtime-evidence-model.md`](./runtime-evidence-model.md) | Per-evidence-type definitions: process_exec, file_open, network_connect, tcp_retransmit, etc. Source mechanism, required/optional fields, Ahti binding. |
| [`probe-definitions.md`](./probe-definitions.md) | How Jälki represents probe plan templates, kernel hook references, and sampling policies as Ahti `definition` / `reference` records. Ahti stores; agents execute. |
| [`local-agent-state.md`](./local-agent-state.md) | What lives on the agent (BPF maps, ring buffers, caches, retry buffer) vs. what reaches the pipeline. Offline buffering, gap representation, time semantics, enrichment. |

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

This design refactors the **output model**: the agent gains a neutral evidence plane that hands evidence to Polku → Vartio (which interprets and writes to Ahti). The fentry/fexit framework, the probe trait, and the eBPF crates are preserved — and per [ADR-0002](./adr/0002-evidence-through-polku-to-vartio.md), Jälki **keeps** its direct product surface (`ask` / MCP / SDK / knowledge base); it is not demoted. Jälki does not write to Ahti directly.

The v0 implementation slice is defined by [ADR-0002](./adr/0002-evidence-through-polku-to-vartio.md): a Polku→Vartio sink behind the existing `EvidenceSink`, mandatory node-local `cgroup→pod` enrichment, and a Vartio-side `Importer.Jalki`. (The old `v0-scope.md` was removed — it described the dead Ahti-producer slice.)
