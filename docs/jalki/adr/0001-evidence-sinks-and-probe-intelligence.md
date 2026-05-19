# ADR-0001 — Evidence sinks, Polku/Ahti routing, and Jälki probe intelligence

- **Status:** Accepted
- **Date:** 2026-05-20
- **Supersedes:** `product-boundaries.md` §2.2, §2.3, §2.5 (in part); `ahti-record-mapping.md` §11 (in part). See §6.
- **Still binding:** `product-boundaries.md` §2.1 (no datastore), §2.4 (no enforcement), §2.6 (no `ahti` namespace), §2.7 (invent no record kinds), §2.8 (no silent loss).
- **Driver:** Reframe Jälki from an eBPF CLI/probe demo into the node-local **kernel evidence plane** of the False Systems stack.

This ADR is the architectural gate for the implementation phase. It changes *design*, not *code*. No behaviour changes land with this document; PRs that follow implement it incrementally.

---

## 1. Context

The May 2026 design pass (`docs/jalki/`) established Jälki as a strict, observe-only Ahti producer: it collects kernel evidence, normalises it, and writes it to Ahti, while **all** interpretation, correlation, and judgment move to Lähde and Vartio. That boundary was deliberately strict (`product-boundaries.md` §6 reserves the right to loosen specific items via an ADR with explicit sign-off).

Two pressures motivate revisiting it:

1. **Routing.** The pass assumed a single direct agent→Ahti write path. The False Systems stack has a transport/routing layer (**Polku**). Production topology needs routing, fan-out, and delivery policy that does not belong inside the datastore and should not be hard-wired into the agent.

2. **Probe intelligence.** The best kernel evidence is only useful if it is *legible*. A bare "47 retransmits" record forces every downstream consumer to re-derive what a probe author already knows ("ESTABLISHED-state retransmits indicate path packet loss, not application latency"). The pass exiled that knowledge to Lähde. Operators and agents want Jälki itself to plan probes for a question and emit candidate explanations with confidence — turning Jälki from a sensor into a diagnostic instrument.

The owner has explicitly chosen to **supersede** the interpretation boundary (not merely soften it). This ADR records that decision and, crucially, defines how interpretation maps onto Ahti's record model **without inventing a new record kind** — so the reversal stays inside the protocol.

The design sentence is updated from:

> *Jälki observes runtime evidence. Ahti stores it. Vartio and Lähde interpret it. Syvä enforces later.*

to:

> *Jälki observes the kernel and interprets what it sees. Polku routes the evidence. Ahti stores it. Lähde and Vartio reason across producers. Syvä enforces later.*

Darker, for the README: *The kernel already saw the failure. Jälki makes sure the evidence survives — and says what it likely means.*

---

## 2. Decision

### D1 — Evidence leaves Jälki through a single `EvidenceSink` abstraction

All durable output **MUST** pass through one trait. The existing `Emitter` trait (`jalki/src/emitter.rs`) is replaced by `EvidenceSink`; it is the same role (async, batch-oriented) with a richer return type that distinguishes failure modes.

```rust
#[async_trait]
pub trait EvidenceSink: Send + Sync {
    fn name(&self) -> &str;
    async fn append_batch(&self, batch: EvidenceBatch) -> Result<AppendResult, SinkError>;
    async fn health(&self) -> HealthStatus;
}
```

`EvidenceBatch` carries batch identity, producer/runtime metadata, the observed-time window, and the records:

```text
EvidenceBatch {
    batch_id,
    producer, producer_version,
    cluster, node,
    observed_at_min, observed_at_max,
    records: Vec<EvidenceRecord>,
    source: Option<RuntimeMetadata>,   // probe/runtime context
}
```

`AppendResult { accepted_count, rejected_count, sink_name, watermark: Option<Checkpoint>, warnings }`.

`SinkError` **MUST** distinguish at least: `Unavailable`, `Timeout`, `InvalidRecord`, `Rejected`, `Backpressure`, `Unauthorized`, `Misconfigured`, `PartialFailure`, `Unsupported`. Sinks **MUST NOT** collapse these into a single opaque error — `Unavailable` (retry) and `Rejected` (do not retry; the record is wrong) demand opposite handling (`product-boundaries.md` §2.8).

### D2 — Ahti receives directly; Polku routes; Jälki supports both behind the trait

```text
kernel event
  → eBPF probe
  → raw ring-buffer payload
  → KernelEvent (typed)            [D3]
  → FALSE Protocol records         [D4]
  → EvidenceBatch
  → EvidenceSink
        ├── PolkuSink  → Polku → Ahti (+ other consumers)   [production default]
        ├── AhtiSink   → Ahti                                [simple / direct]
        ├── StdoutSink                                       [dev]
        ├── FileSink                                         [dev]
        └── CompositeSink(primary, secondaries…)             [debug fan-out]
```

- Ahti **MUST** expose a native append API for FALSE Protocol records and **MUST NOT** depend on Polku for basic ingestion. The datastore stays independently usable.
- Polku **MUST** own routing, fan-out, delivery policy, and optional buffering. Polku **MUST NOT** own Ahti storage semantics (Arrow/Parquet layout, snapshots, tiering).
- Jälki **MUST** support `PolkuSink` and `AhtiSink` behind the same `EvidenceSink`. Production **SHOULD** default to Polku; direct-to-Ahti is a valid simple deployment.
- Jälki **MUST NOT** import Ahti storage internals (Arrow `RecordBatch`, Parquet, DataFusion, hot-tier types). It produces FALSE Protocol records and hands them to a sink.

**Non-decision (explicitly rejected):** forcing *all* writes through Polku (couples the datastore to the router) and forcing *all* writes direct to Ahti (defeats routing/fan-out). Both rigidities are wrong; the trait + two implementations is the model.

### D3 — A typed `KernelEvent` layer sits between raw bytes and FALSE Protocol

Raw ring-buffer bytes **MUST NOT** be converted directly into FALSE Protocol records or ad-hoc JSON. Each probe **MUST** decode into a typed `KernelEvent` first, then normalise that into records.

```text
raw &[u8] → KernelEvent (e.g. TcpRetransmitEvent) → NormalizedEvidence { records: Vec<EvidenceRecord> }
```

`NormalizedEvidence` returns *many* records, not one: a single kernel event may yield an `occurrence`, one or more `entity_version` records, and `relationship_claim` edges (see `ahti-record-mapping.md` §2–§4). Decoding and normalisation are separate, separately tested steps. The `KernelEvent` types and the evidence model carry **no `aya` dependency** so they compile and unit-test on non-Linux hosts (macOS dev).

### D4 — Jälki owns probe intelligence and emits interpretations *as Ahti records, within the eight kinds*

This is the reversal. Jälki **MAY** now:

- Maintain a machine-readable **probe catalog** (catalog v2): per probe, the questions it answers, the signals it emits, **interpretation rules** (e.g. `tcp_state == ESTABLISHED ⇒ class network_packet_loss`), suggested actions, limitations, and confidence hints.
- Run a deterministic **ask planner**: question → intent → probe plan → collection plan → interpretation, printing the plan before attaching probes.
- **Correlate** events into diagnostic stories over the 4-tuple / pid / cgroup / netns and emit a candidate conclusion with confidence.

But the reversal is surgical. Interpretation maps onto Ahti's existing eight kinds — **Jälki still invents no record kind** (§2.7 holds):

| Intelligence artifact | Ahti record kind | `evidence_level` | Notes |
|---|---|---|---|
| Catalog interpretation *rule* (`when … ⇒ class/action`) | `definition` (`vocabulary_term`) | `declared` | The rule, written by `jalki-control`, not a per-event judgment |
| Per-event/per-window **conclusion** ("likely packet loss between A and B") | `occurrence`, `occurrence_type = jalki.diagnosis.<class>` | `derived` | **MUST** cite the supporting raw occurrences in `evidence_refs` |
| Probe plan for a question | `definition` (`vocabulary_term`, `probe_plan_template`) | `declared` | Already anticipated by `probe-definitions.md` |
| Operator/agent note on a diagnosis | `annotation` | `declared` | Per `ahti-record-mapping.md` §8 |

Rules for the new diagnostic occurrence:

- A `jalki.diagnosis.*` occurrence **MUST** set `evidence_level = derived` and **MUST** populate `evidence_refs` with the raw `observed` occurrences it is built from. A diagnosis with no evidence refs is invalid.
- It **MAY** carry a `confidence` value and a `severity` in its payload — these are now **Jälki product judgments**, permitted by this ADR. They are scoped to the `jalki.diagnosis.*` type; raw `observed` kernel occurrences **MUST NOT** carry product severity (keeps raw evidence neutral and re-interpretable).
- Consumers **MUST NOT** rank by `evidence_level` (Ahti rule, unchanged). Confidence is the ranking signal, and it lives in payload, not in `evidence_level`.

This keeps two properties the design pass cared about: raw evidence stays neutral and reusable, and every interpretation is traceable to the evidence that produced it.

### D5 — `observed_at` and `ingested_at` are distinct and never conflated

Jälki **MUST** preserve the kernel observation time (`event_time` in Ahti's envelope; `observed_at_min/max` on the batch) independently. Jälki **MUST NOT** set Ahti's ingest time — Ahti owns `received_at` at append. Jälki **MUST NOT** backfill `event_time` to fit an idealised timeline (`product-boundaries.md` §2.8). Monotonic/skew detail rides in payload (`kernel_time_ns`, `agent_recv_time`, `clock_skew_estimate_ms`) per `ahti-record-mapping.md` §10.3.

### D6 — Every record carries complete, boring producer/probe/kernel metadata

Where the field exists, records **MUST** carry: `producer = jalki`, `producer_version`, `probe_id`, `probe_version`, `probe_family`, `hook_kind` (fentry/fexit/lsm), `kernel_function`, `kernel_release`, `node_id`, `cluster_id`, and (when resolved) `cgroup_id`, `netns`, `pid`/`tgid`, `comm`. Unresolvable fields are **omitted, not zero-padded** (`product-boundaries.md` §1.2). Provenance that is "the rule/template/hook that produced this" goes in `lineage_refs`; provenance that is "the evidence this assertion rests on" goes in `evidence_refs`. They are not merged.

---

## 3. Consequences

**Positive**

- One output seam (`EvidenceSink`) makes stdout/file/Polku/Ahti/composite interchangeable and independently testable with a fake sink.
- Direct-to-Ahti and via-Polku are both first-class; deployment topology is a config choice, not a code fork.
- Interpretations are durable, queryable, and *traceable* (every diagnosis cites its evidence) instead of trapped in CLI prose.
- The `aya`-free evidence/catalog/planner layers are unit-testable on macOS, where `jalki` itself cannot compile.

**Negative / costs**

- Reverses a boundary the team signed off three weeks ago. `product-boundaries.md` and `README.md` must be amended in lockstep (done in this PR) so the design corpus is not self-contradictory.
- Jälki now ships product judgment. A wrong interpretation rule misleads agents at scale (catalog changes redeploy to every node). Mitigation: interpretation *rules* are `definition` records distributable via `jalki-control` without a binary redeploy; per-event diagnoses always cite evidence so a consumer can audit the call.
- `AhtiSink`/`PolkuSink` are built against fakes until the real append/route wire protocols exist (neither client crate exists today). Risk of drift; mitigated by narrow client traits (`AhtiAppendClient`, `PolkuRouteClient`) and coordinating the real protocol with the `ahti` repo before those sinks go live.

**Boundary that still holds (do not let these drift):**

- No Jälki datastore. If "where does this live for a week?" is anywhere but Ahti, the design is wrong.
- No enforcement. Observe-only, even where eBPF could attach to enforcement hooks.
- No writing to the `ahti` namespace; no inventing a ninth record kind.
- No silent loss: outages produce explicit `jalki.agent.gap` occurrences.
- No Actor attribution. Mechanical edges (`process_in_container`) yes; "belongs to deployment X / caused incident Y" remains Vartio's.

---

## 4. Scope of the implementation phase

Uncontroversial plumbing (no boundary dependency) may proceed independently of D4:

- Typed `KernelEvent` model and `NormalizedEvidence` (D3).
- `EvidenceBatch` + metadata model (D5, D6).
- `EvidenceSink` + Stdout/File/Fake; then `AhtiSink`, `PolkuSink`, `CompositeSink`; then spool/retry (D1, D2).

Intelligence layers depend on D4 and are gated on this ADR being accepted:

- Probe catalog v2, ask planner, evidence correlation, `jalki.diagnosis.*` emission.

Crate/module shape: one new `aya`-free crate `jalki-evidence` (KernelEvent, EvidenceBatch, sink traits, normalisation). Everything else stays as modules inside `jalki` (`sink/`, `planner/`, evolved `knowledge/`); extract further crates only when `jalki-control` needs to share a client.

---

## 5. Alternatives considered

- **Keep the strict boundary; interpretation stays in Lähde.** Rejected by the owner: Jälki should be a diagnostic instrument, not only a sensor. Interpretation distant from the probe author loses the author's knowledge.
- **Reframe interpretations as non-authoritative hypotheses only.** Considered (it was the lower-reversal option). Rejected in favour of authoritative Jälki judgments — but the *mechanism* chosen (derived occurrences citing evidence, neutral raw records) preserves most of that option's safety.
- **All writes through Polku.** Rejected: couples Ahti ingestion to the router.
- **All writes direct to Ahti.** Rejected: defeats routing/fan-out; rigid topology.
- **Invent a `diagnosis`/`incident` record kind.** Rejected: violates §2.7. `occurrence` + `evidence_level: derived` + `evidence_refs` already expresses it.

---

## 6. Exactly what this supersedes

| Prior clause | Prior text (paraphrased) | New position |
|---|---|---|
| `product-boundaries.md` §2.2 | Jälki MUST NOT decide root cause or stamp severity | **Superseded.** Jälki MAY emit root-cause conclusions and severity **only** on `jalki.diagnosis.*` occurrences (`evidence_level: derived`, evidence_refs required). Raw `observed` occurrences stay neutral. |
| `product-boundaries.md` §2.3 | Jälki MUST NOT correlate into call chains | **Superseded for diagnostic correlation** over 4-tuple/pid/cgroup/netns. Actor/ownership attribution remains Vartio's. |
| `product-boundaries.md` §2.5 | Jälki MUST NOT define incident/chain concepts | **Partially superseded.** Jälki MAY emit `jalki.diagnosis.*` occurrences. It still MUST NOT define `incident`/`chain` *record kinds* (§2.7 holds). |
| `ahti-record-mapping.md` §11 | No payload field named `interpretation`/`root_cause`/`verdict`/`conclusion`; no severity as judgment | **Superseded for `jalki.diagnosis.*` only.** Those payload fields and a payload `severity`/`confidence` are permitted on diagnosis occurrences; forbidden on raw kernel occurrences. |

All other MUST/MUST NOT clauses in `product-boundaries.md` remain in force. Any future drift past them needs its own ADR.
