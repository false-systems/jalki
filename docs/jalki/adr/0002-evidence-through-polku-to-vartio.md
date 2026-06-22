# ADR-0002 — Evidence routes through Polku to Vartio; Jälki keeps its product surface

- **Status:** Accepted
- **Date:** 2026-06-22
- **Supersedes:** ADR-0001 §D2 (routing) and §D4 (interpretation-as-Ahti-records) in part; the "Jälki is a direct Ahti producer" premise across the entire May-2026 design pass — `product-boundaries.md` §1.3/§1.5, `ahti-record-mapping.md` (wholesale), `runtime-evidence-model.md` (all "Ahti binding" rows), `probe-definitions.md` (definitions/KB-in-Ahti), `local-agent-state.md` §2/§3/§9. See §6.
- **Still binding:** ADR-0001 §D1 (single `EvidenceSink` seam), §D3 (typed `KernelEvent` layer), §D5 (observed vs. ingested time), §D6 (complete producer/probe/kernel metadata); `product-boundaries.md` §2.1 (no datastore), §2.4 (no enforcement), §2.8 (no silent loss), and the Actor-attribution prohibition in §2.3.
- **Driver:** Reconcile Jälki's design with (a) the *actual* False Systems topology — Vartio is the interpreter and the gatekeeper to Ahti for runtime evidence — and (b) Jälki's real identity as a programmable framework, not only a sensor.

This ADR changes *design*, not *code*. PRs that follow implement it.

---

## 1. Context

The May-2026 pass and ADR-0001 assumed two things that are now known to be wrong:

1. **Jälki writes evidence directly to Ahti.** In reality, **Vartio** (the interpreter) ingests evidence by push, parses each producer's *native* runtime shape, reconstructs `ObservedEvent`s → operational chains → decisions, and writes *those product records* to Ahti. Vartio does **not** read raw producer evidence back from Ahti. So a jälki agent writing raw kernel occurrences straight to Ahti would bypass the interpreter entirely — the opposite of the design's intent.

2. **Jälki's product surface should be demoted** (the pass proposed downgrading `ask` to a Lähde shim and moving the knowledge base out of the binary into Ahti `definition` records). But Jälki is a programmable eBPF framework with real users — humans and agents asking the kernel questions through `ask`/MCP/SDK. Throwing that away to become a mute sensor discards the product.

(Ahti has since matured into a full store-and-query system — all eight record kinds persisted, SQL/Flight read path. That is now **irrelevant to Jälki**, because Jälki no longer writes to Ahti.)

The owner has directed the topology, as a **MUST**:

```
jälki → Polku (transport) → Vartio (interpret) → Ahti (store)
```

The design sentence is updated from ADR-0001's:

> *Jälki observes the kernel and interprets what it sees. Polku routes the evidence. Ahti stores it. Lähde and Vartio reason across producers. Syvä enforces later.*

to:

> *Jälki observes the kernel and answers questions about it. Polku transports its evidence to Vartio. Vartio interprets it and writes to Ahti. Lähde and Vartio reason across producers. Syvä enforces later.*

---

## 2. Decision

### D1 — Evidence flows `jälki → Polku → Vartio → Ahti`. Jälki never writes to Ahti.

Jälki **MUST NOT** authenticate to, or write any record to, Ahti. The durable write to Ahti is performed by **Vartio**, which interprets Jälki's evidence (normalize → chains → decisions) and appends the resulting product records. This reverses ADR-0001 §D2: there is **no `AhtiSink`** and **no `PolkuSink → Ahti`**. Polku transports evidence to **Vartio**, not to Ahti.

### D2 — Jälki emits through the existing `EvidenceSink` seam; a Polku sink targets Vartio's ingress

ADR-0001 §D1 (one `EvidenceSink` abstraction) **holds**. The new durable path is a sink implementation that ships `EvidenceBatch`es over **Polku** to Vartio's source ingress (Vartio's `SourceAdapter` contract for high-rate/streaming sources). Implementation reuses Polku's library pattern (`polku-core` / `polku-fp`), with the egress targeting Vartio's ingress rather than Ahti. Jälki needs **no Ahti credentials and no `producer_id`-to-Ahti binding**. `stdout`/`file`/`composite` sinks remain as dev/direct surfaces (Plane A, below).

### D3 — Jälki keeps its full product surface: two planes off one capture engine

- **Plane A — direct / interpreted.** `ask`/`watch`/`stream`/`list`, the MCP server, the Python SDK, the embedded knowledge base, and interpretation. For humans and agents debugging *now*. **Kept** — this reverses the "demote `ask` / move the KB to Ahti" plan.
- **Plane B — neutral pipeline.** capture → normalize → `EvidenceSink` → Polku → Vartio. Neutral evidence for the causality layer.

Both planes run off the same capture engine and in-memory `EventStore`; the `EvidenceSink` seam is the boundary between them.

### D4 — Interpretation is firewalled to Plane A; Plane B evidence is neutral

ADR-0001's reversal ("Jälki **MAY** interpret") still holds — **but interpretation lives on Plane A only** (the KB-driven `ask`/MCP surface). ADR-0001 §D4's *mechanism* — emitting interpretation as `jalki.diagnosis.*` `occurrence` records written to Ahti — is **superseded**, because Jälki writes nothing to Ahti. Interpretation is a local/direct-plane product, not a durable record.

Evidence shipped to Vartio on Plane B **MUST** be neutral: no product severity, no root-cause / `why_it_matters` enrichment. The `OccurrenceError` enrichment currently baked into `jalki-evidence`'s `normalize.rs` **MUST** be stripped from (or gated off) the Plane-B projection. Vartio interprets; Jälki must not pre-empt it.

### D5 — Node-local `cgroup → container → pod` enrichment is mandatory for Plane B

Vartio's runtime importer requires a **strong runtime binding** (`pod.uid` or `container.id`) and **drops** unbound evidence (`{:error, :unbound_runtime_evidence}`). Therefore Jälki **MUST** enrich each kernel event with `cgroup_id → container_id → pod_uid → namespace` *before* emitting on Plane B. This promotes the enrichment described in `local-agent-state.md` §6 from optional polish to a **hard dependency** — and it is the single largest piece of new Jälki work, larger than the sink itself. The `evidence_level` provenance rule survives (`observed` if the lookup is deterministic, `derived` if it came from a possibly-stale cache).

Jälki **MUST** emit correlation keys in Vartio's vocabulary: `k8s_pod_uid`, `k8s_container_id`, `k8s_namespace`, and optionally `github_run_id`; plus a resource reference per event (for TCP, `network_endpoint` = `dst_ip:dst_port`).

### D6 — The Vartio-side importer is the cross-repo contract

A new `VartioCore.Importer.Jalki` (mirroring `VartioCore.Importer.Tetragon`) normalizes Jälki's native evidence shape into `ObservedEvent` — pure, evidence-only, registered in Vartio's static `ImporterRegistry`. It lives in the **Vartio** repo, not Jälki. Jälki's emitted evidence *shape* is the contract between the two repos. Recommendation: a **new** importer (occurrence types `kernel.tcp.connect` etc.), not an extension of the process-exec-only Tetragon importer.

### D7 — No silent loss (ADR-0001 / boundaries hold, destination changed)

`jalki.agent.gap` occurrences and the retry/backpressure model (`local-agent-state.md` §5) survive — but a gap is now expressed toward **Vartio** (Plane B), not Ahti. "No silent loss" is unchanged; only the destination moves.

---

## 3. Consequences

**Positive**
- Aligns with the grain of both codebases: Jälki's `EvidenceSink` seam was built for exactly this; Vartio already ingests by push and already writes Ahti.
- **No fork** — one eBPF/codegen/ABI codebase; the new work is one sink + node-local enrichment.
- Jälki keeps its product (the framework, `ask`, MCP, SDK) *and* becomes a pipeline citizen.
- Vartio is the single, consistent writer of interpreted records to Ahti.

**Negative / costs**
- Reverses a design the team signed off twice (May pass + ADR-0001). The `docs/jalki/` corpus must be reconciled — this ADR plus stale-banners (this PR), with deep rewrites to follow.
- Interpretation must be carefully firewalled off Plane B, or Jälki violates Vartio's "producer ships neutral evidence" contract.
- The mandatory enrichment (D5) is real work, and the cross-repo evidence-shape contract (D6) must be coordinated with the Vartio repo.
- **Build blocker, unrelated but surfaced (now resolved):** `jalki-evidence`/`jalki` depended on `../ahti/false-protocol`, which the Ahti repo deleted in its v1 cleanup. *Resolved 2026-06-22:* recovered from `ahti@7bd55c8^` and vendored in-repo at `false-protocol/` (Polku's `false-protocol` is an incompatible shape, so a repoint was not viable). `jalki-evidence` now compiles.

---

## 4. What this does NOT change

- The fentry/fexit framework, the `Probe` trait, the eBPF crates, and `jalki-codegen`.
- ADR-0001 §D1 (`EvidenceSink` seam), §D3 (typed `KernelEvent`), §D5 (time), §D6 (metadata).
- No Jälki datastore; no enforcement; no Actor attribution; no silent loss.

---

## 5. Alternatives considered

- **Jälki → Ahti directly** (ADR-0001 §D2 / the May pass). Rejected: bypasses Vartio the interpreter; Vartio does not read raw evidence from Ahti.
- **Jälki → Ahti, then Vartio polls Ahti** (the "Ahti-mediated" idea, viable now that Ahti is queryable). Rejected by the owner: Vartio must interpret *before* storage, and no Ahti-reader exists in Vartio.
- **Fork Jälki into a lean producer.** Rejected: nothing to insulate it from once it speaks only to Polku; a fork means maintaining unsafe eBPF code twice.
- **Demote Jälki's product surface** (move KB to Ahti, `ask` → Lähde). Rejected: discards the framework's value; the two planes coexist cleanly off one engine.

---

## 6. Exactly what this supersedes

| Prior clause | Prior position (paraphrased) | New position |
|---|---|---|
| ADR-0001 §D2 | Evidence leaves via `PolkuSink → Polku → Ahti` or `AhtiSink → Ahti`; Jälki supports both. | **Superseded.** No `AhtiSink`; Polku transports to **Vartio**, not Ahti. Jälki never writes Ahti. |
| ADR-0001 §D4 | Jälki emits interpretations as `jalki.diagnosis.*` `occurrence` records into Ahti; rules as `definition` records via `jalki-control`. | **Superseded mechanism.** Jälki MAY interpret, but only on Plane A (local `ask`/MCP); it writes nothing to Ahti. The KB stays embedded, not in Ahti. |
| `product-boundaries.md` §1.3 | "Emit Ahti records… agent authenticates to Ahti… `producer_id`." | **Superseded.** Jälki emits to Polku→Vartio; no Ahti auth/producer binding. |
| `product-boundaries.md` §1.5 | Question surface plans probes or reads Ahti directly. | **Superseded.** `ask` is a kept Plane-A product; it does not read Ahti. |
| `ahti-record-mapping.md` | Whole document: how Jälki writes the 8 Ahti record kinds. | **Superseded for Jälki.** Jälki writes none of them. Retained for historical context / as a reference for the *Vartio*-side write mapping. |
| `runtime-evidence-model.md` | "Ahti binding" per evidence type; entity_version/relationship_claim Jälki writes. | **Payload shapes survive** as the evidence Jälki emits to Vartio. The "Ahti binding" rows and Jälki-writes-entities/relationships are superseded (Vartio derives those). |
| `probe-definitions.md` | Definitions/templates/KB live in Ahti, written by `jalki-control`. | **Superseded.** Probe intelligence and the KB stay **local** to Jälki (Plane A). No `jalki-control`-to-Ahti writes. |
| `local-agent-state.md` §2/§3/§9 | What "must reach Ahti"; producer auth to Ahti; profile as Ahti `entity_version`. | **Superseded for the Ahti destination.** The enrichment (§6), gap/retry (§5), and time (§4) content survives and §D5 makes enrichment mandatory. |

All other MUST/MUST NOT clauses in `product-boundaries.md` remain in force. Future drift past them needs its own ADR.
