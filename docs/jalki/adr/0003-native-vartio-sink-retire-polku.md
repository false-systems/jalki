# ADR-0003 — Jälki speaks Vartio's source-ingress directly; Polku leaves the deployed topology

- **Status:** Proposed (Dima, 2026-07-02 — for Yair's review)
- **Date:** 2026-07-02
- **Supersedes:** ADR-0002 §D1 (the *routing* clause only — "through Polku") and §D2
  (the "Polku sink targets Vartio's ingress" mechanism). See §6.
- **Still binding:** ADR-0002 §D1's core prohibition (**Jälki never writes to Ahti**;
  Vartio performs every Ahti write), §D3 (two planes), §D4 (Plane-B evidence is
  neutral), §D5 (node-local binding enrichment is mandatory; Vartio drops unbound),
  §D6 (the Vartio importer is the cross-repo contract), §D7 (no silent loss);
  ADR-0001 §D1 (single `EvidenceSink` seam), §D3, §D5, §D6; all of
  `product-boundaries.md` §2 not previously superseded.
- **Driver:** ADR-0002 mandated `jälki → Polku → Vartio → Ahti` when Polku was the
  only planned transport. Since then: Ahti gained `Subscribe` (ahti ADR-0004 —
  "tailing, not a broker"), Vartio writes evidence to per-adapter Ahti namespaces and
  tails them back (vartio #104→#117, live-verified), and the audit of Polku's real
  footprint found **no deployment anywhere** (the cluster's `gateway` namespace is an
  nginx placeholder; the sole polku-derived artifact is the Tetragon adapter feeding
  consumer-less occurrences — verified 5.25M on 2026-07-02, growing ~700k/day, none
  self-expiring (see the retirement-plan doc, polku #159)). A hub with one producer and one consumer is
  machinery without a mission.

## 1. Context

ADR-0002 chose Polku for "routing, fan-out, and delivery policy that does not belong
inside the datastore and should not be hard-wired into the agent." Three facts changed:

1. **The delivery-policy home moved server-side.** Vartio's source-ingress contract
   (vartio #88 `SourceAdapter` + #94 `source_ingress.proto`) already owns trust,
   idempotency, per-item accept/duplicate/reject, and batch semantics. Every other
   Vartio source (GitHub, CloudTrail, GCP, Kubernetes) is a direct client of that
   contract — none route through a hub.
2. **The client-side machinery already exists in Jälki.** `jalki-evidence` has the
   `EvidenceSink` seam with retry and checkpoints, and its `AppendResult`
   (`accepted_count` / `rejected_count` / `watermark`) mirrors `ReceiveBatchResponse`
   almost field-for-field. The remaining gap is one gRPC client.
3. **That client is already written and tested** — polku #159's `VartioEmitter`
   (batch assembly, all-or-retry, source-scoped idempotency, an in-crate generated
   `SourceIngress` test receiver, 10 tests) — reviewed 2026-06-23; it ports into a
   `VartioSink` nearly mechanically.

## 2. Decision

### D1 — Topology: `jälki → Vartio source-ingress → Ahti`; no intermediary

Jälki's Plane-B evidence is delivered by a native **`VartioSink`** (an `EvidenceSink`
implementation) speaking `vartio.source_ingress.v1.SourceIngress/ReceiveBatch` over
gRPC. The proto is **vendored from Vartio** (per the per-repo + vendored proto
ownership decision, polku #158 Q2). No Polku hop; no other broker. Vartio remains the
sole Ahti writer; Vartio's own `Subscribe` tail loop is unaffected by this ADR.

### D2 — The sink is ported from polku #159, review fixes included

The `VartioSink` implementation salvages polku #159's `vartio.rs`, carrying its
semantics and its review corrections:

- **all-or-retry:** any transport failure or batch-level `retryable` ⇒ the whole batch
  retries; accepted/duplicate items replay safely (duplicate = idempotent no-op).
- **source-scoped idempotency:** `source_key:cluster_id:node_id:<event identity>`;
  startup **fails fast** if cluster/node identity is empty (never `jalki:::…` keys).
- **strong-binding filter at the source:** events without `pod_uid` or `container_id`
  are dropped before emit (ADR-0002 §D5 already mandates the enrichment; this drops
  what enrichment couldn't bind, saving the round-trip Vartio would refuse).
- **argv discipline:** Jälki already emits `argv_hash`, never raw argv; the #159 test
  invariant ("the secret never appears in an emitted batch") is carried over as a
  fixture test.
- The #159 generated test receiver ports as the sink's test harness — and doubles as
  the reference client for testing Vartio's `ReceiveBatch` server.

### D3 — v0 delivery is bounded-and-lossy after the retry cap, and loss is never silent

If Vartio is unreachable beyond the bounded retry budget, the batch is dropped and the
loss is **observable** (drop counter + structured event carrying batch size and reason)
— honoring ADR-0002 §D7's "no silent loss" as *no-silent* loss, not no-loss. A durable
node-local spool (upgrade to at-least-once across Vartio outages) is explicitly a
**future ADR**, not scope here.

### D4 — Polku leaves the deployed topology (it does not retire)

With D1–D3, nothing in the deployed stack routes through Polku. Sequencing (owned in
polku #159's `docs/polku-retirement-plan.md`): Vartio `ReceiveBatch` endpoint ships →
`VartioSink` lands here → jalki DaemonSet proves parity with the deployed Tetragon
adapter → the Tetragon adapter and Tetragon retire and the orphan occurrences are
**explicitly purged** (they never expire on their own: every row carries
`expires_at = null`, and Ahti's retention sweep checks only `expires_at` —
`retention_class: short` is a no-op today; the derivation gap is filed against Ahti).
Until parity, the Tetragon adapter keeps running unchanged.

**Polku stays a normal repository — out of the stack, not archived.** Its in-process
shaping layer (batch / dedup / throttle / sample) and `polku-ahti-emitter` are tested
assets earmarked for the first high-volume direct-append adapter (OTel, CloudTrail at
scale); that is where Polku re-enters, in-process. The line that decides when: **source
volume, not receiver language** — BEAM handles message rate fine, and the pipeline's
realistic ceiling is Ahti appends and network. Edge shaping exists so hundreds of
thousands of events/sec are never shipped across the wire just to be dropped or
deduped on the other side; and edge dedup is the *only* dedup the direct-append lane
has (Ahti does not dedup occurrences — unlike this ADR's `ReceiveBatch` lane, where
duplicate handling is server-side per-item).

## 3. Consequences

- Jälki gains one gRPC client crate-worth of code (mostly ported) and loses a planned
  external dependency (Polku deployment, its config surface, and its failure modes).
- Vartio's ingress becomes the **single** plug-in point for all sources — the
  "unified place" from the original hub idea, relocated server-side where the
  contract is enforced.
- Future producers (e.g. syva's `would_deny` stream) implement the same small client
  against the same contract; if a third producer makes client duplication painful,
  extracting a shared `source-ingress-client` crate is a refactor, not an ADR.
- The transport loses Polku's tiered buffering/circuit-breaker stack; D3 names the
  accepted v0 posture and the upgrade path.

## 4. What this does NOT change

- Jälki never writes to Ahti; never interprets on Plane B; never enforces.
- The #158 contract semantics (batch shape, idempotency, redaction, per-item results)
  — only the client's address changes.
- Plane A (ask/MCP/SDK product surface) is untouched.

## 5. Alternatives considered

- **Keep Polku as mandated (status quo ADR-0002):** deploy + operate a hub whose only
  route is jälki→Vartio. Rejected: pure operational surface with no second producer or
  consumer in sight; the hub's hard parts are already server-side in Vartio's contract.
- **Jälki writes to Ahti, Vartio subscribes to raw evidence:** rejected — re-opens the
  interpreter bypass ADR-0002 §D1 exists to prevent, and puts producer trust/dedup
  into Ahti, crossing ahti ADR-0004's boundary ("Subscribe is tailing, not a broker").
- **Extract a shared client crate now:** premature with one producer; revisit at the
  second (§3).

## 6. Exactly what this supersedes

| Clause | Status after this ADR |
|---|---|
| ADR-0002 §D1 routing (`→ Polku →`) | **Superseded**: direct to Vartio ingress |
| ADR-0002 §D1 "Jälki never writes to Ahti" | **Unchanged, binding** |
| ADR-0002 §D2 (Polku sink mechanism) | **Superseded** by D2 here (`VartioSink`) |
| ADR-0002 §D3–§D7 | **Unchanged, binding** |
| ADR-0002 §1's owner-directed MUST topology | **Amended** by this ADR upon acceptance |
