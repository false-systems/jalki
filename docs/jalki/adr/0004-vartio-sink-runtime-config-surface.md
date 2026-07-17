# ADR-0004 — VartioSink runtime config surface: authentication + payload shape

- **Status:** Proposed (Dima, 2026-07-17 — **decisions needed from Yair**)
- **Date:** 2026-07-17
- **Follows:** ADR-0003 (the native `VartioSink`). ADR-0003 sized the sink as "the gRPC
  client + wiring" and left the runtime **config surface** — how the sink authenticates
  and exactly what shape rides the wire — as an explicit follow-up. This ADR resolves
  that surface.
- **Still binding:** ADR-0002 §D4 (Plane-B evidence is neutral — no interpretation),
  §D5 (node-local binding is mandatory; unbound drops at the source), §D6 (the Vartio
  importer is the cross-repo contract), §D7 (no silent loss); ADR-0003 D1–D3.
- **Driver:** jalki #22 merged the `jalki-vartio-sink` crate. The **first live
  integration** — driving the real sink against a real Vartio source-ingress endpoint,
  not the in-crate mock — surfaced two gaps that block the lane end-to-end. Both are
  config-surface calls; neither is answered yet. The two halves (this sink, and the
  receiver) were each built to the proto and had **never been run against each other**.

## 1. Context

The wire contract (proto, per-item accept/duplicate/reject, source-scoped idempotency,
all-or-retry) holds. The gaps are in the surface *around* it — the credential the sink
presents, and the concrete field shape of each item's payload. Both were invisible
until a live run because the in-crate mock receiver neither authenticates nor validates
payload structure.

## 2. Decision 1 — authentication on the wire

**Finding (live):** the sink presents **no credential**; the receiver's source-ingress
**mandates a bearer token** (fail-closed — no token configured means no listener at
all). Every batch therefore returns a terminal `SinkError::Unauthorized`. The sink
cannot deliver a single batch as shipped.

**Options**

- **(D1-a) env var read at daemon boot** — the DaemonSet supplies the token from a
  Kubernetes Secret via the pod env; `--sink vartio` reads it. Downward-API / secret
  friendly, no secret on the command line.
- (D1-b) a dedicated CLI flag — puts the token in argv / process listing.
- (D1-c) mTLS — the production posture ADR-0003 already names; a deployment-layer
  concern (server TLS creds + client-cert verification) that layers on without changing
  this contract.

**Recommendation:** **D1-a**. The token rides the pod env from a Secret, mirroring how
the receiver side is configured; mTLS remains the hardening path and does not block v0.

## 3. Decision 2 — payload shape (what rides the wire)

**Finding (live):** with a token attached, the receiver authenticates the call and then
**rejects the item on structural validation**. The sink emits the neutral **Plane-B
FALSE Occurrence** (ADR-0002 §D4/§D5) with the runtime **binding carried in the
occurrence's `labels`**. The receiver's importer expects the binding — and the runtime
fields — as **native, top-level** map fields, so it reads the record as *unbound* and
rejects it. This is a genuine disagreement about the wire shape — a neutral FALSE
Occurrence vs. a native runtime map — **not a field rename**.

**Options**

- **(D2-a) the sink projects to the receiver's native runtime map** before sending
  (binding + runtime fields at top level).
- (D2-b) the receiver's importer learns to read the neutral FALSE Occurrence (pull
  binding from `labels`).
- (D2-c) a shared, versioned wire schema both sides target explicitly.

**Recommendation:** **D2-a**. The importer is the cross-repo contract (§D6) and its
stated shape is native event data + binding, not a FALSE/Ahti Occurrence wrapper — so
converting on the sink keeps the receiver untouched. Plane-B neutrality (§D4) is
preserved: we reshape **fields**, we do not add interpretation; unbound records still
drop at the source (§D5).

**Tension to confirm explicitly:** §D4 currently frames Plane-B as "the neutral
*occurrence*." Under D2-a the wire is the native map, so §D4 narrows to "neutral
*content*, native *shape*." Please confirm that narrowing, or pick D2-b/D2-c instead.

## 4. Consequence — runtime wiring (mechanical, follows the decisions)

Once D1/D2 land, the implementation PR is plumbing, not a decision: register
`jalki-vartio-sink` in the daemon, add `--sink vartio` (+ endpoint, adapter-id) to the
sink selector, and pass producer cluster/node identity via downward-API env (the sink
already fail-fasts on empty identity). Today the daemon offers only `stdout` / `file` —
`--sink vartio` does not yet exist.

## 5. Evidence / reproduction

An env-gated live test (`jalki-vartio-sink/tests/vartio_live.rs`, skipped in CI) drives
both cases against a real receiver: the stock sink → `Unauthorized`; a token-carrying
client → the item's real accept/reject verdict. It is the wire-level regression test
this lane has been missing and folds into the implementation PR.

## 6. Requested

Please **review + answer D1 and D2** — approve the recommendations or amend — and
confirm the §D4 narrowing implied by D2-a. With those settled, the runtime wiring +
sink changes land as one implementation PR against this ADR.
