# ADR 0006 — Adopt vartio ADR-0009 cross-service flow contracts

**Status:** accepted, 2026-07-31. `false-systems/vartio#245` merged at
14:51Z, and the merged text is byte-identical to the draft this was written
against (`eafcb68`) — checked rather than assumed, because this document said
to re-check if it was reworded before landing.

The conformance record below was written before acceptance and is independent
of it: it describes what jälki already does, from the implementations rather
than from the intent.

**Context:** vartio ADR-0009 defines six flow contracts for the
jälki → Vartio → Ahti pipeline, drawn from the 2026-07-28/29 tri-service
incident. Five bind jälki. This records how each is satisfied, and — more
usefully — where jälki still falls short of one.

## Why this document is a record and not a promise

Every contract below was implemented *before* this was written, in response to
a specific failure rather than to the contract text. Saying "jälki conforms"
without naming the mechanism and its limits would be the kind of claim
ADR-0009 contract 6 exists to prevent.

## Conformance

### Contract 1 — two retriable signals with distinct meanings

`UNAVAILABLE` (retry later) and `RESOURCE_EXHAUSTED` (slow down) are separated
at both ends of the sink.

Receiving: `classify_status` maps `ResourceExhausted` to
`SinkError::Backpressure` and other transport failures to
`SinkError::Unavailable`. They are then handled *differently*, which is the
part that matters — backpressure halves the drain rate through
`DrainPacer::on_backpressure` (#40), while unavailability only reschedules.
Before that, both merely meant "try again", so a sink's only way to shed load
was to keep refusing while jälki kept asking at the same rate.

Sending: jälki is not a gRPC server on this lane, so it has no send-side
obligation here.

### Contract 2 — a dependency outage is a value, not a crash

`VartioSink::connect` is lazy (#38). A Vartio that is down at startup is
buffered against, not a reason to exit. Previously one eager dial failed and
`main` propagated it to a non-zero exit, so any restart during an outage —
OOM, drain, rollout — became a crash loop with kubelet backoff as the only
retry, while an outage *mid-run* was already handled gracefully. That
asymmetry was the bug.

Only misconfiguration still fails fast, and structurally rather than by
convention: with the eager dial gone, `Misconfigured` is the sole error
`connect` can return.

### Contract 3 — deadline hierarchy validated at boot

**Not satisfied.** jälki has no boot-time validation of its deadlines against
its peers', and cannot have one alone: the values it would validate against
live in Vartio's configuration. Its own numbers are declared
(`JALKI_RETRY_BACKOFF_{BASE_MS,MAX_MS}`, `JALKI_DRAIN_MAX_*`,
`JALKI_READY_MAX_BACKLOG_AGE_SECS`) and logged at startup, which is the
prerequisite — Appendix A's Jälki→Vartio row is a 10s/10s tie between two
values that are at least now written down rather than being library defaults.
The joint assertion belongs to the chaos suite (vartio#255).

### Contract 4 — drain pacing

`DrainPacer` (#40): two token buckets, bytes and batches, scaled by an AIMD
factor. Defaults of 2MiB/s and 20 batches/s drain a full 64Mi buffer in ~32s.
This bounds *recovery*, not traffic — the inline delivery path is unpaced, so
ordinary operation is untouched.

The failure it addresses is specific: on 2026-07-28 Vartio returned at 21:34,
jälki handed over its backlog at line rate, and Ahti went from 0.24Gi to its
4Gi OOM limit inside 90 minutes. The outage was survivable; the recovery was
not.

Recovery from backpressure is per delivered batch and deliberately slow
(0.002). An earlier 0.02 climbed back to full rate in about two seconds on a
busy drain, which made the signal decorative.

### Contract 5 — shed order, encoded structurally

`EvidenceClass` (#41): reliability evidence (`kernel.tcp.close`,
`kernel.tcp.retransmit`) sheds before attribution evidence (exec, connect,
file opens). Batches are split by class on the way into the buffer, because a
mixed batch can only be shed as a unit — classify one by its strongest member
and nearly everything becomes attribution, leaving the order inert.

Delivery order is untouched and remains strictly FIFO; only the *shed* choice
is class-aware. Reordering delivery would make a drain unreconstructible
downstream.

**Known divergence risk.** This mapping is a second copy of Vartio's
`@attribution_types` / `@reliability_types`. The producer must own it —
contract 5 says so, and the shed happens here long before anything reaches
Vartio — but if Vartio promotes a type and jälki is not updated, jälki will
quietly shed evidence Vartio treats as attribution-critical, with "a chain
that never forms" as the only symptom. A test pins both lists; the
coordination rule is Vartio first, then here. Unclassified types default to
attribution so a new probe is kept rather than silently shed.

### Contract 6 — honesty on loss

Every shed emits a `jalki.agent.gap` occurrence carrying cause, per-class
counts, and the covered time range. Causes are distinguished rather than
collapsed: `retry_buffer_overflow`, `retry_buffer_expired`, and
`memory_pressure` are different operational stories.

Three losses that used to be silent now are not:

- **Shutdown with an undeliverable backlog** logs the batch, record and byte
  counts (#47). It was previously indistinguishable from a clean drain.
- **Memory pressure** sheds deliberately with gap evidence rather than waiting
  for an OOM kill, which costs the entire backlog *and* reports nothing (#33).
- **A torn spool tail** is reported in bytes on replay rather than swallowed
  (#33).

Related, and beyond jälki's reach: contract 6 as worded covers shed and drop,
not durability loss — see vartio#259.

## Consequences

- Contract 3 remains open on jälki's side and cannot be closed unilaterally.
- Contract 5 carries a standing coordination cost with Vartio's importer.
- If ADR-0009 is renumbered or reworded before merging, this document must be
  re-checked against it rather than assumed still accurate.
