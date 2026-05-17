# Product Boundaries

This document specifies what Jälki **does** and what Jälki **must not do**. Every other Jälki design document is constrained by this one.

When in doubt, the rule is:

> Jälki observes runtime evidence. It does not interpret meaning, attribute Actors, decide incidents, or enforce policy.

## 1. What Jälki does

### 1.1 Collect kernel and runtime evidence

Jälki **MUST** be able to collect, on each node it runs on:

- Process exec / fork / exit
- File open / read / write of sensitive paths (declared per agent profile, not per kernel hook)
- Network connect (TCP, optionally UDP)
- Network listen / accept
- TCP retransmit
- DNS lookups (when in scope; see `runtime-evidence-model.md`)
- Block I/O issued / completed
- Scheduler latency / runqueue delay
- cgroup / container / pod mapping for any of the above

Jälki **MAY** extend this list. New evidence types **MUST** be registered as Ahti `definition` records (see `probe-definitions.md`); ad-hoc payload shapes are not permitted.

### 1.2 Normalize evidence

Jälki **MUST** normalize raw kernel data into validated Ahti payloads:

- Endianness, alignment, and pointer reads are handled in the eBPF / agent layer.
- Container / pod / namespace / service account enrichment happens before the record is written to Ahti.
- Time is normalized to the agent's best-known wall clock with skew metadata (see `local-agent-state.md` §time).
- Fields with unresolvable values **MUST** be omitted, not zero-padded. A missing `container_id` is more honest than `container_id = ""`.

### 1.3 Emit Ahti records

Jälki **MUST** be the producer of every record it writes. The Ahti producer-binding rule applies:

- The agent authenticates to Ahti (mechanism is deployment configuration).
- Ahti **MUST** stamp `producer_id` from the bound principal; the agent **MUST NOT** assume its payload-level `producer_id` will be honored.
- A `jalki` namespace producer **MUST NOT** write to the `ahti` namespace. Writes to other product namespaces (e.g. `vartio`, `lahde`) are not permitted.

The full producer model is in [`local-agent-state.md`](./local-agent-state.md) §producer.

### 1.4 Maintain operational local state

Jälki agents **MAY** keep short-lived local state for operational reasons:

- BPF maps and ring buffers
- Container / pod metadata caches
- Retry / backpressure buffers
- BTF / kernel capability snapshots until they can be flushed as `reference` records
- Generated artifacts pending upload

All such state **MUST** have a declared bound and a declared eviction policy. See [`local-agent-state.md`](./local-agent-state.md).

### 1.5 Provide runtime question machinery

Jälki **MAY** expose a question-answering surface ("which process opened this file?") **as a thin operational tool** that does one of two things:

1. Plans probes from a Jälki-owned `definition` record (`probe_plan_template`), deploys them, and forwards the resulting Ahti record IDs to the caller.
2. Reads Ahti directly via Ahti's query API.

Jälki's question-answering surface **MUST NOT** invent answers from its own datastore. There is no Jälki datastore.

## 2. What Jälki must not do

### 2.1 No durable datastore

Jälki **MUST NOT** maintain a long-term datastore parallel to Ahti.

- Durable evidence: in Ahti.
- Definitions, references, artifact handles: in Ahti.
- Operational local state (ring buffers, caches, retry buffers): on the agent, with declared bounds.

If the answer to "where does this live for a week?" is anywhere other than Ahti, the design is wrong.

### 2.2 No product interpretation

Jälki **MUST NOT** decide:

- Root cause ("network is the problem" — Lähde decides).
- Severity in the product sense ("warning" vs "critical" — Lähde decides). Jälki **MAY** carry an `evidence_level` (e.g. `observed`) per Ahti's protocol, but it **MUST NOT** stamp severity as a product judgment.
- Incident formation ("these three events are one incident" — Lähde / Vartio decide).
- Whether a behavior is suspicious ("this file open is a token theft" — Vartio / Lähde decide).

The Jälki TCP retransmit record states the retransmit happened. It does not say "this is a network problem."

### 2.3 No Actor attribution

Jälki **MUST NOT** assert:

- That a process belongs to a deployment, release, or workload Actor envelope.
- That a network connection is part of a service-to-service call chain.
- That a pod is owned by a human or non-human Actor.

Jälki **MAY** assert mechanical mappings: `process belongs_to cgroup`, `cgroup belongs_to container`, `container belongs_to pod`, `pod ran_on node`. Vartio composes those mechanical facts into operational chains. That composition is not Jälki's job.

### 2.4 No enforcement

Jälki **MUST NOT** block, deny, kill, throttle, or rate-limit anything. The agent is observe-only. Even if Jälki's eBPF programs could attach to enforcement hooks (LSM, seccomp, cgroup_skb), the v0 design forbids it.

Syvä will own enforcement when it exists. Jälki may later provide evidence that informs Syvä decisions, but Jälki itself remains observe-only.

### 2.5 No incident or chain concepts

Jälki **MUST NOT** define:

- `incident` records.
- `chain` records.
- `attribution` records.
- Any record kind that asserts a high-level operational narrative.

Those are product semantics. They belong to Vartio and Lähde.

### 2.6 No reuse of `ahti` namespace

Jälki **MUST NOT** write to the reserved `ahti` namespace. Ahti rejects such writes at the protocol layer (`auth-producers.md` §5.3); the rule is stated here so Jälki authors do not attempt it through configuration.

### 2.7 No invented record kinds

Jälki **MUST NOT** invent record kinds outside Ahti's eight (`occurrence`, `entity_version`, `relationship_claim`, `definition`, `reference`, `annotation`, `artifact_ref`, `extension_record`). When a Jälki concept does not obviously fit, the choice is between:

1. Use the closest core kind (preferred).
2. Use `extension_record` with a non-empty `why_extension` justification (acceptable when no core kind fits).

Inventing a new top-level kind is **not** an option for Jälki.

### 2.8 No silent data loss

If the agent cannot reach Ahti, it **MUST NOT**:

- Drop records silently when the retry buffer overflows.
- Emit records that pretend the agent was online during a gap.
- Backfill `event_time` to fit an idealized timeline.

Loss **MUST** be either represented as an explicit gap occurrence (see `runtime-evidence-model.md`) or declared in the agent's policy as a deliberate sampling regime.

## 3. Forbidden patterns restated (from Ahti `record-kinds.md` §9)

These are protocol-level forbidden patterns that Jälki **MUST** honor:

- **Untyped refs.** A bare string ID anywhere a ref is expected is rejected. Every ref must carry `{kind: record_id | logical_key | external_uri, …}`.
- **Cross-producer `logical_key` exploitation.** A Jälki `logical_key = "node-1"` is not the same identity as another producer's `logical_key = "node-1"`. They are distinct.
- **Mismatched `producer_id`.** Jälki **MUST NOT** stamp a `producer_id` in payload that differs from its authenticated identity.
- **`evidence_level` as priority.** Consumers must not rank by it. Jälki **MUST NOT** abuse `evidence_level` to signal severity or confidence.
- **Mutating records after commit.** No affordance exists. State changes are new records; deletion is redaction by an authorized actor.

## 4. Concrete responsibility table

| Concern | Owned by | Jälki's role |
|---|---|---|
| Kernel/runtime event collection | Jälki | Source of truth |
| Container / pod metadata enrichment | Jälki | Performs enrichment before write |
| Probe lifecycle on the agent | Jälki | Attaches, detaches, samples |
| Durable storage | Ahti | Producer; never owns storage |
| Schema definition for Jälki types | Jälki | Writes `definition` records into the `jalki` namespace |
| Schema validation | Ahti | At write time |
| Producer authentication | Ahti + deployment | Jälki agents authenticate; mechanism is deployment config |
| Root cause analysis | Lähde | Consumes Jälki records via Ahti |
| Actor attribution / chains | Vartio | Consumes Jälki records via Ahti |
| Policy enforcement | Syvä (future) | Jälki **MUST NOT** enforce |
| Dashboards / alerts | Lähde and friends | Jälki does not render |
| Incident records | Vartio / Lähde | Jälki does not author |

## 5. What "evidence" means in this design

A piece of evidence is a record that:

- Is grounded in a mechanical observation (a kernel hook fired, a syscall returned, a metadata enrichment succeeded).
- Has a producer-bound identity (Jälki agent X on node Y).
- Has explicit time (when the kernel observed it, when the agent received it, optionally when it was ingested).
- Has no product judgment in its payload.
- Validates against a Jälki-owned schema in the `jalki` namespace.

A piece of evidence is not:

- A judgment about what the evidence means.
- A claim about which Actor caused it.
- A claim about which incident it belongs to.

A Lähde derivation that cites Jälki evidence in `evidence_refs` is the right shape. A Jälki record that says "this caused the outage" is wrong.

## 6. Where this boundary may evolve

This boundary is intentionally strict for v0. A future revision **MAY** loosen specific items if a real product need emerges; until then, follow the strict version.

Candidates for later revisitation (call out explicitly when proposing):

- Whether Jälki agents may serve a read-only query API for *local* short-window evidence as an operational convenience (without becoming a datastore).
- Whether Jälki agents may emit pre-aggregated counts as `occurrence` records (e.g. "1,432 retransmits in the last second on this node") in addition to per-event records.
- Whether Jälki may carry minimal entity_version updates for fast-moving runtime entities (process tables), or whether those belong to a different producer.

Any proposal to loosen a "**MUST NOT**" in §2 requires explicit sign-off and an ADR in this directory.
