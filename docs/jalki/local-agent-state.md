# Local Agent State

This document specifies what may live on a Jälki agent locally, what **must** reach Ahti, how the agent behaves when Ahti is unreachable, how time is normalized, and how producer identity is bound.

The headline rule (recap):

> Local Jälki state is **operational**. Ahti state is **durable evidence**. If a fact must survive an agent restart, it lives in Ahti.

## 1. What may live locally

Permitted local state (with declared bounds and eviction policy):

| State | Why local | Bound |
|---|---|---|
| BPF ring buffers | Kernel-side queues for events the agent has not yet drained | Per-buffer max bytes (default 4 MB, configurable per probe) |
| BPF maps (HashMap, LRU, percpu arrays) | Per-probe kernel state (e.g. PID_FILTER, in-flight syscall tracking) | Per-map max entries declared at load |
| Metadata enrichment caches | Cgroup → container, container → pod mappings | Bounded LRU; size declared per agent profile |
| Retry buffer | Records that failed to write to Ahti | See §5 |
| In-flight assembly buffers | Multi-fragment events (e.g. argv across pages) | Per-event TTL; expire and emit a `jalki.agent.gap` if unresolved |
| Capability snapshot draft | Built during agent startup before being flushed as an `entity_version` | Discarded once written to Ahti |
| Local debug artifacts pending upload | tar / pcap / verifier logs to be promoted to `artifact_ref` | Per-agent disk quota; oldest-first eviction with a `jalki.agent.lifecycle` note |
| Process-table cache | Per-node view of running PIDs and their entity_version `logical_key`s | Bounded; rebuilt on agent restart |
| Active probe registry | Per-agent record of attached probes and their plan template `record_id`s | Rebuilt from `agent_profile` on restart |
| Last-ingested watermark per probe | Used to size the retry buffer and to reason about gaps | Single value per probe |

Every local store **MUST** have:

- A declared maximum size.
- A declared eviction policy.
- An observable counter / gauge (Prometheus or equivalent) so operators can see when it is filling.
- A defined behavior on eviction (drop with gap event, or block with backpressure).

## 2. What must reach Ahti

Anything in this list **MUST NOT** persist only on the agent:

- All `occurrence` records the agent produces (kernel events, gaps, lifecycle).
- All `entity_version` records (process, cgroup, node, capability snapshot).
- All `relationship_claim` records the agent emits.
- All `reference` records the agent produces (e.g. node-local container handles).
- All `artifact_ref` records (when an artifact is registered, its handle goes to Ahti even if the bytes live in object storage).
- All `definition` records (written by `jalki-control`, not agents).

If a Jälki author finds themselves writing "we'll keep this on the agent for a while", check this list. If it's on the list, the design is wrong.

## 3. Producer identity

### 3.1 Producer IDs in use

| `producer_id` | Who | Writes |
|---|---|---|
| `jalki-control` | The Jälki control plane (a single principal, usually deployed once per cluster or per fleet) | All `definition` records; cluster-wide `reference` records; per-node `agent_profile` `entity_version`s |
| `jalki-agent:<cluster>:<node_id>` | Each Jälki agent | Per-node `occurrence`, `entity_version`, `relationship_claim`, node-local `reference`, `artifact_ref` |
| `jalki-debug-tool` | Optional operator tooling that creates `annotation` records or registers debug artifacts | `annotation`, `artifact_ref` |

### 3.2 Binding rule (recap from Ahti `auth-producers.md`)

- Every agent **MUST** authenticate to Ahti before writing.
- The authenticated principal **MUST** map to exactly one `producer_id`.
- Ahti **MUST** stamp `producer_id` from the bound principal; payload-level `producer_id` mismatching the bound value **MUST** be rejected.
- Credentials rotate; `producer_id` does not. A node renaming does not produce the same `producer_id`.
- `jalki-agent:<cluster>:<node_id>` **MUST NOT** be reused for a different node after decommissioning (Ahti `auth-producers.md` §6.4).

### 3.3 Per-producer permitted schemas (recommended)

Deployment configuration **SHOULD** scope which schemas each producer may write:

| Producer | Permitted `record_kind` | Permitted `occurrence_type` / `entity_type` / `relationship_type` |
|---|---|---|
| `jalki-control` | `definition`, `reference`, `entity_version` (only `agent_profile`) | n/a for occurrences |
| `jalki-agent:*` | `occurrence`, `entity_version`, `relationship_claim`, `reference` (node-local only), `artifact_ref` | The full Jälki vocabulary except `agent_profile` |
| `jalki-debug-tool` | `annotation`, `artifact_ref` | `jalki.attached_artifact` and similar |

Enforcement is deployment-level (Ahti permits scoping at the namespace level by default; finer-grained scoping is a deployment add-on). v0 does not require finer-than-namespace scoping; it documents the recommended split.

### 3.4 Authentication mechanism

The Ahti protocol does not pin a mechanism. Two appropriate choices for Jälki:

- **mTLS** with per-node client certificates issued by an internal CA. Preferred for production. Rotation handled by the Kubernetes deployment (cert-manager or equivalent).
- **OIDC / SPIFFE / projected service account token** for Kubernetes-native deployments. The token's identity claim maps to `jalki-agent:<cluster>:<node>` via a deployment-side mapping table.

The agent **MUST** be configurable for either. The control plane chooses mechanism at deployment.

### 3.5 Bootstrap before Ahti is reachable

When the agent starts:

1. Load its credentials and discover the Ahti endpoint (from agent profile passed at launch).
2. Build a capability snapshot in memory.
3. Attempt to write the capability snapshot as an `entity_version`. If Ahti is unreachable, hold it in the retry buffer (see §5).
4. Begin attaching probes per the agent profile. The agent profile **MUST** be supplied at launch (env / file / control protocol) so the agent can start without a round-trip to Ahti.

The agent **MAY** start attaching probes before the snapshot is acknowledged by Ahti, but every emitted record carries `lineage_refs` to the capability snapshot's local identity (which gets resolved to an Ahti `record_id` when the snapshot lands). Until then, the records remain in the retry buffer.

## 4. Time semantics

### 4.1 Time fields recap

| Field | Source | Used for |
|---|---|---|
| `event_time` (envelope) | Agent wall-clock estimate of when the event happened | Cross-node ordering, queries |
| `kernel_time_ns` (payload) | CLOCK_BOOTTIME nanoseconds from the kernel | Same-node ordering across events |
| `agent_recv_time` (payload) | Agent wall clock at receipt from ring buffer | Detecting agent-internal delay |
| `clock_source` (payload) | Description of how `event_time` was derived | Auditing the conversion |
| `clock_skew_estimate_ms` (payload) | Agent's best estimate of its own clock skew | Confidence on `event_time` |
| `received_at` (Ahti envelope, ingest-side) | Ahti commit time | Ingest-order operations on Ahti's side |

### 4.2 Conversion rule

The kernel produces `CLOCK_BOOTTIME` nanoseconds. The agent converts to wall time at the moment of receipt:

```
event_time ≈ agent_now() − (agent_boot_clock_now() − kernel_time_ns)
```

The agent **MUST**:

- Record `clock_source` describing the conversion (e.g. `"CLOCK_BOOTTIME+wall_offset(NTP)"`).
- Record `clock_skew_estimate_ms` when it has one (from NTP / chrony / PTP); omit when unknown.
- **Not** rewrite `event_time` retroactively if its wall clock jumps; the recorded `event_time` is the agent's best knowledge at write time.

### 4.3 Cross-node ordering

Ahti orders by **ingest order**, not `event_time` (Ahti `record-kinds.md` §2 for `entity_version`; `consistency.md` for the protocol-level statement). Jälki consumers needing cross-node temporal ordering **MUST** use `event_time` and tolerate skew. The protocol does not promise that two records with `event_time_A < event_time_B` are ingested in that order.

### 4.4 Clock skew on outage

If the agent's wall clock jumps during an outage (NTP correction after offline) and buffered events would otherwise carry pre-jump `event_time`, the agent **MUST**:

- Preserve `kernel_time_ns` exactly as captured.
- Recompute `event_time` against the **current** wall clock and current `clock_skew_estimate_ms`, noting in `clock_source` that the conversion was post-jump.
- Emit a `jalki.agent.gap` occurrence with `cause = "clock_jump"` covering the affected window.

### 4.5 Monotonic-only mode

If the agent cannot establish a reliable wall clock (e.g. no NTP, embedded environment), the agent **MAY** omit `event_time` and rely only on `kernel_time_ns` in payload. The `event_time` envelope field is required by Ahti when known; an agent that genuinely never has it should consult deployment configuration for whether to write `event_time = received_at` (acceptable for short-window in-cluster use) or to refuse to start (preferred for long-term audit).

## 5. Offline behavior — retry, backpressure, gaps

### 5.1 Retry buffer

When Ahti is unreachable, the agent **MUST** buffer outgoing records up to a declared bound:

| Bound | Declared per | Default |
|---|---|---|
| `max_bytes` | agent profile | 256 MB |
| `max_records` | agent profile | 1,000,000 |
| `max_age_seconds` | agent profile | 600 |

Whichever bound is hit first triggers the loss policy.

### 5.2 Loss policy

The agent profile **MUST** declare one of:

| Policy | Effect when bound hit |
|---|---|
| `emit_gap_and_drop_oldest` | Drop the oldest records to make room; on next successful Ahti write, emit a `jalki.agent.gap` occurrence covering the dropped window. **Default and recommended.** |
| `emit_gap_and_drop_newest` | Drop newest until buffer fits; emit `jalki.agent.gap`. |
| `block_with_backpressure` | Stop draining BPF ring buffers; allow the kernel-side ring buffer to overflow. Emit a `jalki.agent.gap` with `cause = "ringbuffer_overflow"` once the agent recovers. |

`best_effort_silent_drop` is **not** a permitted policy in v0 ([`product-boundaries.md`](./product-boundaries.md) §2.8).

### 5.3 Gap records

A `jalki.agent.gap` occurrence (see [`runtime-evidence-model.md`](./runtime-evidence-model.md) §2.11) is the only honest way to express "Jälki was not watching this window". The agent **MUST** emit one when:

- The retry buffer overflowed and records were dropped.
- A BPF ring buffer overflowed and the kernel dropped events.
- A probe was unloaded and reattached during the window (e.g. agent restart).
- The agent's clock jumped during an outage (per §4.4).
- A sampling policy intentionally dropped events the policy declares as needing gap markers.

### 5.4 Backpressure visibility

The retry buffer fill ratio, BPF ring buffer fill ratio, and drop counter **MUST** be exported as agent metrics. Operators **SHOULD** alert on sustained fill > 50% as a signal that bounds are too tight or Ahti is intermittently unreachable.

## 6. Enrichment locality

### 6.1 What is enriched on the agent

| Field | Source | Notes |
|---|---|---|
| `container_id` | cgroup → container mapping (containerd, CRI-O, docker) | Cached LRU |
| `pod_uid` | container → pod mapping (kubelet metadata) | Cached LRU |
| `namespace`, `service_account` | pod → metadata | Cached LRU |
| `exe` resolved path | `/proc/<pid>/exe` | Best-effort; agent runs in hostPID |
| `argv_hash` | `/proc/<pid>/cmdline` or kernel-side capture | Hash before write |

### 6.2 Provenance

If enrichment is deterministic (e.g. `cgroup_id` → `container_id` from a single lookup), the record's `evidence_level` stays `observed`. If the agent relies on a possibly-stale cache, set `evidence_level = derived` and cite the enrichment cache `reference` in `lineage_refs`. See [`runtime-evidence-model.md`](./runtime-evidence-model.md) §6.4.

### 6.3 Unresolved fields

Unresolved enrichment **MUST** be omitted, not zero-filled (per [`runtime-evidence-model.md`](./runtime-evidence-model.md) §6.1). A record without `container_id` is honest; a record with `container_id = ""` is a lie.

## 7. Operational counters the agent SHOULD expose

These are not Ahti records; they are local operational metrics (Prometheus or equivalent):

- `jalki_records_written_total{kind,occurrence_type}`
- `jalki_records_buffered_bytes`
- `jalki_records_dropped_total{cause}`
- `jalki_ringbuffer_fill_ratio{probe}`
- `jalki_ahti_write_failures_total{reason}`
- `jalki_ahti_write_latency_seconds_bucket`
- `jalki_enrichment_cache_hit_ratio{cache}`
- `jalki_probes_attached`
- `jalki_clock_skew_ms`

Operators consume these for ops; they do **not** replace Ahti as the durable evidence path.

## 8. State that explicitly does **not** live on the agent

Restated for emphasis:

- **Past observations beyond the retry buffer.** Once a record is acked by Ahti, the agent **MUST** drop it.
- **Query indexes.** The agent is not queryable for "what happened yesterday on this node". That query goes to Ahti.
- **Aggregated counts beyond the local sampler window.** If aggregated counts are valuable, they are emitted as occurrences to Ahti; they are not maintained as long-running local aggregates.
- **Cross-node knowledge.** The agent knows about its node only. Cross-node state is Ahti.
- **Replay buffer for downstream consumers.** Consumers read from Ahti, not from the agent.

## 9. Configuration management

The agent profile (see [`probe-definitions.md`](./probe-definitions.md) §6) is the source of truth for what the agent runs. Two configuration loads matter:

| When | Source |
|---|---|
| Cold start | Local file / env vars / launch flags — minimum needed to authenticate to Ahti and locate its own `agent_profile` |
| Steady state | Ahti `entity_version` of `entity_type = agent_profile` with `logical_key = agent_profile/<cluster>/<node>` |

The agent **MAY** poll Ahti for profile updates on a fixed interval (declared at launch) or be pushed updates via a control protocol. Both models update the underlying `entity_version` in Ahti so Ahti remains the system of record. See [`probe-definitions.md`](./probe-definitions.md) §3.4 for the open question on dispatch model.

## 10. Decommissioning a node

When a node is decommissioned:

1. The agent **SHOULD** emit a final `jalki.agent.lifecycle` occurrence with `phase = "draining"` and stop attaching new probes.
2. Drain the retry buffer to Ahti, or emit a `jalki.agent.gap` covering anything still buffered.
3. Emit a final `jalki.agent.lifecycle` occurrence with `phase = "stopped"`.
4. The control plane **SHOULD** write a terminal `agent_profile` `entity_version` whose payload signals shutdown (Jälki convention; Ahti does not interpret payload tombstones).
5. Credentials revoked per Ahti `auth-producers.md` §6.3 — past records are preserved; new writes are refused.
6. The `producer_id = jalki-agent:<cluster>:<node>` **MUST NOT** be reused.

## 11. Failure modes summary

| Scenario | Required behavior |
|---|---|
| Ahti unreachable | Buffer up to declared bounds; emit gap on overflow |
| BPF ring buffer overflow | Emit gap; do **not** silently drop |
| Agent crash | On restart, emit a gap covering the unobserved window; rebuild local state from the agent profile |
| Clock jump | Recompute `event_time`; emit gap with `cause = "clock_jump"` |
| Schema unknown to Ahti | Write fails; agent treats as "Ahti unreachable" for that schema and buffers (do **not** silently drop; the control plane should have written the schema first) |
| `producer_id` rejected by Ahti | Hard fail; refuse to start. This is a deployment misconfiguration, not a runtime condition to paper over |
| Auth credential expired mid-run | Re-authenticate if possible; otherwise treat as Ahti unreachable |
| Capability snapshot fails (BTF missing) | Emit `jalki.agent.lifecycle` with the failure; degrade to probes that don't need the missing BTF; do **not** start probes that require it |

## 12. Open questions specific to local agent state

Propagated to [`v0-scope.md`](./v0-scope.md):

- Default authentication mechanism for v0 (mTLS vs. projected SA token).
- Default retry buffer sizing and loss policy.
- Whether `block_with_backpressure` is a v0 option or strictly post-v0.
- Whether to support resumable writes (idempotency via `logical_key` on occurrences) in v0 or rely on at-least-once + gap records.
- Whether the agent runs the question-answering surface (today's `ask`) locally or moves it to a separate `jalki-control`-side tool.
- Whether the agent serves any read-only API at all (operational read-only Prometheus + a `status` endpoint vs. a richer surface).
