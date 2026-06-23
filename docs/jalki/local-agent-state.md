# Local Agent State

> **Reconciled to [ADR-0002](./adr/0002-evidence-through-polku-to-vartio.md) (2026-06-23).** Topology `jälki → Polku → Vartio → Ahti`: local state ships to the **pipeline sink** (Polku→Vartio), never to Ahti. §5 (retry/gaps) and §6 (enrichment) are now **implemented** — §6 in `jalki-enrich` + `jalki/src/kube_watch.rs`, §5 in `jalki-evidence/src/retry.rs`. §3 (producer auth-to-Ahti) and §9 (`agent_profile` in Ahti) are **superseded**: Jälki authenticates to the pipeline ingress, not Ahti. Enrichment is a **hard requirement** — Vartio drops unbound evidence (ADR-0002 §D5).

This document specifies what may live on a Jälki agent locally, what **must** reach the Polku→Vartio pipeline, how the agent behaves when the pipeline is unreachable, how time is normalized, and how producer identity is bound.

The headline rule (recap):

> Local Jälki state is **operational**. Plane-B pipeline state is the durable evidence path. If a fact must survive an agent restart, it is emitted to Polku→Vartio, which writes Ahti.

## 1. What may live locally

Permitted local state (with declared bounds and eviction policy):

| State | Why local | Bound |
|---|---|---|
| BPF ring buffers | Kernel-side queues for events the agent has not yet drained | Per-buffer max bytes (default 4 MB, configurable per probe) |
| BPF maps (HashMap, LRU, percpu arrays) | Per-probe kernel state (e.g. PID_FILTER, in-flight syscall tracking) | Per-map max entries declared at load |
| Metadata enrichment caches | Cgroup → container, container → pod mappings | Bounded LRU; size declared per agent profile |
| Retry buffer | Batches that failed to append to the pipeline sink | See §5 |
| In-flight assembly buffers | Multi-fragment events (e.g. argv across pages) | Per-event TTL; expire and emit a `jalki.agent.gap` if unresolved |
| Capability snapshot draft | Built during agent startup before being emitted as lifecycle/capability evidence | Discarded once sent or superseded |
| Local debug artifacts pending upload | tar / pcap / verifier logs to be promoted by downstream tooling if configured | Per-agent disk quota; oldest-first eviction with a `jalki.agent.lifecycle` note |
| Process-table cache | Per-node view of running PIDs and cgroup/container context | Bounded; rebuilt on agent restart |
| Active probe registry | Per-agent record of attached probes and local probe metadata | Rebuilt from launch/config state on restart |
| Last-sent watermark per probe | Used to size the retry buffer and to reason about gaps | Single value per probe |

Every local store **MUST** have:

- A declared maximum size.
- A declared eviction policy.
- An observable counter / gauge (Prometheus or equivalent) so operators can see when it is filling.
- A defined behavior on eviction (drop with gap event, or block with backpressure).

## 2. What must reach the pipeline (Plane B)

Evidence is durable only once shipped off the node to **Polku → Vartio** (which interprets and writes to Ahti). The agent **MUST NOT** treat local buffers as a datastore:

- All neutral `occurrence`s the agent produces (kernel events, `jalki.agent.gap`, `jalki.agent.lifecycle`) must reach the pipeline sink. Strongly-bound records go to Plane B; unbound records are dropped from Plane B (counted in `jalki_unbound_dropped_total`) and survive only on the local debug surface (Plane A).
- Jälki does **not** produce `entity_version` / `relationship_claim` / `definition` / `reference` records — Vartio derives entities and chains from the occurrences plus the runtime binding Jälki attaches.

If a Jälki author finds themselves writing "we'll keep this on the agent for a while", the design is wrong — the agent buffers transiently (§5) and emits gaps on loss.

## 3. Producer identity

> **Superseded (ADR-0002).** This section described authenticating to Ahti and Ahti stamping `producer_id`. Jälki no longer writes to Ahti — it authenticates to the pipeline ingress (Polku→Vartio), and producer/probe identity rides in the occurrence's projected metadata (`producer`, `producer_version`, `node_id`, `kernel_release`, …). The `jalki-control` producer split below does **not** apply. Kept for historical context.

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

### 5.1 Retry buffer — **implemented**

When the pipeline sink returns a transient error (`Unavailable` / `Timeout` / `Backpressure`), the agent buffers outgoing batches up to a declared bound. Implemented in `jalki-evidence/src/retry.rs` as `RetryBuffer` (`RetryBufferConfig`):

| Bound | Default |
|---|---|
| `max_records` | 1,000,000 |
| `max_batches` | 8,192 |
| `max_age_ms` | 600,000 (10 min) |

Whichever bound is hit first triggers the loss policy. Expiry uses a **monotonic** clock, so an NTP step cannot prematurely drop batches.

### 5.2 Loss policy

| Policy | Effect when bound hit |
|---|---|
| `emit_gap_and_drop_oldest` | Drop the oldest batch; emit a `jalki.agent.gap` covering its window. **Implemented (the only policy today).** |
| `emit_gap_and_drop_newest` | Designed, not implemented. |
| `block_with_backpressure` | Designed, not implemented. |

`best_effort_silent_drop` is **not** permitted ([`product-boundaries.md`](./product-boundaries.md) §2.8). On a **terminal** sink error (`Rejected` / `Unauthorized` / …) the batch is dropped and a `jalki.agent.gap` with the matching cause is emitted.

### 5.3 Gap records

A `jalki.agent.gap` occurrence (see [`runtime-evidence-model.md`](./runtime-evidence-model.md) §2.11) is the only honest way to express "Jälki was not watching this window". The agent **MUST** emit one when:

- The retry buffer overflowed and records were dropped.
- A BPF ring buffer overflowed and the kernel dropped events.
- A probe was unloaded and reattached during the window (e.g. agent restart).
- The agent's clock jumped during an outage (per §4.4).
- A sampling policy intentionally dropped events the policy declares as needing gap markers.

### 5.4 Backpressure visibility

BPF ring-buffer drops (`jalki_ring_buffer_drops`), sink errors (`jalki_sink_errors`), and unbound drops (`jalki_unbound_dropped_total`) are exported (§7). Operators **SHOULD** alert on sustained sink errors as a signal that the pipeline is intermittently unreachable. (A retry-buffer fill-ratio gauge is planned.)

## 6. Enrichment locality — **implemented**

Runtime binding is mandatory: Vartio drops evidence without a `pod_uid`/`container_id` (ADR-0002 §D5), so Jälki resolves the binding on the node before a record reaches the sink. Code: `jalki-enrich` (aya/kube-free parsing + bounded `BindingCache`) and `jalki/src/kube_watch.rs` (the pod watch), wired via `jalki/src/enrich.rs` (`CachedEnricher`).

### 6.1 How the binding is resolved

| Field | Source | Notes |
|---|---|---|
| `container_id` | **`/proc/<pid>/cgroup`** (hot path, O(1)); cgroupfs-inode scan as a **memoized** fallback | parses containerd / CRI-O / docker cgroup forms |
| `pod_uid`, `namespace`, `service_account`, labels | Kubernetes **pod watch** filtered to this node (`spec.nodeName`), indexed `container_id → pod metadata` in a bounded `BindingCache` (FIFO eviction, hit/miss stats) | refreshed on watch events |
| `github_run_id` | the ARC runner-pod label `actions.github.com/run-id` | the join to the GitHub Actions chain root |
| `argv_hash` | source-side digest | raw argv is never captured |

### 6.2 Provenance

`BindingProvenance::Observed` when the container ref was resolved live (procfs); `DerivedFromCache` when served from the memoized cgroupfs fallback. This rides in the `evidence_level` label — not as an Ahti record.

### 6.3 Unresolved fields

Unresolved fields are **omitted, not zero-filled** (e.g. `ppid` is `None` when unknown, never `0`). Unbound records are excluded from Plane B and counted in `jalki_unbound_dropped_total{reason}`.

## 7. Operational counters

Local Prometheus metrics on `:9090` (not Ahti records). **Implemented:**

- `jalki_events_total{...}` — events captured per probe
- `jalki_ring_buffer_drops{probe}` — kernel ring-buffer overflow
- `jalki_attach_errors{probe}` — probe attach failures
- `jalki_sink_errors{sink}` — pipeline append failures
- `jalki_unbound_dropped_total{reason}` — Plane-B records dropped for missing/weak binding
- `jalki_binding_cache_entries` / `jalki_binding_cache_hit_ratio` — enrichment cache health

Planned: retry-buffer fill ratio, clock-skew gauge, append-latency histogram. Operators consume these for ops; they do **not** replace the pipeline as the durable evidence path.

## 8. State that explicitly does **not** live on the agent

Restated for emphasis:

- **Past observations beyond the retry buffer.** Once a batch is accepted by the pipeline sink, the agent **MUST** drop it.
- **Query indexes.** The agent is not queryable for "what happened yesterday on this node". That query goes to Ahti.
- **Aggregated counts beyond the local sampler window.** If aggregated counts are valuable, they are emitted as occurrences to the pipeline; they are not maintained as long-running local aggregates.
- **Cross-node knowledge.** The agent knows about its node only. Cross-node state is Ahti.
- **Replay buffer for downstream consumers.** Consumers read from Ahti, not from the agent.

## 9. Configuration management

Agent configuration (see [`probe-definitions.md`](./probe-definitions.md) §6) is the source of truth for what the agent runs. Two configuration loads matter:

| When | Source |
|---|---|
| Cold start | Local file / env vars / launch flags — minimum needed to authenticate to the pipeline ingress and locate runtime config |
| Steady state | Control-plane supplied config; its durable source is outside the Jälki agent |

The agent **MAY** poll for config updates on a fixed interval (declared at launch) or be pushed updates via a control protocol. In either model, the agent treats config as input; it does not make Ahti writes to manage its own profile. See [`probe-definitions.md`](./probe-definitions.md) §3.4 for the open question on dispatch model.

## 10. Decommissioning a node

When a node is decommissioned:

1. The agent **SHOULD** emit a final `jalki.agent.lifecycle` occurrence with `phase = "draining"` and stop attaching new probes.
2. Drain the retry buffer to the pipeline sink, or emit a `jalki.agent.gap` covering anything still buffered.
3. Emit a final `jalki.agent.lifecycle` occurrence with `phase = "stopped"`.
4. The control plane **SHOULD** mark the node/agent config terminal in its own durable store.
5. Pipeline credentials are revoked — past records are preserved downstream; new writes are refused.
6. The agent identity for `<cluster>:<node>` **MUST NOT** be reused for a different node.

## 11. Failure modes summary

| Scenario | Required behavior |
|---|---|
| Pipeline unreachable | Buffer up to declared bounds; emit gap on overflow |
| BPF ring buffer overflow | Emit gap; do **not** silently drop |
| Agent crash | On restart, emit a gap covering the unobserved window; rebuild local state from launch/config state |
| Clock jump | Recompute `event_time`; emit gap with `cause = "clock_jump"` |
| Pipeline rejects schema/record | Terminal sink error; emit a `jalki.agent.gap` for the dropped batch and surface `jalki_sink_errors` |
| Pipeline identity rejected | Hard fail; refuse to start. This is a deployment misconfiguration, not a runtime condition to paper over |
| Auth credential expired mid-run | Re-authenticate if possible; otherwise treat as pipeline unreachable |
| Capability snapshot fails (BTF missing) | Emit `jalki.agent.lifecycle` with the failure; degrade to probes that don't need the missing BTF; do **not** start probes that require it |

## 12. Open questions specific to local agent state

Propagated to [`v0-scope.md`](./v0-scope.md):

- Default authentication mechanism for v0 (mTLS vs. projected SA token).
- Default retry buffer sizing and loss policy.
- Whether `block_with_backpressure` is a v0 option or strictly post-v0.
- Whether to support resumable writes (idempotency via `logical_key` on occurrences) in v0 or rely on at-least-once + gap records.
- Whether the agent runs the question-answering surface (today's `ask`) locally or moves it to a separate `jalki-control`-side tool.
- Whether the agent serves any read-only API at all (operational read-only Prometheus + a `status` endpoint vs. a richer surface).
