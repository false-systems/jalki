# Runtime Evidence Model

> **⚠ AMENDED by [ADR-0002](./adr/0002-evidence-through-polku-to-vartio.md) (2026-06-22).** Jälki no longer writes to Ahti (`jälki → Polku → Vartio → Ahti`). The **payload field shapes** below survive as the evidence Jälki emits to Vartio, but every "**Ahti binding**" line and the "entity_version / relationship_claim records Jälki writes" are **superseded** — Vartio derives those when it interprets. Plane-B evidence must be **neutral** (no severity / root-cause); see ADR-0002 §D4.

This document defines the core evidence types Jälki agents produce, with source mechanism, required and optional fields, Ahti binding, and the entity / relationship records each evidence type can support.

The vocabulary used here is normative. Every name and every field shape **MUST** be backed by a Jälki-owned `definition` record in the `jalki` namespace (see [`ahti-record-mapping.md`](./ahti-record-mapping.md) §5 and [`probe-definitions.md`](./probe-definitions.md)).

## 0. Common envelope (recap)

Every record discussed below carries the Ahti envelope fields described in [`ahti-record-mapping.md`](./ahti-record-mapping.md) §0:

- `record_kind`, `namespace = "jalki"`, `producer_id`, `evidence_level`, `retention_class`, `event_time`, `schema_ref`, optional `source_ref`, `evidence_refs`, `lineage_refs`.

This document only specifies the **payload** shape per evidence type, plus the entity and relationship records each can support.

## 1. Source mechanism — fentry vs fexit vs tracepoint

For every evidence type below, the **source mechanism** field constrains how the agent collects it:

| Mechanism | When to use |
|---|---|
| **fexit** | Need the return value or errno (e.g. `tcp_connect` success/failure, `tcp_sendmsg` byte count). Fires after the function returns. |
| **fentry** | Only need to know the call happened (e.g. `tcp_retransmit_skb`). Fires before execution. |
| **tracepoint** | Stable kernel-defined trace point; preferred when one exists (e.g. `sched/sched_switch`). |
| **kprobe / kretprobe** | Only when no fentry/fexit/tracepoint covers the function and the symbol is non-trace-safe. Document why. |

The mechanism is recorded on the **probe plan template** (see [`probe-definitions.md`](./probe-definitions.md)), not on every event. Per-event records do **NOT** carry the mechanism — it is implied by `occurrence_type` and the linked `definition`.

## 2. Evidence type catalogue

### 2.1 `kernel.process.exec`

**Source mechanism:** `tracepoint:sched/sched_process_exec` for successful exec path capture.

**Required payload fields:**

| Field | Type | Notes |
|---|---|---|
| `node_id` | string | Agent's node identifier |
| `pid` | u32 | Process ID |
| `comm` | string (≤16) | `task->comm` |
| `exe` | string | Resolved executable path; **MUST** be omitted if unresolved |
| `kernel_time_ns` | u64 | CLOCK_BOOTTIME nanoseconds |
| `agent_recv_time` | RFC3339 | Agent wall-clock receipt |

**Optional payload fields:**

| Field | Type | Notes |
|---|---|---|
| `ppid` | u32 | Parent PID |
| `argv_hash` | string | `sha256:` hex of arg vector; raw argv only on explicit profile opt-in |
| `argv` | string[] | Only when explicitly enabled in agent profile; subject to redaction class |
| `uid` / `gid` | u32 | |
| `cgroup_id` | u64 | Kernel cgroup ID |
| `container_id` | string | Enriched; format `<runtime>://<id>` |
| `pod_uid` | string | Enriched |
| `namespace` | string | Kubernetes namespace (enrichment) |
| `service_account` | string | Enrichment |
| `clock_source` | string | e.g. `CLOCK_BOOTTIME+wall_offset` |
| `clock_skew_estimate_ms` | i32 | |

**Ahti binding:** `occurrence`, `occurrence_type = kernel.process.exec`, `schema_ref → jalki/jalki-control/definition/kernel.process.exec.v1`.

**Entity records derived:** `entity_version` of `entity_type = process` with `logical_key = process/<node_id>/<pid>/<start_time_ns>`. The `kernel.process.exec` occurrence is cited in `lineage_refs` of the entity_version.

**Relationship records derived:**

- `process_in_cgroup` (when `cgroup_id` resolves to a known `cgroup` entity).
- `process_in_container` (when `container_id` resolves).
- `container_in_pod` (when both `container_id` and `pod_uid` are present, written once per container lifetime).

**Sensitive content note:** raw `argv` may contain secrets. Default agent profile **MUST** emit `argv_hash` only. Operators may opt in to raw `argv` per profile, with awareness that the record will be subject to operator-managed redaction.

---

### 2.2 `kernel.process.fork`

**Source mechanism:** `tracepoint:sched/sched_process_fork`.

**Required payload fields:**

| Field | Type | Notes |
|---|---|---|
| `node_id` | string | |
| `parent_pid` | u32 | |
| `child_pid` | u32 | |
| `kernel_time_ns` | u64 | |
| `agent_recv_time` | RFC3339 | |

**Optional payload fields:**

| Field | Type | Notes |
|---|---|---|
| `parent_comm` | string | |
| `cgroup_id` | u64 | |

**Ahti binding:** `occurrence`, `occurrence_type = kernel.process.fork`.

**Entity records derived:** none on fork alone. The new process entity is created on the subsequent `kernel.process.exec` (which may never come if the child execs directly into a thread; in that case the entity is created from `sched_process_exec`).

---

### 2.3 `kernel.process.exit`

**Source mechanism:** `tracepoint:sched/sched_process_exit`.

**Required payload fields:**

| Field | Type | Notes |
|---|---|---|
| `node_id` | string | |
| `pid` | u32 | |
| `exit_code` | i32 | |
| `kernel_time_ns` | u64 | |
| `agent_recv_time` | RFC3339 | |

**Optional payload fields:**

| Field | Type | Notes |
|---|---|---|
| `comm` | string | |
| `cgroup_id` | u64 | |
| `signal` | i32 | Termination signal if killed |

**Ahti binding:** `occurrence`, `occurrence_type = kernel.process.exit`.

**Entity records derived:** terminal `entity_version` for the process, payload includes `terminated_at = event_time` and `exit_code`.

---

### 2.4 `kernel.network.connect`

**Source mechanism:** fexit on `tcp_connect` (TCP). UDP equivalent deferred.

**Required payload fields:**

| Field | Type | Notes |
|---|---|---|
| `node_id` | string | |
| `pid` | u32 | |
| `protocol` | string | `"tcp"` |
| `destination_ip` | string | IPv4 or IPv6 |
| `destination_port` | u16 | |
| `kernel_time_ns` | u64 | |
| `agent_recv_time` | RFC3339 | |

**Optional payload fields:**

| Field | Type | Notes |
|---|---|---|
| `comm` | string | |
| `source_ip` | string | May be unresolved at fexit if SNAT applies |
| `source_port` | u16 | |
| `cgroup_id` | u64 | |
| `container_id` | string | Enriched |
| `pod_uid` | string | Enriched |
| `namespace` | string | Enriched |
| `socket_cookie` | u64 | If available |
| `result` | string | `"success" | "failure"` |
| `errno` | i32 | Present on failure |

**Ahti binding:** `occurrence`, `occurrence_type = kernel.network.connect`.

**Known constraint:** `destination_ip = 0.0.0.0` on Cilium-managed connections when the destination has not yet been resolved at fexit. This is **not** a bug — see top-level `CLAUDE.md` "Known Constraints". Jälki **SHOULD** still emit the record (the agent must not silently drop it); downstream consumers handle the missing destination.

**Relationship records derived:**

- `process_connected_to_endpoint` from the `process` entity → an endpoint `reference` (`external_uri = tcp-endpoint://<dst_ip>:<dst_port>`). The relationship is **mechanical** ("this process attempted this connect"), not interpretive ("this process is the payments API"). v0 may defer this and emit only the `occurrence`.

---

### 2.5 `kernel.network.listen` and `kernel.network.accept`

**Source mechanism:** fexit on `inet_listen` and `inet_csk_accept` respectively.

**Required payload fields (listen):** `node_id`, `pid`, `protocol`, `bind_port`, `kernel_time_ns`, `agent_recv_time`. Optional: `bind_ip`, `cgroup_id`, `container_id`, `pod_uid`.

**Required payload fields (accept):** `node_id`, `pid`, `protocol`, `local_port`, `peer_ip`, `peer_port`, `kernel_time_ns`, `agent_recv_time`. Optional: `local_ip`, `cgroup_id`, `container_id`, `pod_uid`, `socket_cookie`.

**Ahti binding:** two distinct `occurrence_type`s, two distinct `record_schema` definitions.

---

### 2.6 `kernel.tcp.retransmit`

**Source mechanism:** fentry on `tcp_retransmit_skb` (no return value needed).

**Required payload fields:**

| Field | Type | Notes |
|---|---|---|
| `node_id` | string | |
| `source_ip` | string | |
| `source_port` | u16 | |
| `destination_ip` | string | |
| `destination_port` | u16 | |
| `tcp_state` | u8 | Numeric kernel TCP state at retransmit time |
| `kernel_time_ns` | u64 | |
| `agent_recv_time` | RFC3339 | |

**Optional payload fields:**

| Field | Type | Notes |
|---|---|---|
| `pid` | u32 | Often unavailable in retransmit context |
| `cgroup_id` | u64 | |
| `container_id` | string | Enriched if `cgroup_id` resolves |
| `pod_uid` | string | Enriched |
| `count` | u32 | Default `1`; agents **MAY** coalesce identical events within a small window and report `count > 1` (the agent profile declares the window) |
| `bytes_in_flight` | u32 | If readable from `tcp_sock` |

**Ahti binding:** `occurrence`, `occurrence_type = kernel.tcp.retransmit`.

**Interpretation note:** The TCP state is **observed**, not interpreted. Jälki **MUST NOT** include a field like `interpretation = "network problem"`. Lähde maps `(occurrence_type, tcp_state)` to a meaning; that mapping lives in Lähde, not in Jälki.

---

### 2.7 `kernel.file.open`

**Source mechanism:** LSM hook `security_file_open` if available; otherwise fexit on `do_filp_open`. Open question (see [`v0-scope.md`](./v0-scope.md)): which to standardize for v0.

**Required payload fields:**

| Field | Type | Notes |
|---|---|---|
| `node_id` | string | |
| `pid` | u32 | |
| `path` | string | Resolved absolute path |
| `flags` | string[] | Normalized: `read`, `write`, `create`, `truncate`, … |
| `result` | string | `"allowed" | "denied"` |
| `kernel_time_ns` | u64 | |
| `agent_recv_time` | RFC3339 | |

**Optional payload fields:**

| Field | Type | Notes |
|---|---|---|
| `comm` | string | |
| `uid` | u32 | |
| `cgroup_id` | u64 | |
| `container_id` | string | Enriched |
| `pod_uid` | string | Enriched |
| `namespace` | string | Enriched |
| `errno` | i32 | On denial |
| `sensitive_class` | string | If the path matches a configured sensitive-path policy; classifier is a `vocabulary_term` definition |

**Ahti binding:** `occurrence`, `occurrence_type = kernel.file.open`.

**Scope guard:** the default agent profile **MUST NOT** capture every open. The agent profile **MUST** declare which path patterns are captured. Blanket capture is operationally infeasible and is forbidden by default — see [`local-agent-state.md`](./local-agent-state.md) §sampling.

**Relationship records derived:** `process_opened_file` from `process` entity → the `kernel.file.open` occurrence (or a `file_path` reference if the path is hot enough to warrant a stable handle).

---

### 2.8 `kernel.dns.lookup` (deferred to post-v0)

DNS observability is in scope for the framework but not for v0 (no built-in eBPF program today; would need uprobe on libc resolver or hooking into the kernel's UDP path). When added, this section will specify the source mechanism and fields.

---

### 2.9 `kernel.block.io_issue` and `kernel.block.io_complete` (deferred to post-v0)

Block I/O latency is in scope for the framework but deferred to a later slice. Source mechanism candidates: `tracepoint:block/block_rq_issue` and `block_rq_complete`. Fields to design include device, sector, size, latency.

---

### 2.10 `kernel.sched.latency` (deferred to post-v0)

Scheduler latency / runqueue delay. Source mechanism candidate: `tracepoint:sched/sched_switch` paired with `sched_wakeup`. Deferred.

---

### 2.11 `jalki.agent.gap`

**Source mechanism:** Agent-internal. Emitted when the agent resumes after an outage, when a ring buffer overflowed, or when sampling dropped events the operator declared it must not silently drop.

**Required payload fields:**

| Field | Type | Notes |
|---|---|---|
| `node_id` | string | |
| `gap_start` | RFC3339 | Wall-clock estimate; nullable when only monotonic time is known |
| `gap_end` | RFC3339 | |
| `cause` | string | `"agent_offline" | "ringbuffer_overflow" | "sampling_drop" | "ahti_unreachable" | "probe_unloaded"` |
| `affected_probes` | string[] | `occurrence_type` values affected |

**Optional payload fields:**

| Field | Type | Notes |
|---|---|---|
| `estimated_events_lost` | u64 | Only when the count is known |
| `note` | string | |

**Ahti binding:** `occurrence`, `occurrence_type = jalki.agent.gap`, `evidence_level = observed`, `retention_class = long`.

**Why this exists:** consumers **MUST** be able to distinguish "no event happened" from "Jälki was not watching". The gap record is the only honest way to do so. Jälki **MUST NOT** emit a sequence of evidence records that hides a gap.

---

### 2.12 `jalki.agent.lifecycle`

Agent start, stop, probe attach, probe detach, capability snapshot taken. Emitted as `occurrence` records with `occurrence_type = jalki.agent.lifecycle` and a `phase` field. The `lineage_refs` on these events point to the `definition` of the probe plan template and the `reference` of the capability snapshot.

## 3. Entity catalogue

### 3.1 Jälki-owned entities (v0)

These entities Jälki **directly observes** and **MAY** emit as `entity_version` records:

| `entity_type` | `logical_key` form | Source |
|---|---|---|
| `process` | `process/<node_id>/<pid>/<start_time_ns>` | exec / fork |
| `cgroup` | `cgroup/<node_id>/<cgroup_id>` | first observation; rare updates |
| `node` | `node/<cluster>/<node_id>` | agent startup |
| `kernel_capability_snapshot` | `kernel_snapshot/<node_id>/<kernel_release>` | agent startup / BTF probe |

### 3.2 Entities Jälki references but does **not** own (v0)

These Jälki refers to via `reference` records (using URI schemes from [`ahti-record-mapping.md`](./ahti-record-mapping.md) §6.2):

| Concept | Why a reference, not an entity |
|---|---|
| `container` | Container runtime is the authoritative producer of container entities |
| `pod` | A Kubernetes producer is the authoritative writer; Jälki references by `pod_uid` |

Open question (v0): whether Jälki **MAY** emit lightweight `entity_version` records for containers when no Kubernetes producer is present. Default: no. See [`v0-scope.md`](./v0-scope.md) §open-questions.

### 3.3 Entity write rules

- Jälki **SHOULD NOT** emit an `entity_version` per occurrence; instead, emit on **lifecycle transitions** (exec, exit, significant cgroup changes).
- Jälki **MUST** serialize entity_version writes per `logical_key` on the agent to avoid out-of-order supersedence.
- Every entity_version **SHOULD** carry the originating occurrence in `lineage_refs`.

## 4. Relationship catalogue

### 4.1 Permitted in v0

| `relationship_type` | Source → target | Mechanism |
|---|---|---|
| `process_in_cgroup` | `process` entity → `cgroup` entity | From cgroup_id on first observation |
| `process_in_container` | `process` entity → `container` reference | From cgroup→container ID mapping |
| `container_in_pod` | `container` reference → `pod` reference | From cgroup or container runtime metadata |
| `pod_on_node` | `pod` reference → `node` entity | From the agent's node ID + observation |

### 4.2 Forbidden (restated from [`product-boundaries.md`](./product-boundaries.md))

Jälki **MUST NOT** emit `caused_incident`, `root_cause_of`, `actor_violated_policy`, `belongs_to_actor`, `is_part_of_chain`, or any other interpretive type.

### 4.3 Relationship write cadence

- Emit a relationship **once** per stable lifetime (e.g. one `process_in_container` per process lifetime).
- Use `entity_version` updates for state that changes within a stable identity (e.g. process renaming via `prctl(PR_SET_NAME)`).
- To express that a relationship no longer holds, write a superseding `entity_version` whose payload reflects the new state, or write a new claim with a producer-defined `revoked_at` qualifier (Ahti does not interpret revocation).

## 5. Evidence-type → Ahti record kind matrix

| Evidence | Ahti kind | `evidence_level` | Default `retention_class` |
|---|---|---|---|
| `kernel.process.exec` | `occurrence` | `observed` | `short` |
| `kernel.process.fork` | `occurrence` | `observed` | `short` |
| `kernel.process.exit` | `occurrence` | `observed` | `short` |
| `kernel.network.connect` | `occurrence` | `observed` | `short` |
| `kernel.network.listen` | `occurrence` | `observed` | `short` |
| `kernel.network.accept` | `occurrence` | `observed` | `short` |
| `kernel.tcp.retransmit` | `occurrence` | `observed` | `short` |
| `kernel.file.open` | `occurrence` | `observed` | `short` |
| `jalki.agent.gap` | `occurrence` | `observed` | `long` |
| `jalki.agent.lifecycle` | `occurrence` | `observed` | `long` |
| Process entity | `entity_version` (`process`) | `observed` | `short` |
| cgroup entity | `entity_version` (`cgroup`) | `observed` | `short` |
| Node entity | `entity_version` (`node`) | `observed` | `long` |
| Kernel capability snapshot | `entity_version` (`kernel_capability_snapshot`) | `declared` | `long` |
| Mechanical mappings | `relationship_claim` | `derived` | matches source entity |
| Kernel hook handles | `reference` | `declared` | `permanent` |
| Container / pod handles | `reference` | `declared` | `long` |
| Capture bundles | `artifact_ref` | `observed` | `long` |

Deployment may override `retention_class` per agent profile; the protocol guarantee is only that the class is declared, not that any specific class is used.

## 6. Cross-cutting field rules

### 6.1 Missing values

Fields with unresolved values **MUST** be omitted, not zero-padded. A missing `container_id` is correct; `container_id = ""` is wrong.

### 6.2 String length and shape

- `comm` is bounded by kernel: ≤ 16 bytes.
- `exe` is unbounded by the kernel but agents **SHOULD** cap and warn (log line plus an agent.lifecycle event if truncation matters).
- IPs are canonical strings (`"10.0.3.12"`, `"2001:db8::1"`), not packed integers, even though the kernel stores them packed.
- Ports are unsigned integers in payload, not strings.

### 6.3 Time fields placement (recap)

- `event_time` in envelope, normalized to RFC3339.
- `kernel_time_ns` (CLOCK_BOOTTIME nanoseconds) in payload for skew-tolerant ordering on the same node.
- `agent_recv_time` in payload for measuring agent-internal delay.
- `clock_source`, `clock_skew_estimate_ms` in payload when relevant.
- Ahti's `received_at` is set at ingest; Jälki does not control it.

### 6.4 Enrichment provenance

When a field is added by enrichment (e.g. `container_id` derived from `cgroup_id`), the record's `evidence_level` is **still** `observed` if the core fact is observed and the enrichment is deterministic. If the enrichment requires a non-deterministic lookup (e.g. a stale cache), set `evidence_level = derived` and add the enrichment cache `reference` to `lineage_refs`. See [`local-agent-state.md`](./local-agent-state.md) §enrichment.

## 7. Open questions specific to evidence model

These are propagated to [`v0-scope.md`](./v0-scope.md):

- Which file-open source mechanism to standardize on (LSM `security_file_open` vs. fexit `do_filp_open`).
- Whether to capture `argv` (raw) or only `argv_hash` by default for `kernel.process.exec`.
- Whether Jälki **MAY** emit lightweight `container` and `pod` `entity_version` records when no Kubernetes producer is present.
- Whether `count`-coalesced `tcp_retransmit` occurrences are permitted in v0 and, if so, how long the coalesce window may be.
- Whether destination endpoint `reference` records are emitted in v0 or deferred.
- How `socket_cookie` correlation is preserved across `network.connect` / `network.accept` / `tcp.retransmit` when not always available.
