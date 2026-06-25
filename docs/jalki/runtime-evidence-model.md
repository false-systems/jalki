# Runtime Evidence Model

> **Reconciled to [ADR-0002](./adr/0002-evidence-through-polku-to-vartio.md) (2026-06-23).** Topology is `jälki → Polku → Vartio → Ahti`: Jälki emits **neutral** FALSE Protocol occurrences to a pipeline sink. It does **not** write to Ahti, and does **not** write `entity_version`/`relationship_claim` records — Vartio derives those when it interprets. The payload shapes below are the contract for Jälki's emitted evidence (`jalki-evidence::normalize` builds them; `VartioCore.Importer.Jalki` maps them). `process.exec`, `tcp.connect`, `tcp.close`, `tcp.retransmit` are **implemented**; the rest are planned.

This document defines the core evidence types Jälki agents produce: source mechanism, required/optional payload fields, the Plane-B occurrence they map to, and the entities/relationships Vartio can derive from them.

The vocabulary is normative. Field shapes are encoded by `jalki-evidence` on emit and validated by the Vartio importer on ingest — not by an Ahti `definition` written by Jälki.

## 0. Common envelope (recap)

Each occurrence carries the FALSE Protocol fields produced by `jalki-evidence` (`source`, `occurrence_type`, `severity`, `outcome`, `cluster`, `correlation_keys`, `labels`, …) plus the producer/probe metadata projected by `EvidenceBatch` (ADR-0001 D6). Runtime binding (`k8s_pod_uid` / `k8s_container_id` / `k8s_namespace`, optional `github_run_id`) is attached on the node by `jalki-enrich` before the record reaches the sink; unbound records are dropped from Plane B.

- `observed_at` (kernel CLOCK_BOOTTIME) is preserved; ingest time is never set by Jälki.

This document specifies the **payload** shape per evidence type, plus what Vartio can derive from each.

## 1. Source mechanism — fentry vs fexit vs tracepoint

For every evidence type below, the **source mechanism** field constrains how the agent collects it:

| Mechanism | When to use |
|---|---|
| **fexit** | Need the return value or errno (e.g. `tcp_connect` success/failure, `tcp_sendmsg` byte count). Fires after the function returns. |
| **fentry** | Only need to know the call happened (e.g. `tcp_retransmit_skb`). Fires before execution. |
| **tracepoint** | Stable kernel-defined trace point; preferred when one exists (e.g. `sched/sched_switch`). |
| **kprobe / kretprobe** | Only when no fentry/fexit/tracepoint covers the function and the symbol is non-trace-safe. Document why. |

The mechanism is recorded on the probe metadata and projected into each occurrence as `hook_kind` / `kernel_function` labels. That makes the capture path explicit even before Vartio maps the event into its downstream record shape.

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

**Plane B occurrence type:** `kernel.process.exec` — **implemented** via `tracepoint:sched/sched_process_exec`. Emitted neutral to Polku→Vartio; `ppid` is omitted when unresolved; argv is carried only as `argv_hash`.

**Vartio can derive (entity):** a `process` `entity_version` keyed `process/<node_id>/<pid>/<start_time_ns>`, linking it to this `kernel.process.exec` occurrence as supporting evidence.

**Vartio can derive (relationships):**

- `process_in_cgroup` (when `cgroup_id` resolves to a known `cgroup` entity).
- `process_in_container` (when `container_id` resolves).
- `container_in_pod` (when both `container_id` and `pod_uid` are present; once per container lifetime).

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

**Plane B occurrence type:** `kernel.process.fork`. *Planned — not yet implemented.*

**Vartio can derive (entity):** none on fork alone. The new process entity is created on the subsequent `kernel.process.exec` (which may never come if the child execs directly into a thread; in that case the entity is created from `sched_process_exec`).

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

**Plane B occurrence type:** `kernel.process.exit`. *Planned — not yet implemented.*

**Vartio can derive (entity):** terminal `entity_version` for the process, payload includes `terminated_at = event_time` and `exit_code`.

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

**Plane B occurrence type:** `kernel.network.connect` / current implementation name `kernel.tcp.connect`.

**Known constraint:** `destination_ip = 0.0.0.0` on Cilium-managed connections when the destination has not yet been resolved at fexit. This is **not** a bug — see top-level `CLAUDE.md` "Known Constraints". Jälki **SHOULD** still emit the record (the agent must not silently drop it); downstream consumers handle the missing destination.

**Vartio can derive (relationships):**

- `process_connected_to_endpoint` from the `process` entity → an endpoint `reference` (`external_uri = tcp-endpoint://<dst_ip>:<dst_port>`). The relationship is **mechanical** ("this process attempted this connect"), not interpretive ("this process is the payments API"). v0 may defer this and emit only the `occurrence`.

---

### 2.5 `kernel.network.listen` and `kernel.network.accept`

**Source mechanism:** fexit on `inet_listen` and `inet_csk_accept` respectively.

**Required payload fields (listen):** `node_id`, `pid`, `protocol`, `bind_port`, `kernel_time_ns`, `agent_recv_time`. Optional: `bind_ip`, `cgroup_id`, `container_id`, `pod_uid`.

**Required payload fields (accept):** `node_id`, `pid`, `protocol`, `local_port`, `peer_ip`, `peer_port`, `kernel_time_ns`, `agent_recv_time`. Optional: `local_ip`, `cgroup_id`, `container_id`, `pod_uid`, `socket_cookie`.

**Plane B occurrence types:** two distinct `occurrence_type`s (`kernel.network.listen`, `kernel.network.accept`). *Planned — not yet implemented.*

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

**Plane B occurrence type:** `kernel.tcp.retransmit` — **implemented**.

**Interpretation note:** The TCP state is **observed**, not interpreted. Jälki **MUST NOT** include a field like `interpretation = "network problem"`. Lähde maps `(occurrence_type, tcp_state)` to a meaning; that mapping lives in Lähde, not in Jälki.

---

### 2.7 `kernel.file.open`

**Source mechanism:** **Implemented** as fexit on `security_file_open`.
This observes opens that reach the LSM hook, including LSM-denied opens; ordinary
path lookup or DAC permission failures may fail before this hook and are not
emitted by this v0 probe.

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

**Plane B occurrence type:** `kernel.file.open` — **implemented**. Emitted only for configured sensitive-path patterns. Jälki applies a coarse in-kernel prefix gate before the ring buffer and a precise userspace pattern match before emission. Truncated paths are labeled with `path_truncated=true`.

**Scope guard:** the default agent profile **MUST NOT** capture every open. The agent profile **MUST** declare which path patterns are captured. Blanket capture is operationally infeasible and is forbidden by default — see [`local-agent-state.md`](./local-agent-state.md) §sampling.

**Vartio can derive (relationships):** `process_opened_file` from `process` entity → the `kernel.file.open` occurrence (or a `file_path` reference if the path is hot enough to warrant a stable handle).

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
| `cause` | string | `"agent_offline" | "ringbuffer_overflow" | "sampling_drop" | "pipeline_unreachable" | "probe_unloaded"`, plus sink-specific terminal causes such as `"sink_rejected"` |
| `affected_probes` | string[] | `occurrence_type` values affected |

**Optional payload fields:**

| Field | Type | Notes |
|---|---|---|
| `estimated_events_lost` | u64 | Only when the count is known |
| `note` | string | |

**Plane B occurrence type:** `jalki.agent.gap`, `evidence_level = observed`, `retention_class = long`.

**Why this exists:** consumers **MUST** be able to distinguish "no event happened" from "Jälki was not watching". The gap record is the only honest way to do so. Jälki **MUST NOT** emit a sequence of evidence records that hides a gap.

---

### 2.12 `jalki.agent.lifecycle`

Agent start, stop, probe attach, probe detach, capability snapshot taken. Emitted as `occurrence` records with `occurrence_type = jalki.agent.lifecycle` and a `phase` field. These are Plane-B occurrences; Vartio may attach lineage to downstream entities when it interprets them.

## 3. Entity catalogue

> **Jälki does not write `entity_version` records (ADR-0002).** Vartio derives entities from Jälki's occurrences plus the runtime binding Jälki attaches. The taxonomy below is what Jälki's evidence lets Vartio reconstruct.

### 3.1 Entities derivable from Jälki evidence (v0)

These are observable from the fields Jälki emits (`pid`, `cgroup_id`, and the enriched `container_id` / `pod_uid`):

| `entity_type` | `logical_key` form | Source |
|---|---|---|
| `process` | `process/<node_id>/<pid>/<start_time_ns>` | exec / fork |
| `cgroup` | `cgroup/<node_id>/<cgroup_id>` | first observation; rare updates |
| `node` | `node/<cluster>/<node_id>` | agent startup |
| `kernel_capability_snapshot` | `kernel_snapshot/<node_id>/<kernel_release>` | agent startup / BTF probe |

### 3.2 Entities Jälki references but does **not** own (v0)

These Jälki refers to through runtime-binding labels and resource refs (using URI schemes from [`ahti-record-mapping.md`](./ahti-record-mapping.md) §6.2 where applicable):

| Concept | Why a reference, not an entity |
|---|---|
| `container` | Container runtime is the authoritative producer of container entities |
| `pod` | A Kubernetes producer is the authoritative writer; Jälki references by `pod_uid` |

Open question (v0): whether Vartio should derive lightweight container entities when no Kubernetes producer is present. Default: no. See [`v0-scope.md`](./v0-scope.md) §open-questions.

### 3.3 Entity derivation rules

- Vartio **SHOULD NOT** derive an `entity_version` per occurrence; instead, derive on lifecycle transitions (exec, exit, significant cgroup changes).
- Vartio owns supersedence ordering for derived entities.
- Every derived entity version **SHOULD** cite the originating occurrence in lineage.

## 4. Relationship catalogue

> **Vartio composes these** from the binding Jälki attaches; Jälki writes no `relationship_claim` records. Actor/ownership attribution remains Vartio's (product-boundaries §2.3).

### 4.1 Mechanical relationships Vartio can derive (v0)

| `relationship_type` | Source → target | Mechanism |
|---|---|---|
| `process_in_cgroup` | `process` entity → `cgroup` entity | From cgroup_id on first observation |
| `process_in_container` | `process` entity → `container` reference | From cgroup→container ID mapping |
| `container_in_pod` | `container` reference → `pod` reference | From cgroup or container runtime metadata |
| `pod_on_node` | `pod` reference → `node` entity | From the agent's node ID + observation |

### 4.2 Forbidden (restated from [`product-boundaries.md`](./product-boundaries.md))

Jälki **MUST NOT** emit `caused_incident`, `root_cause_of`, `actor_violated_policy`, `belongs_to_actor`, `is_part_of_chain`, or any other interpretive type.

### 4.3 Relationship write cadence

- Vartio should emit a relationship **once** per stable lifetime (e.g. one `process_in_container` per process lifetime).
- State changes within a stable identity become derived entity updates downstream.
- To express that a relationship no longer holds, Vartio writes the appropriate superseding downstream record; Jälki only emits the observations.

## 5. Evidence-type → downstream record kind

> The `occurrence` rows are what **Jälki emits** to Plane B. The `entity_version` / `relationship_claim` / `reference` rows are **derived and written by Vartio**, not Jälki — listed so the downstream shape is clear.

| Evidence | Downstream record kind | `evidence_level` | Default `retention_class` |
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
- Downstream ingest time is set after the pipeline receives the record; Jälki does not control it.

### 6.4 Enrichment provenance

When a field is added by enrichment (e.g. `container_id` derived from `cgroup_id`), the record's `evidence_level` is **still** `observed` if the core fact is observed and the enrichment is deterministic. If the enrichment uses a cached fallback, Jälki sets `evidence_level = derived`. It does not add Ahti lineage records itself; Vartio may attach downstream lineage when it interprets the occurrence. See [`local-agent-state.md`](./local-agent-state.md) §enrichment.

## 7. Open questions specific to evidence model

These are propagated to [`v0-scope.md`](./v0-scope.md):

- Whether to replace the v0 file-open `struct file` field-offset reads with CO-RE/BTF field relocation helpers once the local Aya stack exposes them.
- Whether to capture `argv` (raw) or only `argv_hash` by default for `kernel.process.exec`.
- Whether Vartio should derive lightweight `container` and `pod` `entity_version` records when no Kubernetes producer is present.
- Whether `count`-coalesced `tcp_retransmit` occurrences are permitted in v0 and, if so, how long the coalesce window may be.
- Whether destination endpoint references are derived in v0 or deferred.
- How `socket_cookie` correlation is preserved across `network.connect` / `network.accept` / `tcp.retransmit` when not always available.
