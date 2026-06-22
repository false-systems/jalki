# Ahti Record Mapping

> **⚠ SUPERSEDED for Jälki by [ADR-0002](./adr/0002-evidence-through-polku-to-vartio.md) (2026-06-22).** This entire document describes how Jälki writes Ahti records. **Jälki no longer writes to Ahti** — evidence flows `jälki → Polku → Vartio → Ahti`, and **Vartio** performs every Ahti write. Treat this as historical, or as a reference for the *Vartio-side* write mapping — not as Jälki's contract.

This document maps every Jälki concept to one of Ahti's eight record kinds, using Ahti's actual field names (cf. `ahti/docs/record-kinds.md`, `ahti/docs/schema-registry.md`, `ahti/docs/auth-producers.md`).

The headline rule: **Jälki invents no record kinds.** Every durable thing Jälki writes is one of the eight Ahti kinds, with `payload` validated by a Jälki-owned `definition` in the `jalki` namespace.

## 0. Conventions used in this document

### 0.1 Producer identity

Every example shows `producer_id` for clarity, but Ahti stamps it from the bound principal regardless. A Jälki agent uses a `producer_id` of the form:

```
jalki-agent:<cluster>:<node_id>
```

Other Jälki components (control plane, debug tooling, probe planner) use distinct `producer_id` values. See [`local-agent-state.md`](./local-agent-state.md) §producer.

### 0.2 Namespace

All Jälki records are written to the `jalki` namespace. Sub-grouping is via `producer_id` and `logical_key`, not via sub-namespaces (Ahti namespaces are flat).

### 0.3 Typed refs

Every ref carries `kind` explicitly:

```json
{ "kind": "record_id", "value": "01HZ..." }
{ "kind": "logical_key", "namespace": "jalki", "producer_id": "jalki-agent:dev:node-1",
  "record_kind": "entity_version", "value": "process/node-1/18422/1715900400000" }
{ "kind": "external_uri", "value": "kernel-symbol://tcp_connect" }
```

Untyped refs are rejected by Ahti and are **forbidden** in Jälki design.

### 0.4 Required envelope fields

Every Jälki record carries, in addition to kind-specific fields:

| Field | Source | Note |
|---|---|---|
| `record_kind` | author | one of the 8 Ahti kinds |
| `namespace` | author = `"jalki"` | Ahti rejects mismatches with permitted set |
| `producer_id` | author, **stamped by Ahti** | author **MUST** match bound principal |
| `evidence_level` | author | typically `observed` for kernel events, `declared` for definitions/references, `derived` for enrichment |
| `retention_class` | author | one of `permanent | long | short | ephemeral`; no default |
| `event_time` | author | producer's best knowledge of when the event happened |
| `schema_ref` | author | typed ref to the `definition` validating `payload` |
| `payload` | author | validated against `schema_ref` |

### 0.5 evidence_level is descriptive, not ranking

Jälki uses `evidence_level` to describe how a record came to be:

| Value | Use |
|---|---|
| `observed` | Kernel hook fired; payload is what the agent saw |
| `declared` | A definition / reference / template |
| `derived` | Agent-side enrichment added a value not directly from the kernel |

Consumers **MUST NOT** rank records by `evidence_level` (Ahti `record-kinds.md` §9).

## 1. Mapping summary

| Jälki concept | Ahti record kind | Why |
|---|---|---|
| Kernel/runtime event (exec, connect, retransmit, …) | `occurrence` | Discrete events with `event_time` |
| Observation gap (agent offline window, sampler drop) | `occurrence` | Discrete event; payload describes the gap |
| Runtime entity snapshot (process, container, pod) | `entity_version` | Latest state per `logical_key`; supersedence by ingest order |
| Mechanical mapping (process_in_container, container_in_pod) | `relationship_claim` | Typed directional edge with `source_ref` / `target_ref` |
| Jälki-owned schema (event payload shape) | `definition` (kind: `record_schema`) | Validates a record kind's payload |
| Jälki-owned entity type (process, container, pod) | `definition` (kind: `entity_type`) | Names an `entity_version` type |
| Jälki-owned occurrence type (`kernel.tcp.retransmit`) | `definition` (kind: `occurrence_type`) | Names an `occurrence` type |
| Jälki-owned relationship type (`process_in_container`) | `definition` (kind: `relationship_type`) | Names a `relationship_claim` type |
| Reusable plan / template / vocabulary term | `definition` (kind: `vocabulary_term`) | Named reusable structure |
| External kernel hook handle | `reference` | Stable handle for a kernel symbol / BTF type |
| Container runtime handle | `reference` | Stable handle for a container/pod ID |
| Debug bundle, pcap, perf data, verifier log | `artifact_ref` | Bytes live outside the record store |
| Operator note on a Jälki record | `annotation` | Commentary, not a mutation |
| Anything that genuinely doesn't fit | `extension_record` | Escape hatch; requires `why_extension` justification |

## 2. `occurrence` — kernel and runtime events

The bulk of Jälki's writes are `occurrence` records. Each fires when a kernel hook resolves with enough data for a complete payload.

### 2.1 Required envelope additions (Ahti)

| Field | Notes |
|---|---|
| `event_time` | Kernel observation wall time (agent-corrected, see [`local-agent-state.md`](./local-agent-state.md) §time) |
| `occurrence_type` | Stable string, MUST be defined as a `definition` of kind `occurrence_type` in `jalki` namespace |
| `schema_ref` | Pinned (`record_id`) ref to the `record_schema` definition for the payload shape |

### 2.2 Optional envelope additions (Ahti)

| Field | Jälki usage |
|---|---|
| `source_ref` | The entity the occurrence is about (e.g. the process `entity_version` `logical_key`) |
| `evidence_refs` | Other Jälki records that semantically support the event (rare for raw kernel events; common for enrichment) |
| `lineage_refs` | Mechanical provenance — the `definition` record for the probe template that produced this occurrence, or the agent's capability snapshot `reference` |
| `payload` | Validated against `schema_ref` |

### 2.3 Example — process exec

```json
{
  "record_kind": "occurrence",
  "namespace": "jalki",
  "producer_id": "jalki-agent:dev:node-1",
  "occurrence_type": "kernel.process.exec",
  "event_time": "2026-05-17T14:03:11.482739204Z",
  "evidence_level": "observed",
  "retention_class": "short",
  "schema_ref": {
    "kind": "logical_key",
    "namespace": "jalki",
    "producer_id": "jalki-control",
    "record_kind": "definition",
    "value": "kernel.process.exec.v1"
  },
  "source_ref": {
    "kind": "logical_key",
    "namespace": "jalki",
    "producer_id": "jalki-agent:dev:node-1",
    "record_kind": "entity_version",
    "value": "process/node-1/18422/1715900591482"
  },
  "payload": {
    "node_id": "node-1",
    "pid": 18422,
    "ppid": 18001,
    "comm": "curl",
    "exe": "/usr/bin/curl",
    "argv_hash": "sha256:9af3...",
    "uid": 1000,
    "gid": 1000,
    "cgroup_id": 0x100000300abc,
    "container_id": "docker://3f2a...",
    "pod_uid": "8e7c4d...",
    "namespace": "payments",
    "service_account": "payments-api",
    "kernel_time_ns": 19283749182,
    "agent_recv_time": "2026-05-17T14:03:11.483102004Z",
    "clock_source": "CLOCK_BOOTTIME+wall_offset",
    "clock_skew_estimate_ms": 4
  }
}
```

Per-evidence-type field specifications are in [`runtime-evidence-model.md`](./runtime-evidence-model.md).

### 2.4 Occurrences are events, not state

Two consecutive `occurrence` records with identical payload are **two distinct events**, not deduplication targets (Ahti `record-kinds.md` §1). If Jälki ever needs supersedence semantics — "this process now has this name" — use `entity_version` instead.

### 2.5 `logical_key` on occurrences

Jälki **MAY** set `logical_key` on an occurrence for producer-side idempotency only. Two occurrences with the same `(jalki, jalki-agent:…, logical_key)` are accepted as two distinct events; the second does **not** supersede the first. Use only when the agent needs idempotency across retry (e.g. a write succeeded but the ack was lost).

## 3. `entity_version` — runtime entity state

Jälki **MAY** emit `entity_version` records for runtime entities whose latest known state is useful to downstream products.

### 3.1 Candidate Jälki entities

| Entity | `entity_type` (definition) | `logical_key` (suggested) |
|---|---|---|
| Process | `process` | `process/<node_id>/<pid>/<start_time_ns>` |
| Container | `container` | `container/<runtime>/<container_id>` |
| Pod | `pod` | `pod/<cluster>/<pod_uid>` |
| Node | `node` | `node/<cluster>/<node_id>` |
| cgroup | `cgroup` | `cgroup/<node_id>/<cgroup_id>` |
| Kernel capability snapshot | `kernel_capability_snapshot` | `kernel_snapshot/<node_id>/<kernel_release>` |

Open question: which of these belong to Jälki vs. to Vartio / a Kubernetes producer. v0 keeps Jälki to the entities it can observe **directly** from kernel/runtime (`process`, `cgroup`, `node`) and writes the others as `reference` records. See [`runtime-evidence-model.md`](./runtime-evidence-model.md) §entities and [`v0-scope.md`](./v0-scope.md) §open-questions.

### 3.2 Example — process entity_version

```json
{
  "record_kind": "entity_version",
  "namespace": "jalki",
  "producer_id": "jalki-agent:dev:node-1",
  "logical_key": "process/node-1/18422/1715900591482",
  "entity_type": "process",
  "schema_ref": {
    "kind": "logical_key",
    "namespace": "jalki",
    "producer_id": "jalki-control",
    "record_kind": "definition",
    "value": "entity.process.v1"
  },
  "evidence_level": "observed",
  "retention_class": "short",
  "event_time": "2026-05-17T14:03:11.482739204Z",
  "lineage_refs": [
    { "kind": "record_id", "value": "01HZ...<the exec occurrence>" }
  ],
  "payload": {
    "node_id": "node-1",
    "pid": 18422,
    "start_time_ns": 1715900591482,
    "comm": "payments-api",
    "exe": "/app/payments-api",
    "container_id": "docker://3f2a...",
    "pod_uid": "8e7c4d...",
    "namespace": "payments"
  }
}
```

### 3.3 Supersedence

The latest `entity_version` for `(jalki, jalki-agent:…, logical_key)` is decided by **ingest order**, not by `event_time` (Ahti `record-kinds.md` §2). Jälki agents writing entity updates **MUST** serialize per `logical_key` if they need a stable view.

### 3.4 Entities are not events

Jälki **MUST NOT** model an event as an `entity_version`. Process exec is an `occurrence`. The process's current state is an `entity_version`. Both may be written for the same exec, with the `entity_version` carrying the `occurrence`'s record in `lineage_refs`.

### 3.5 Deletion

A process exits, a container dies. Jälki expresses this by writing a final `entity_version` whose payload includes a producer-domain "terminated" marker (e.g. `terminated_at` and `exit_code`). Ahti does **not** interpret payload tombstones — the payload tombstone is a Jälki convention, not an Ahti feature.

## 4. `relationship_claim` — mechanical edges

Jälki **MAY** emit `relationship_claim` records for relationships it can support with direct kernel/runtime evidence.

### 4.1 Permitted Jälki relationship types

| `relationship_type` | Source → target |
|---|---|
| `process_in_container` | `process` entity → `container` entity |
| `container_in_pod` | `container` entity → `pod` entity / `pod` reference |
| `pod_on_node` | `pod` entity / reference → `node` entity |
| `process_opened_file` | `process` entity → `file_open` occurrence (or file reference) |
| `process_connected_to_endpoint` | `process` entity → `network_connect` occurrence (or endpoint reference) |
| `process_in_cgroup` | `process` entity → `cgroup` entity |

Each **MUST** be backed by a `definition` of kind `relationship_type` in the `jalki` namespace.

### 4.2 Forbidden Jälki relationship types

Jälki **MUST NOT** emit:

- `caused_incident`
- `root_cause_of`
- `actor_violated_policy`
- `deployment_caused_error`
- `belongs_to_actor`
- `is_part_of_chain`

These are product semantics. Lähde or Vartio may emit them, citing Jälki records in `evidence_refs`.

### 4.3 Example — process_in_container

```json
{
  "record_kind": "relationship_claim",
  "namespace": "jalki",
  "producer_id": "jalki-agent:dev:node-1",
  "relationship_type": "process_in_container",
  "schema_ref": {
    "kind": "logical_key",
    "namespace": "jalki",
    "producer_id": "jalki-control",
    "record_kind": "definition",
    "value": "rel.process_in_container.v1"
  },
  "evidence_level": "derived",
  "retention_class": "short",
  "event_time": "2026-05-17T14:03:11.482739204Z",
  "source_ref": {
    "kind": "logical_key",
    "namespace": "jalki",
    "producer_id": "jalki-agent:dev:node-1",
    "record_kind": "entity_version",
    "value": "process/node-1/18422/1715900591482"
  },
  "target_ref": {
    "kind": "logical_key",
    "namespace": "jalki",
    "producer_id": "jalki-agent:dev:node-1",
    "record_kind": "entity_version",
    "value": "container/containerd/3f2a..."
  },
  "evidence_refs": [
    { "kind": "record_id", "value": "01HZ...<the exec occurrence with cgroup_id>" }
  ],
  "payload": {
    "method": "cgroup_path_match",
    "cgroup_id": 0x100000300abc
  }
}
```

### 4.4 Revocation

Ahti does **not** interpret "revoke". To express that a relationship no longer holds, Jälki **SHOULD** write a new claim with a producer-defined qualifier (e.g. payload `{ "method": "…", "revoked_at": "…" }`) or update the source entity's `entity_version` to reflect the new state. See `record-kinds.md` §3.

## 5. `definition` — Jälki vocabulary

Every Jälki record kind, type, and reusable structure is declared as a `definition` in the `jalki` namespace.

### 5.1 Definition kinds Jälki uses

| `definition_kind` | Jälki use |
|---|---|
| `record_schema` | Payload shape of an `occurrence` / `entity_version` / `relationship_claim` / `annotation` / `artifact_ref` |
| `entity_type` | Names a Jälki entity (`process`, `container`, `pod`, `node`, `cgroup`) |
| `occurrence_type` | Names an event class (`kernel.process.exec`, `kernel.tcp.retransmit`) |
| `relationship_type` | Names a relationship (`process_in_container`) |
| `vocabulary_term` | Named reusable structures (probe plan templates, sampling policies, question mappings) |

### 5.2 Schema source of truth

The definitions themselves are written by the **Jälki control plane** producer (`jalki-control`), not by agents. Agents reference them by `record_id` (pinned) or by `logical_key` (latest). See [`probe-definitions.md`](./probe-definitions.md) for how the control plane manages definition lifecycle.

### 5.3 Example — definition for a `record_schema`

```json
{
  "record_kind": "definition",
  "namespace": "jalki",
  "producer_id": "jalki-control",
  "definition_kind": "record_schema",
  "logical_key": "kernel.process.exec.v1",
  "schema_ref": {
    "kind": "logical_key",
    "namespace": "ahti",
    "producer_id": "ahti",
    "record_kind": "definition",
    "value": "record_schema"
  },
  "evidence_level": "declared",
  "retention_class": "permanent",
  "payload": {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["node_id", "pid", "comm", "exe", "kernel_time_ns"],
    "properties": {
      "node_id":  { "type": "string" },
      "pid":      { "type": "integer", "minimum": 0 },
      "ppid":     { "type": "integer", "minimum": 0 },
      "comm":     { "type": "string", "maxLength": 16 },
      "exe":      { "type": "string" },
      "argv_hash":{ "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
      "uid":      { "type": "integer" },
      "gid":      { "type": "integer" },
      "cgroup_id":{ "type": "integer" },
      "container_id":{ "type": "string" },
      "pod_uid":  { "type": "string" },
      "namespace":{ "type": "string" },
      "service_account": { "type": "string" },
      "kernel_time_ns":  { "type": "integer" },
      "agent_recv_time": { "type": "string", "format": "date-time" },
      "clock_source":    { "type": "string" },
      "clock_skew_estimate_ms": { "type": "integer" }
    }
  }
}
```

### 5.4 Evolution

A new schema version is a new `definition` with the same `logical_key`. Ahti decides "latest" by ingest order. Agents writing occurrences against this schema **SHOULD** pin by `record_id` (Ahti `schema-registry.md` §4.2). See [`v0-scope.md`](./v0-scope.md) §evolution.

## 6. `reference` — external handles

Jälki **MAY** emit `reference` records to register stable handles for things outside Ahti: kernel hooks, BTF types, container runtime IDs, node identities, etc.

### 6.1 Required fields

| Field | Notes |
|---|---|
| `external_uri` | A URI for the external thing |
| `reference_type` | Stable string, MUST be a `definition` of any kind in `jalki` namespace (typically `vocabulary_term`) |
| `logical_key` | Stable producer-side name |

### 6.2 URI schemes Jälki uses

The URI scheme is a design decision; v0 proposes:

| Scheme | Example | Use |
|---|---|---|
| `kernel-symbol://<name>` | `kernel-symbol://tcp_connect` | Kernel function name (target of fentry/fexit) |
| `kernel-tracepoint://<subsys>/<name>` | `kernel-tracepoint://sched/sched_switch` | Tracepoint |
| `btf-type://<kernel_release>/<type>` | `btf-type://6.6.0/sock` | BTF struct/union type |
| `container-runtime://<runtime>/<id>` | `container-runtime://containerd/3f2a...` | Container ID |
| `pod-uid://<cluster>/<uid>` | `pod-uid://prod-east-1/8e7c4d...` | Kubernetes pod UID |
| `k8s-node://<cluster>/<node>` | `k8s-node://prod-east-1/ip-10-0-1-25` | Kubernetes node |

Open question (see [`v0-scope.md`](./v0-scope.md)): the precise scheme set, registered authority, and stability rules across kernel releases.

### 6.3 Example — kernel hook reference

```json
{
  "record_kind": "reference",
  "namespace": "jalki",
  "producer_id": "jalki-control",
  "reference_type": "kernel_hook",
  "logical_key": "kernel_hook/tcp_connect",
  "external_uri": "kernel-symbol://tcp_connect",
  "evidence_level": "declared",
  "retention_class": "permanent",
  "schema_ref": {
    "kind": "logical_key",
    "namespace": "jalki",
    "producer_id": "jalki-control",
    "record_kind": "definition",
    "value": "ref.kernel_hook.v1"
  },
  "payload": {
    "hook_name": "tcp_connect",
    "hook_kinds_supported": ["fexit"],
    "subsystem": "networking",
    "requires_btf": true,
    "min_kernel_release": "5.5",
    "evidence_emitted": ["kernel.tcp.connect"]
  }
}
```

### 6.4 No dereference

Ahti does not dereference `external_uri` (Ahti `record-kinds.md` §5). Jälki producers are responsible for the URI's validity at the time of registration. Agents **MUST NOT** assume Ahti will follow the URI back to a kernel.

## 7. `artifact_ref` — large captures

Jälki **MUST NOT** put large debug captures in a `payload`. Use `artifact_ref` with bytes in object storage.

### 7.1 Required fields

| Field | Notes |
|---|---|
| `storage_uri` | Where the bytes live (`s3://`, `gs://`, `file://`, …) |
| `content_hash` | SHA-256 hex recommended |
| `content_type` | MIME or producer-defined |
| `size_bytes` | Integer |
| `artifact_kind` | MUST be a `definition` in `jalki` namespace |

### 7.2 Jälki `artifact_kind` candidates

| `artifact_kind` (logical_key of definition) | Use |
|---|---|
| `jalki.debug_bundle` | tar.zst of agent diagnostic state |
| `jalki.pcap_sample` | Packet capture |
| `jalki.perf_data` | `perf` recording |
| `jalki.bpf_verifier_log` | Verifier output for a probe load failure |
| `jalki.long_event_capture` | Raw ring buffer dump for a time window |

### 7.3 Example

```json
{
  "record_kind": "artifact_ref",
  "namespace": "jalki",
  "producer_id": "jalki-agent:dev:node-1",
  "storage_uri": "s3://ahti-artifacts/jalki/debug/node-1/bundle-2026-05-17T140311Z.tar.zst",
  "content_hash": "sha256:9af3e2...",
  "content_type": "application/zstd",
  "size_bytes": 1234567,
  "artifact_kind": "jalki.debug_bundle",
  "evidence_level": "observed",
  "retention_class": "long",
  "event_time": "2026-05-17T14:03:11.482739204Z",
  "schema_ref": {
    "kind": "logical_key",
    "namespace": "jalki",
    "producer_id": "jalki-control",
    "record_kind": "definition",
    "value": "artifact.debug_bundle.v1"
  },
  "lineage_refs": [
    { "kind": "record_id", "value": "01HZ...<the occurrence that triggered the capture>" }
  ],
  "payload": {
    "captured_window": { "start": "2026-05-17T14:03:10Z", "end": "2026-05-17T14:03:11Z" },
    "captured_probes": ["tcp_connect", "tcp_retransmit"],
    "node_id": "node-1"
  }
}
```

The bytes are immutable once registered. If the capture changes, register a new `artifact_ref` (Ahti `record-kinds.md` §7).

## 8. `annotation` — operator commentary

Jälki **MAY** write `annotation` records, but the v0 surface is narrow: only `jalki-control` or an operator tool writes annotations, never agents. Use cases:

- Operator marks an event as known-noisy.
- A debug tool attaches a captured `pcap` artifact as commentary on a network occurrence.

Annotations **MUST NOT** mutate the target (Ahti `record-kinds.md` §6).

### 8.1 Example

```json
{
  "record_kind": "annotation",
  "namespace": "jalki",
  "producer_id": "jalki-debug-tool",
  "target_ref": { "kind": "record_id", "value": "01HZ...<a tcp_retransmit occurrence>" },
  "annotation_type": "jalki.attached_artifact",
  "schema_ref": {
    "kind": "logical_key",
    "namespace": "jalki",
    "producer_id": "jalki-control",
    "record_kind": "definition",
    "value": "annotation.attached_artifact.v1"
  },
  "evidence_level": "declared",
  "retention_class": "long",
  "payload": {
    "artifact_ref": { "kind": "record_id", "value": "01HZ...<the pcap artifact_ref>" },
    "note": "captured pcap for the 5s window around this retransmit"
  }
}
```

## 9. `extension_record` — escape hatch

Jälki **SHOULD NOT** use `extension_record` in v0. Every Jälki shape mapped here fits a core kind. The escape hatch exists for genuinely novel shapes; the design has none.

If a future Jälki design needs `extension_record`, the `why_extension` field **MUST** be filled with a non-empty justification and the proposing change **MUST** include a rationale for not promoting the shape to a `definition`-backed core kind.

## 10. Cross-cutting design rules

### 10.1 Evidence vs lineage refs

- `evidence_refs` — records that semantically support the assertion (a `relationship_claim` cites the exec `occurrence` whose `cgroup_id` justified the mapping).
- `lineage_refs` — mechanical provenance (the `definition` for the probe template; the `reference` for the kernel hook).

Do **not** collapse them into a single field (Ahti `record-kinds.md` §9 forbidden patterns).

### 10.2 Retention class per Jälki kind

No protocol default exists. Jälki **MUST** declare `retention_class` on every write. Recommended defaults (per agent profile, overridable):

| Record kind | Default | Why |
|---|---|---|
| `occurrence` (kernel event) | `short` | High volume; Lähde / Vartio derive `long` records from them |
| `occurrence` (gap, error, agent-lifecycle) | `long` | Need to keep these for audit |
| `entity_version` (process, cgroup) | `short` | Fast-moving |
| `entity_version` (node, kernel snapshot) | `long` | Slow-moving |
| `relationship_claim` | matches the source entity's class | |
| `definition` | `permanent` | Records pinned to them stay valid |
| `reference` | `permanent` | Stable handles |
| `artifact_ref` | `long` | Match the artifact's storage lifecycle |
| `annotation` | `long` | |

These are recommended defaults; deployment may override per-profile.

### 10.3 Time fields placement

- `event_time` (envelope) — agent's best wall-clock estimate of when the event happened.
- Payload **MAY** carry additional time fields when clock skew or monotonic time matters: `kernel_time_ns` (CLOCK_BOOTTIME or similar), `agent_recv_time`, `clock_source`, `clock_skew_estimate_ms`. See [`local-agent-state.md`](./local-agent-state.md) §time.
- Ahti's `received_at` is set at ingest; Jälki does not control it.

### 10.4 Schema pinning

Agents writing high-volume records (kernel events) **SHOULD** pin `schema_ref` by `record_id`, not `logical_key`, so that schema evolution does not change validation behavior mid-stream. The Jälki control plane distributes the active `record_id` for each schema as part of the agent's probe deployment payload (see [`probe-definitions.md`](./probe-definitions.md)).

## 11. What does **not** appear in this mapping

Cross-reference with [`product-boundaries.md`](./product-boundaries.md):

- No `incident` kind.
- No `chain` kind.
- No `actor_attribution` kind.
- No `caused_by` relationship type.
- No "severity" stamped as product judgment in payload.
- No payload field named `interpretation`, `root_cause`, `verdict`, or `conclusion`.

If a Jälki PR introduces any of the above, the design has drifted across a product boundary.
