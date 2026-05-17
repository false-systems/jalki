# Probe Definitions

This document specifies how Jälki represents the **reusable structures** that drive an agent: probe plan templates, kernel hook handles, sampling policies, capability requirements, output schemas, and the question→plan mappings the agent's question-answering surface needs.

The headline rule:

> Definitions live in Ahti as `definition` records. References live in Ahti as `reference` records. Ahti stores; the agent executes.

No probe plan, kernel hook list, or sampling policy lives durably outside Ahti.

## 1. Producer split

Two Jälki producers write the records described here:

| Producer | What it writes | Why split |
|---|---|---|
| `jalki-control` | All `definition` records; most `reference` records (kernel hooks, BTF types). | Schemas and reusable templates evolve under controlled review, not from a thousand agents. |
| `jalki-agent:<cluster>:<node>` | `reference` records for **node-local** facts (container/pod handles, node capability snapshots) and all `occurrence` / `entity_version` / `relationship_claim` records. | Per-node observations. |

A single deployment **MAY** map both producer IDs to the same control-plane principal during early phases, but the IDs **MUST** be distinct (Ahti binds principals to producer IDs; see [`local-agent-state.md`](./local-agent-state.md) §producer).

## 2. Categories of definition

Jälki uses Ahti's five `definition_kind` values:

| `definition_kind` | Jälki use | Examples |
|---|---|---|
| `record_schema` | Payload shape of a Jälki record | `kernel.process.exec.v1`, `entity.process.v1` |
| `entity_type` | Names a Jälki entity | `process`, `cgroup`, `node` |
| `occurrence_type` | Names an event class | `kernel.tcp.retransmit`, `jalki.agent.gap` |
| `relationship_type` | Names a mechanical relationship | `process_in_container` |
| `vocabulary_term` | Named reusable structure | `probe_plan_template`, `sampling_policy`, `agent_profile`, `question_mapping` |

### 2.1 Choice for "probe plan template"

A probe plan template is **not** a schema, an entity type, an occurrence type, or a relationship type. It is a reusable named structure. The cleanest fit is:

> A probe plan template is a `definition` with `definition_kind = vocabulary_term` whose payload validates against the meta-schema `probe_plan_template.v1` (itself a `record_schema` definition).

This is the **proposed design**. It is called out as an open question in [`v0-scope.md`](./v0-scope.md); the alternative is to model templates as `entity_version` records of an `entity_type = probe_plan_template`. The `vocabulary_term` choice is preferred because templates are named reusable references (like vocabulary), not state-tracked entities.

## 3. Probe plan templates

A probe plan template specifies what evidence Jälki should collect when a particular question is asked or when a deployment profile says "always be collecting these".

### 3.1 Template payload (proposed, v0)

```jsonc
{
  "template_name": "postgres_latency_v1",
  "question_class": "database_latency",
  "applicable_when": {
    "any_pod_label": { "app.kubernetes.io/component": "postgres" }
  },
  "required_capabilities": [
    "kernel-symbol://tcp_retransmit_skb",
    "kernel-tracepoint://sched/sched_switch",
    "kernel-tracepoint://block/block_rq_issue"
  ],
  "probes": [
    {
      "name": "tcp_retransmit",
      "mechanism": "fentry",
      "target": { "kind": "external_uri", "value": "kernel-symbol://tcp_retransmit_skb" },
      "output_occurrence_type": "kernel.tcp.retransmit",
      "output_schema_pinned": { "kind": "record_id", "value": "01HZ..." },
      "sampling_policy_ref": {
        "kind": "logical_key", "namespace": "jalki",
        "producer_id": "jalki-control", "record_kind": "definition",
        "value": "sampling.tcp_retransmit_default_v1"
      }
    },
    {
      "name": "sched_switch_latency",
      "mechanism": "tracepoint",
      "target": { "kind": "external_uri", "value": "kernel-tracepoint://sched/sched_switch" },
      "output_occurrence_type": "kernel.sched.latency",
      "output_schema_pinned": { "kind": "record_id", "value": "01HZ..." },
      "sampling_policy_ref": { "kind": "logical_key", "namespace": "jalki",
        "producer_id": "jalki-control", "record_kind": "definition",
        "value": "sampling.aggressive_v1" }
    }
  ],
  "default_duration_seconds": 60,
  "default_retention_class_for_outputs": "short"
}
```

### 3.2 As an Ahti `definition` record

```json
{
  "record_kind": "definition",
  "namespace": "jalki",
  "producer_id": "jalki-control",
  "definition_kind": "vocabulary_term",
  "logical_key": "probe_plan_template/postgres_latency_v1",
  "evidence_level": "declared",
  "retention_class": "permanent",
  "schema_ref": {
    "kind": "logical_key", "namespace": "jalki",
    "producer_id": "jalki-control", "record_kind": "definition",
    "value": "probe_plan_template.v1"
  },
  "payload": { "...": "the template payload above" }
}
```

The meta-schema `probe_plan_template.v1` is itself a `definition` of `definition_kind = record_schema`, written by `jalki-control`, validated against Ahti's bootstrap `record_schema`.

### 3.3 Ahti stores; agent executes

The agent **MUST**:

1. Fetch templates from Ahti by `logical_key` (latest) or `record_id` (pinned).
2. Resolve every `*_ref` inside the template (sampling policies, output schemas, kernel hook references) by reading the referenced records from Ahti.
3. Apply the template locally — attach probes, enforce sampling, write outputs.
4. Emit a `jalki.agent.lifecycle` occurrence on attach / detach, with `lineage_refs = [{template definition}]`.

Ahti **MUST NOT** execute anything. There is no Ahti-side trigger that says "deploy this on these agents".

### 3.4 Probe deployment dispatch (open question)

How a particular template gets onto a particular agent is a control-plane concern. Two candidates, both legitimate:

1. **Pull model**: agent polls Ahti for `entity_version` records of `entity_type = agent_profile` with `logical_key = agent_profile/<cluster>/<node>`. The profile lists template `record_id`s the agent should run.
2. **Push model**: a side-channel control protocol (gRPC) tells the agent "run these templates". The control plane writes the corresponding `agent_profile` `entity_version` to Ahti for audit; Ahti is the system of record, not the dispatch path.

v0 picks one and documents the open question. See [`v0-scope.md`](./v0-scope.md) §open-questions.

## 4. Kernel hook references

Every kernel hook Jälki might attach to is registered as a `reference` record, so that:

- Probe plan templates and probe deployment records can refer to hooks stably.
- An operator can list the hooks Jälki knows about by querying `reference_type = kernel_hook` in the `jalki` namespace.
- Capability snapshots (per node) cite the hook references they support / don't support.

### 4.1 Schema for kernel hook reference (payload)

```jsonc
{
  "hook_name": "tcp_connect",
  "hook_kinds_supported": ["fexit"],
  "subsystem": "networking",
  "requires_btf": true,
  "min_kernel_release": "5.5",
  "max_kernel_release": null,
  "evidence_emitted": ["kernel.network.connect"],
  "stability": "stable",
  "notes": "fexit gives errno; do not use kprobe"
}
```

### 4.2 As an Ahti `reference` record (recap)

See [`ahti-record-mapping.md`](./ahti-record-mapping.md) §6.3.

### 4.3 Tracepoint references

Tracepoints follow the same pattern with `external_uri = kernel-tracepoint://<subsys>/<name>`, and the payload's `hook_kinds_supported = ["tracepoint"]`.

### 4.4 BTF type references

When a probe depends on a specific BTF struct/union (e.g. `tcp_sock`), the dependency is recorded as a `reference` with `external_uri = btf-type://<kernel_release>/<type>` so that a capability snapshot can cite which BTF types were resolved.

## 5. Sampling policies

A sampling policy describes how the agent decides which events to keep, drop, or coalesce.

### 5.1 Policy payload (proposed, v0)

```jsonc
{
  "policy_name": "sampling.tcp_retransmit_default_v1",
  "applies_to": ["kernel.tcp.retransmit"],
  "method": "head_sampler",
  "rate": 1.0,
  "coalesce": {
    "key_fields": ["source_ip", "source_port", "destination_ip", "destination_port"],
    "window_ms": 1000,
    "emit": "count"
  },
  "ringbuffer_overflow": "emit_gap",
  "max_events_per_second_per_node": 5000
}
```

### 5.2 As an Ahti `definition`

`definition_kind = vocabulary_term`, `logical_key = sampling/<policy_name>`. Same envelope shape as probe plan templates.

### 5.3 Loss semantics

A sampling policy **MUST** declare what happens when the policy's bounds are exceeded:

| Field | Meaning |
|---|---|
| `ringbuffer_overflow = "emit_gap"` | When the BPF ring buffer overflows, emit a `jalki.agent.gap` occurrence covering the lost window. |
| `ringbuffer_overflow = "best_effort"` | Drop silently. **Forbidden in v0**; included for explicit future opt-in only. |
| `max_events_per_second_per_node` | Hard ceiling. Exceeding it emits a `jalki.agent.gap` and stops emitting that occurrence_type until the rate falls. |

`best_effort` exists only as documentation of a future option and **MUST NOT** be a valid v0 sampling choice — see [`product-boundaries.md`](./product-boundaries.md) §2.8.

## 6. Agent profiles

An agent profile is the per-node configuration: which probe plan templates the agent is running, which sampling policies apply by default, which sensitive-path patterns to capture, and so on.

### 6.1 Agent profile as `entity_version`

Agent profiles are **stateful** (per-node, supersedable), so they are `entity_version` records (not `vocabulary_term` definitions):

```json
{
  "record_kind": "entity_version",
  "namespace": "jalki",
  "producer_id": "jalki-control",
  "logical_key": "agent_profile/dev/node-1",
  "entity_type": "agent_profile",
  "schema_ref": {
    "kind": "logical_key", "namespace": "jalki",
    "producer_id": "jalki-control", "record_kind": "definition",
    "value": "entity.agent_profile.v1"
  },
  "evidence_level": "declared",
  "retention_class": "long",
  "event_time": "2026-05-17T12:00:00Z",
  "payload": {
    "cluster": "dev",
    "node_id": "node-1",
    "templates": [
      { "kind": "record_id", "value": "01HZ...<postgres_latency_v1>" }
    ],
    "default_sampling": [
      { "kind": "logical_key", "namespace": "jalki",
        "producer_id": "jalki-control", "record_kind": "definition",
        "value": "sampling.tcp_retransmit_default_v1" }
    ],
    "sensitive_path_patterns": [
      { "pattern": "/var/run/secrets/**", "class": "k8s_service_account" }
    ],
    "argv_capture": "hash_only",
    "ahti_endpoint": "https://ahti.dev.svc.cluster.local:8443"
  }
}
```

### 6.2 Why `entity_version`, not `definition`

A definition names a reusable thing. An agent profile is the state of a specific agent's configuration. State is `entity_version`; latest is decided by ingest order. Treating agent profiles as definitions would confuse evolution semantics.

## 7. Question mappings

Today's Jälki has a knowledge base (`knowledge/*.json` compiled into the binary) that maps human questions to probe plans. In the new architecture, that mapping moves to Ahti.

### 7.1 Question mapping as `definition`

`definition_kind = vocabulary_term`, `logical_key = question_mapping/<class>`:

```json
{
  "record_kind": "definition",
  "namespace": "jalki",
  "producer_id": "jalki-control",
  "definition_kind": "vocabulary_term",
  "logical_key": "question_mapping/database_latency",
  "schema_ref": { "kind": "logical_key", "namespace": "jalki",
    "producer_id": "jalki-control", "record_kind": "definition",
    "value": "question_mapping.v1" },
  "evidence_level": "declared",
  "retention_class": "permanent",
  "payload": {
    "question_class": "database_latency",
    "keywords": ["slow", "postgres", "mysql", "database", "latency"],
    "applicable_templates": [
      { "kind": "logical_key", "namespace": "jalki",
        "producer_id": "jalki-control", "record_kind": "definition",
        "value": "probe_plan_template/postgres_latency_v1" }
    ]
  }
}
```

### 7.2 Where the matching logic lives

The matching ("does this human question match the database_latency class?") is **not Jälki's job in the long run**. v0 keeps a simple keyword matcher in the agent for backward compatibility with the existing `jalki ask` CLI, but the strategic owner of question→class mapping is Lähde or a future intent-routing service. See [`product-boundaries.md`](./product-boundaries.md) §1.5 and §6.

In v0, Jälki may keep the existing keyword matcher as a thin shim; the **mapping data** (question class → templates) lives in Ahti, not compiled into the binary.

## 8. Capability snapshots

When an agent starts, it discovers what its kernel can support: BTF availability, which hooks resolve, which BPF program types are permitted, ring buffer sizes, etc. This is durable evidence about the node's capability and is written to Ahti.

### 8.1 Capability snapshot as `entity_version`

```json
{
  "record_kind": "entity_version",
  "namespace": "jalki",
  "producer_id": "jalki-agent:dev:node-1",
  "logical_key": "kernel_snapshot/node-1/6.6.0",
  "entity_type": "kernel_capability_snapshot",
  "schema_ref": { "kind": "logical_key", "namespace": "jalki",
    "producer_id": "jalki-control", "record_kind": "definition",
    "value": "entity.kernel_capability_snapshot.v1" },
  "evidence_level": "declared",
  "retention_class": "long",
  "event_time": "2026-05-17T11:59:55Z",
  "payload": {
    "node_id": "node-1",
    "kernel_release": "6.6.0",
    "arch": "x86_64",
    "btf_available": true,
    "btf_path": "/sys/kernel/btf/vmlinux",
    "supported_hooks": [
      { "kind": "record_id", "value": "01HZ...<tcp_connect ref>" },
      { "kind": "record_id", "value": "01HZ...<tcp_retransmit ref>" }
    ],
    "unsupported_hooks": [
      { "ref": { "kind": "record_id", "value": "01HZ...<some hook>" }, "reason": "BTF type missing" }
    ],
    "ringbuffer_max_bytes": 4194304,
    "bpf_program_types_permitted": ["FENTRY", "FEXIT", "TRACEPOINT"]
  }
}
```

### 8.2 Why `entity_version`

The snapshot represents the agent's view of the node's kernel capability at a moment. Newer snapshots supersede older ones for the same `logical_key`. This is state, not an event.

## 9. Versioning and evolution

### 9.1 Schemas

A new schema version is a new `definition` with the same `logical_key`. Agents writing high-volume occurrences **SHOULD** pin by `record_id` so a schema rev does not change validation behavior mid-stream (see [`ahti-record-mapping.md`](./ahti-record-mapping.md) §10.4 and Ahti `schema-registry.md` §7).

### 9.2 Templates

A new template version is a new `definition` with the same `logical_key = probe_plan_template/<name>`. Agent profiles citing the template by `logical_key` (latest) auto-upgrade on next reload. Profiles that pin by `record_id` are stable.

### 9.3 References

Kernel hook `reference` records evolve when their support matrix changes (a new minimum kernel release, a deprecation note). A new version is a new `reference` with the same `logical_key`.

## 10. Lifecycle summary

```
   jalki-control writes definitions and references to Ahti (once / when evolving)
        │
        ▼
   jalki-control writes per-node agent_profile entity_version to Ahti
        │
        ▼
   jalki-agent reads its agent_profile (latest), resolves template + sampling refs
        │
        ▼
   jalki-agent attaches probes; emits jalki.agent.lifecycle (attached)
        │
        ▼
   jalki-agent emits occurrences / entity_versions / relationship_claims to Ahti
        │
        ▼
   jalki-agent on detach: emit jalki.agent.lifecycle (detached)
```

Every step writes to Ahti or reads from Ahti. There is no parallel store.

## 11. Open questions specific to probe definitions

Propagated to [`v0-scope.md`](./v0-scope.md):

- Confirm `vocabulary_term` as the `definition_kind` for probe plan templates, sampling policies, and question mappings (vs. modeling templates as `entity_version`).
- Pick a probe-deployment dispatch model (pull from Ahti vs. side-channel control protocol).
- Define the URI scheme set for kernel hook / BTF / container references (covered in [`ahti-record-mapping.md`](./ahti-record-mapping.md) §6.2 — open question).
- Decide whether question-mapping logic stays in Jälki for v0 or moves immediately to Lähde.
- Decide how operators introspect "what's deployed on which node" — Ahti query vs. agent-local read-only API.
