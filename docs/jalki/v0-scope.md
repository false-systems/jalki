# Jälki v0 Scope

This document defines the first implementation slice and what it deliberately leaves out. It is the contract between the design (the other docs in this directory) and the first round of implementation PRs.

The headline rule: v0 makes the **producer-to-Ahti loop real** for three evidence types and one entity type. Everything else is documented and deferred.

## 1. In scope for v0

### 1.1 Evidence types

| Evidence | Source mechanism | Notes |
|---|---|---|
| `kernel.process.exec` | fexit on `bprm_execve` (preferred) | argv as `argv_hash` only |
| `kernel.network.connect` | fexit on `tcp_connect` (TCP) | UDP deferred |
| `kernel.file.open` | LSM `security_file_open` if available; else fexit on `do_filp_open` (decision in §5 open questions) | Only paths matching the agent profile's `sensitive_path_patterns` |

### 1.2 Internal Jälki events (v0)

| Event | Why required |
|---|---|
| `jalki.agent.lifecycle` | Attach / detach / capability snapshot events; required for any audit story |
| `jalki.agent.gap` | Required by the no-silent-loss rule; v0 MUST emit these on overflow / restart / clock jump |

### 1.3 Entities

| Entity | Notes |
|---|---|
| `process` | `entity_version` on exec and on terminal exit |
| `node` | `entity_version` on agent start; superseded on restart with non-trivial capability change |
| `kernel_capability_snapshot` | `entity_version` per (node, kernel_release) on agent start |

`cgroup` is deferred to v0.1 to keep the slice tight. `container` and `pod` are **never** Jälki entities by default; they are referenced via `reference` records when present in payloads.

### 1.4 Relationships

| Relationship | Notes |
|---|---|
| `process_in_container` | Only when `cgroup_id → container_id` enrichment succeeds; emitted once per process lifetime |

Other relationships (`process_in_cgroup`, `container_in_pod`, `pod_on_node`) are deferred to v0.1.

### 1.5 Definitions (written by `jalki-control`)

| `logical_key` | `definition_kind` | Purpose |
|---|---|---|
| `kernel.process.exec.v1` | `record_schema` | Payload schema for exec occurrences |
| `kernel.network.connect.v1` | `record_schema` | Payload schema for connect occurrences |
| `kernel.file.open.v1` | `record_schema` | Payload schema for file_open occurrences |
| `jalki.agent.gap.v1` | `record_schema` | Payload schema for gap occurrences |
| `jalki.agent.lifecycle.v1` | `record_schema` | Payload schema for lifecycle occurrences |
| `entity.process.v1` | `record_schema` | Payload schema for process entity_version |
| `entity.node.v1` | `record_schema` | Payload schema for node entity_version |
| `entity.kernel_capability_snapshot.v1` | `record_schema` | Capability snapshot payload schema |
| `entity.agent_profile.v1` | `record_schema` | Agent profile payload schema |
| `rel.process_in_container.v1` | `record_schema` | Relationship claim payload schema |
| `ref.kernel_hook.v1` | `record_schema` | Kernel hook reference payload schema |
| `kernel.process.exec` | `occurrence_type` | Names the event class |
| `kernel.network.connect` | `occurrence_type` | |
| `kernel.file.open` | `occurrence_type` | |
| `jalki.agent.gap` | `occurrence_type` | |
| `jalki.agent.lifecycle` | `occurrence_type` | |
| `process` | `entity_type` | |
| `node` | `entity_type` | |
| `kernel_capability_snapshot` | `entity_type` | |
| `agent_profile` | `entity_type` | |
| `process_in_container` | `relationship_type` | |
| `kernel_hook` | `vocabulary_term` | Names the reference type |
| `probe_plan_template.v1` | `record_schema` | Meta-schema for templates |
| `sampling_policy.v1` | `record_schema` | Meta-schema for sampling policies |
| `agent_profile_default_v0` | `vocabulary_term` | One reference profile shipped with v0 |

### 1.6 References (written by `jalki-control` for cluster-wide; by agent for node-local)

| Reference | Producer | Notes |
|---|---|---|
| `kernel_hook/bprm_execve` | `jalki-control` | |
| `kernel_hook/tcp_connect` | `jalki-control` | |
| `kernel_hook/security_file_open` *or* `kernel_hook/do_filp_open` | `jalki-control` | depending on §5 decision |

### 1.7 Agent profile mechanics

- One reference `agent_profile_default_v0` shipped as a `definition` (`vocabulary_term`).
- For each node, `jalki-control` writes an `entity_version` of `entity_type = agent_profile` whose payload lists `templates`, `sampling`, `sensitive_path_patterns`, `argv_capture = "hash_only"`, `ahti_endpoint`, and `retry_buffer` bounds.
- Agent on cold start reads `agent_profile` by `logical_key`.

### 1.8 Producer authentication

- v0 standardizes on **one** authentication mechanism — decision deferred to the open questions in §5 (mTLS vs. projected SA token).
- One principal → one `producer_id`. Misconfiguration is a hard fail at startup, not at runtime.

### 1.9 Sampling and loss

- One sampling policy: `sampling.v0_default` — head-sample at 1.0 (no drop) for `kernel.process.exec` and `kernel.network.connect`; `kernel.file.open` gated by `sensitive_path_patterns` only.
- One loss policy: `emit_gap_and_drop_oldest`. `block_with_backpressure` and `best_effort` are post-v0.
- Retry buffer defaults: 256 MB / 1,000,000 records / 600 s — declared in the agent profile.

### 1.10 Capability snapshot

Agent on start:

1. Build snapshot in memory (BTF present? which `kernel_hook` refs resolve?).
2. Write as `entity_version`.
3. Subsequent records cite the snapshot in `lineage_refs`.

## 2. Explicit non-goals for v0

| Non-goal | Why |
|---|---|
| Enforcement | Jälki is observe-only ([`product-boundaries.md`](./product-boundaries.md) §2.4). |
| Root cause / interpretation | Lähde owns ([`product-boundaries.md`](./product-boundaries.md) §2.2). |
| Actor attribution / chains | Vartio owns ([`product-boundaries.md`](./product-boundaries.md) §2.3). |
| Incident records | Vartio / Lähde own. |
| Separate Jälki datastore | Forbidden by design ([`product-boundaries.md`](./product-boundaries.md) §2.1). |
| Custom UI | Not in scope. |
| `extension_record` use | None of the v0 shapes need it ([`ahti-record-mapping.md`](./ahti-record-mapping.md) §9). |
| DNS / block IO / scheduler latency probes | Deferred to v0.1+. |
| UDP `network.connect` | Deferred. |
| `cgroup` / `container` / `pod` Jälki entities | Deferred; references only. |
| Probe planner with question→template synthesis | v0 ships templates by hand; planner is deferred. |
| Agent-side read API beyond Prometheus + `/healthz` + `/status` | The agent is **not** a query surface for products. |
| Lähde / Vartio reading from the agent directly | They read from Ahti. |
| Multi-Ahti / multi-region writes | One Ahti endpoint per agent. |
| Cross-cluster agent profiles | One cluster per agent profile. |
| Mature schema evolution tooling | Single version per schema in v0; evolution machinery added when first evolution is required. |

## 3. What changes in the existing repo

This section maps the design onto today's `jalki` repo (see top-level `CLAUDE.md` for current crate layout).

### 3.1 Crates that **stay**

| Crate | Role in v0 |
|---|---|
| `jalki-common` | `#[repr(C)]` event structs and size tests remain the BPF ABI source of truth |
| `jalki-ebpf` | Three v0 probe programs: `bprm_execve` (fexit), `tcp_connect` (fexit), and one of `security_file_open` / `do_filp_open` |
| `jalki-codegen` | Runtime BPF program generation from `ProbeSpec` continues to support agent-side codegen for SDK probes |
| `xtask` | eBPF build orchestration unchanged |

### 3.2 Crates that **change shape**

| Crate | What changes |
|---|---|
| `jalki` (userspace) | New `ahti_emitter` `Emitter` impl, becomes the **only** durable emit path in production. `stdout` / `file` / `grpc-stub` emitters demoted to development helpers. New `agent_profile` loader. Retry buffer with declared bounds. New `jalki.agent.gap` and `jalki.agent.lifecycle` emission paths. |
| Existing CLI subcommands | `status` and `watch` stay (operational). `ask` is downgraded to a Lähde-bound surface (out of scope for v0; the existing implementation may stay running for backward compatibility but is not the strategic surface). `list` becomes a thin query of Ahti `definition` records — not a read of the embedded KB. `stream` reads from the agent's BPF ring buffer for local debug only; not for product consumers. |
| `knowledge/*.json` | **Moves out of the binary.** Schemas, probe plan templates, and question mappings are written to Ahti as `definition` records. v0 ships an `init` tool (under `jalki-control`) that bootstraps the `jalki` namespace with the v0 definitions listed in §1.5. The embedded JSON files become migration source material and are removed from the build path once the bootstrap is run. |
| `jalki-mcp` | The `find_probe`, `deploy_probe`, `get_events`, `probe_status` tools are reframed as **Ahti queries** + **agent-side actuator calls**. `explain_event` (interpretation) belongs to Lähde; the v0 MCP server may keep a thin compatibility shim that returns a "interpretation lives in Lähde" link. |
| `jalki-sdk-meta` / `jalki-sdk-python` | The SDK becomes a Jälki **client** to Ahti (read evidence) and to the agent (deploy probes via the control protocol). The wire protocol between SDK and agent stays useful for short-window operational tools; the durable data path is Ahti. |
| `eval/oracle/` | Adds Ahti-binding contract tests: every emitted record validates against the relevant `definition`; producer_id stamping matches binding rule; gap records are emitted on the synthetic outage scenario. |

### 3.3 New work in v0

| Work | Owner |
|---|---|
| `ahti-client` Rust crate (in `jalki/` or shared) | Authenticated, retrying Ahti producer; one impl, used by both `jalki-agent` and `jalki-control` |
| `jalki-control` binary | Writes definitions, references, and per-node agent profiles to Ahti. CLI: `bootstrap` (write v0 definitions), `set-profile <node>` (write agent_profile entity_version), `list-profiles`, `show <record_id>` |
| Agent profile loader | Cold-start from local file + steady-state from Ahti `entity_version` |
| Retry buffer | Bounded, with declared loss policy; metric counters |
| Gap emission | On overflow / restart / clock jump / ring buffer overflow |
| Capability snapshot | Built on start; written as `entity_version` |
| Schema generation from `jalki-common` event structs | The Rust source is the source of truth; a `cargo run -p jalki-sdk-meta -- emit-ahti-definitions` command emits JSON Schema payloads ready for `jalki-control bootstrap` |
| Oracle contract tests | See §3.2 last row |

### 3.4 Things that move **out** of Jälki

| Function | Moves to |
|---|---|
| Root cause / "interpretation" in `jalki ask` | Lähde |
| Actor attribution / chains | Vartio |
| Long-term storage and query of events | Ahti |
| Dashboards / alert rules | Lähde and friends |
| Question→class matching beyond a minimal v0 shim | Lähde |

## 4. Acceptance criteria for v0

v0 ships when **all** of the following are true:

1. A Jälki agent deployed on a Linux 6.x node attaches the three v0 probes, authenticates to Ahti, and writes valid records for at least the three v0 occurrence types and the two v0 internal events.
2. Records are rejected by Ahti's schema validation when the agent writes a malformed payload (proves validation is wired up, not silently skipped).
3. The agent emits a `jalki.agent.gap` occurrence after a synthetic Ahti outage longer than the retry buffer's `max_age_seconds`, with `cause = "ahti_unreachable"` and `gap_start`/`gap_end` covering the outage window.
4. The agent emits a `jalki.agent.gap` after a synthetic BPF ring buffer overflow.
5. The agent emits a `jalki.agent.lifecycle` on attach, capability snapshot write, and detach.
6. A second agent on a second node produces records with a distinct `producer_id` and Ahti correctly stamps it.
7. The `jalki-control bootstrap` command, run once, writes all v0 definitions listed in §1.5 to Ahti and is idempotent on second run (a second run does **not** create duplicate latest-versions).
8. The `agent_profile` `entity_version` for a node is the agent's actual configuration: changing the profile via `jalki-control set-profile` causes the agent to pick up the change on its next poll / push interval.
9. Oracle tests for the bindings above pass.
10. The repository's `CLAUDE.md` is updated to reflect the new architecture and the `knowledge/*.json` files are either removed or marked as bootstrap-only.

## 5. Consolidated open questions

These are deliberately surfaced for explicit decision before implementation begins. Each was raised in one of the per-area docs and is collected here.

### 5.1 From the design as a whole

- **Q1.** Default authentication mechanism for v0: mTLS vs. Kubernetes projected service account token. *Recommendation: mTLS for the agent; projected SA token as a v0.1 alternative for in-cluster deployments.*
- **Q2.** Probe deployment dispatch model: agent pulls `agent_profile` from Ahti on a poll interval, or control plane pushes via a side-channel gRPC and Ahti is system-of-record-only. *Recommendation: pull model for v0 — fewer moving parts; Ahti is the dispatch path as well as the audit path.*
- **Q3.** URI scheme set for kernel hook / BTF / container references. *Recommendation: adopt the schemes listed in [`ahti-record-mapping.md`](./ahti-record-mapping.md) §6.2 verbatim for v0 and register them as a Jälki vocabulary term.*

### 5.2 From `runtime-evidence-model.md`

- **Q4.** File-open source mechanism: LSM `security_file_open` vs. fexit on `do_filp_open`. *Recommendation: LSM hook when CONFIG_BPF_LSM=y is available (cleaner semantics, deny vs. allow is explicit); fallback to fexit `do_filp_open` when not. The capability snapshot records which path the agent took.*
- **Q5.** argv capture default: `hash_only` (proposed) vs. raw `argv` (opt-in only). *Recommendation: `hash_only` default; raw `argv` requires explicit operator opt-in per profile.*
- **Q6.** Whether Jälki **MAY** emit lightweight `container` / `pod` `entity_version` records when no Kubernetes producer is present. *Recommendation: no for v0 — references only.*
- **Q7.** `count`-coalesced `tcp_retransmit` occurrences in v0. *Recommendation: deferred to v0.1; v0 emits one occurrence per retransmit, head-sampled.*
- **Q8.** Endpoint `reference` records for network connects in v0. *Recommendation: deferred to v0.1.*

### 5.3 From `probe-definitions.md`

- **Q9.** Confirm `vocabulary_term` as the `definition_kind` for probe plan templates, sampling policies, and question mappings. *Recommendation: yes — templates are named reusable references, not state-tracked entities.*
- **Q10.** Whether question-mapping logic stays in Jälki for v0 or moves immediately to Lähde. *Recommendation: keep a minimal v0 shim in the agent's `ask` CLI so existing users are not broken, but mark it deprecated and surface a pointer to Lähde when Lähde lands.*
- **Q11.** How operators introspect "what's deployed on which node" — Ahti query of `agent_profile` `entity_version` vs. agent-local read-only API. *Recommendation: Ahti query is canonical; agent's `/status` endpoint is operational convenience only and reports what is currently attached locally.*

### 5.4 From `local-agent-state.md`

- **Q12.** Retry buffer default sizing. *Recommendation: 256 MB / 1,000,000 records / 600 s, declared in `agent_profile_default_v0`.*
- **Q13.** Whether `block_with_backpressure` is a v0 option. *Recommendation: no — v0 is `emit_gap_and_drop_oldest` only. Backpressure mode is post-v0 once we understand the operational profile.*
- **Q14.** Whether resumable writes (idempotency via `logical_key` on occurrences) are in v0. *Recommendation: no — v0 relies on at-least-once + gap records. Idempotency is added when at-least-once duplicate volume becomes a real problem.*

## 6. Implementation implications

This section names what the first round of implementation PRs will touch. **No implementation code in this pass** — these are pointers for the next conversation.

### 6.1 New code paths (Linux-only)

- `jalki/src/ahti.rs` — Ahti client wrapper: connection management, mTLS / token auth, retry buffer, schema-ref pinning cache, metrics.
- `jalki/src/profile.rs` — Agent profile loader (cold + steady).
- `jalki/src/gap.rs` — Gap detection (retry overflow, ring buffer overflow, restart, clock jump) and `jalki.agent.gap` emission.
- `jalki/src/lifecycle.rs` — Lifecycle event emission.
- `jalki/src/probes/exec.rs` — New `Probe` impl for `bprm_execve` exec.
- `jalki/src/probes/file_open.rs` — New `Probe` impl for `security_file_open` (with fallback).
- `jalki-common` additions — `ProcessExecEvent`, `FileOpenEvent` `#[repr(C)]` structs + size tests + `aya::Pod` impls.
- `jalki-control/` — New binary crate. Subcommands: `bootstrap`, `set-profile`, `list-profiles`, `show`.
- `jalki-sdk-meta` — New `emit-ahti-definitions` subcommand: walks the v0 schema list and emits JSON Schema payloads ready for `jalki-control bootstrap`.

### 6.2 Code paths that shrink or move

- `jalki/src/emit/stdout.rs` and `jalki/src/emit/file.rs` — Demoted to dev-only. Keep working but document them as non-production.
- `jalki/src/emit/grpc.rs` — Removed (stub) or rewired as the Ahti gRPC transport if Ahti's wire protocol is gRPC.
- `jalki/src/knowledge.rs` and `knowledge/*.json` — The compile-time KB becomes bootstrap material. After `jalki-control bootstrap` succeeds, the `include_str!` path is removed.
- `jalki/src/cli/ask.rs` — Keep working as a v0 shim; mark as legacy with a tracing warning that points to Lähde.

### 6.3 Tests

- `eval/oracle/` — New cases:
  - **Producer binding** — agent writes with payload `producer_id` ≠ bound; Ahti rejects; agent surfaces the rejection.
  - **Gap on Ahti outage** — synthetic outage longer than `max_age_seconds`; expect a `jalki.agent.gap` with `cause = "ahti_unreachable"`.
  - **Gap on ring buffer overflow** — synthetic load exceeding ring buffer; expect a `jalki.agent.gap` with `cause = "ringbuffer_overflow"`.
  - **Schema validation** — agent writes malformed payload; Ahti rejects; agent does not silently drop.
  - **Bootstrap idempotence** — `jalki-control bootstrap` run twice; second run produces no duplicate latest-versions.
  - **Capability snapshot lineage** — every occurrence has the snapshot in `lineage_refs`.
- `jalki-common` — Size tests for new event structs.
- `jalki` integration — Authenticated round trip against a local Ahti instance.

### 6.4 Build / deployment

- Helm chart `helm/jalki/`: add `jalki-control` Deployment (run once at install time as a Job for `bootstrap`; long-running for `set-profile` if push model is chosen). Per-node DaemonSet remains for agents.
- Helm values surface the Ahti endpoint, authentication choice, and `agent_profile` initial overrides.
- Macos dev: continue to support `cargo check -p jalki-common -p jalki-sdk-meta -p xtask` and oracle tests; Ahti-emitter integration tests are Linux-only.

### 6.5 Documentation

- Top-level `CLAUDE.md`: add a one-paragraph "v1 is Ahti-bound; see `docs/jalki/`" pointer.
- `README.md`: shift the "what you get" example to show an Ahti `occurrence` shape rather than a FALSE Protocol Occurrence (note: in this architecture, the Ahti `occurrence` carries the FALSE Protocol's role).

## 7. What this design does **not** decide

The following are out of scope for this design pass and are expected to be resolved in their own design rounds:

- Lähde's interpretation surface (how it consumes Jälki evidence and what it emits back into Ahti as `derived` records).
- Vartio's chain assembly (how it joins Jälki evidence with deployment / CI / SCM evidence into Actor chains).
- Syvä's enforcement model (and whether Jälki provides a closed-loop feedback channel into Syvä for telemetry on enforcement decisions).
- Cross-cluster federation (multiple Ahti instances; how a single Jälki control plane spans them).
- Long-term schema evolution policy (compatibility classes, deprecation cadence).
- Frontier-model interpretation layered on Lähde (this is product, not protocol).

## 8. The design sentence (recap)

> *Jälki observes runtime evidence. Ahti stores it. Vartio and Lähde interpret it. Syvä enforces later.*

If a future change to v0 contradicts this sentence, the change is wrong.
