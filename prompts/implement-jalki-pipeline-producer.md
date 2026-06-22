# PROMPT — Implement jälki's Plane B (kernel-evidence producer for Vartio)

> **For:** an implementation agent (Codex/Claude) working in `false-systems/jalki` (Rust) and
> `false-systems/vartio` (Elixir). **Goal:** turn jälki from a standalone kernel-observability
> framework into a *pipeline producer* that feeds runtime evidence to Vartio via Polku.
>
> This prompt is self-contained. Read it fully before writing any code. If you have the
> `ebpf`, `qa`, `rust-infra`, `dev-practices`, and `git-workflow` skills, use them — this prompt
> embeds their key constraints so it works either way.

---

## 0. TL;DR — the five tasks, in dependency order

| # | Task | Repo | Size | Blocks |
|---|------|------|------|--------|
| 1 | **Node-local `cgroup → container → pod` enrichment** | jalki | L (linchpin) | 2,3,4 |
| 2 | **`process.exec` probe** (`bprm_execve` fexit) | jalki | M | 4 |
| 3 | **Polku→Vartio `EvidenceSink`** (neutral emission) | jalki | S–M | 4 |
| 4 | **`VartioCore.Importer.Jalki`** + SourceAdapter ingress | vartio | M | — |
| 5 | **gap / lifecycle / retry buffer + interpretation firewall** | jalki | M | — |

Do them roughly in this order. 1 gates everything (Vartio **drops** unbound evidence). 2 and 3
can proceed in parallel after 1. 4 needs 1–3's output shape. 5 hardens.

**The end-to-end goal:**
```
kernel → eBPF probe → enrich (cgroup→pod) → neutral Occurrence → EvidenceSink
       → Polku → Vartio SourceAdapter → Importer.Jalki.normalize → ObservedEvent
       → chains → Vartio writes Ahti
```
jälki **never writes to Ahti**. Vartio interprets and writes.

---

## 1. Context you MUST absorb first

### 1.1 Read these, in order
1. `docs/jalki/adr/0002-evidence-through-polku-to-vartio.md` — **the authoritative architecture.** D1–D7.
2. `CLAUDE.md` (root) — crate layout, build commands, conventions, known constraints.
3. `AGENTS.md` — agentic dev lane + change rules.
4. `jalki/src/probe.rs` — the `Probe` trait (real signature; not what older docs show).
5. `jalki-evidence/src/{event,normalize,evidence,sink}.rs` — the capture→output layer.
6. `jalki/src/probes/tcp_connect.rs` + `jalki-ebpf/src/tcp_connect.rs` — the probe pattern to mirror.
7. In the **vartio** repo: `apps/vartio_core/lib/vartio_core/importer/tetragon.ex` — **your template for Task 4**, and `importer.ex`, `importer_registry.ex`, `importer/manifest.ex`, `observed_event.ex`, `resource.ex` (`ResourceRef`), `apps/vartio_runtime/lib/vartio_runtime/source_ingress.ex` + `source_adapter.ex`.

### 1.2 The topology (do not violate)
- `jälki → Polku → Vartio → Ahti`. jälki MUST NOT authenticate to or write to Ahti. No `AhtiSink`.
- jälki has **two planes off one capture engine**:
  - **Plane A (direct/interpreted):** `ask`/`watch`/`stream`/`list`, MCP, SDK, the embedded knowledge base. Interpretation **ON**. *Keep it; do not demote it.*
  - **Plane B (neutral pipeline):** capture → normalize → `EvidenceSink` → Polku → Vartio. Interpretation **OFF**.
- **Interpretation firewall (Task 5):** Plane B evidence must be neutral — no product severity, no
  `OccurrenceError.why_it_matters`/`possible_causes`. Vartio interprets. The KB-driven interpretation
  stays on Plane A only.

### 1.3 Gotchas already discovered (save yourself the pain)
- **`false-protocol` is vendored** in-repo at `false-protocol/` (recovered from `ahti@7bd55c8^`).
  Do **NOT** repoint to Polku's `false-protocol` — it's a *different, incompatible* shape (nested
  `context`, `data: Value`, no `NetworkEventData`/`ProcessEventData`/`labels`/`new_id`/`in_cluster`).
- **`jalki-codegen` is a frozen prototype** — works but no kernel-in-the-loop verifier test, leaks
  `Ebpf` via `std::mem::forget`. Do not build Task 2 on top of codegen; write a real batteries-included
  probe (the `tcp_*` pattern). If you touch codegen, add a verifier test first.
- **`jalki-evidence` is aya-free on purpose** (direct path-dep on `jalki-common` without the
  `userspace` feature) so it builds/tests on macOS. **Keep it aya-free.** Do not add `aya` or k8s
  clients to it. Enrichment (Task 1) and the sink (Task 3) live in the `jalki` crate, not here.
- **`jalki-common` is `no_std`** and shared with the kernel. Every event struct is `#[repr(C)]`,
  8-byte aligned, with a **mandatory size test** locking the BPF ABI, and an `aya::Pod` impl under
  `#[cfg(feature = "userspace")]`.

---

## 2. The cross-repo contract (Vartio is the consumer)

Vartio's importers parse a producer's **native event shape** (pushed in), are **pure** (no IO), and
emit `[%VartioCore.ObservedEvent{}]`. The non-negotiables jälki's evidence must satisfy:

- **Binding is the heart.** Vartio's `strong_binding?/1` requires `pod.uid` **or** `container.id`.
  Evidence without it → `{:error, :unbound_runtime_evidence}` → **dropped as noise.** This is *why*
  Task 1 gates everything.
- **Correlation-key vocabulary** (exact atoms): `:k8s_pod_uid`, `:k8s_container_id`, `:k8s_namespace`,
  and optional `:github_run_id` (read from the ARC runner-pod label `actions.github.com/run-id` —
  the join to the GitHub Actions chain root).
- **Resource ref.** Tetragon uses `%{kind: :executable, id: binary}`. For jälki:
  - `process.exec` → `%{kind: :executable, id: <exe path>}`
  - `tcp.connect` → `%{kind: :network_endpoint, id: "<dst_ip>:<dst_port>"}`
- **Redaction at source.** Never ship raw argv — `argv_hash` (`"sha256:…"`) only. Never ship secret-
  bearing payloads.
- **`observed_at` ≠ `ingested_at`.** Preserve the kernel observation time; never backfill.

**Decision (Task 4): write a NEW `VartioCore.Importer.Jalki`**, do not extend `Importer.Tetragon`.
jälki's occurrence types (`kernel.tcp.connect`, `kernel.process.exec`) are a different family with
their own `schema_ref`/`evidence_fields`. Mirror Tetragon's *discipline*, not its module.

---

## 3. Repo map, build & test

### 3.1 jälki crates
```
false-protocol/   vendored FALSE Protocol types (Occurrence, Severity, …)
jalki-common/     no_std #[repr(C)] event structs + ABI size tests (shared with kernel)
jalki-evidence/   aya-free: KernelEvent decode, normalize→Occurrence, EvidenceBatch, EvidenceSink
jalki-ebpf/       eBPF programs (bpfel-unknown-none target; NOT a workspace member)
jalki/            userspace daemon+lib: Probe trait, loader, reader, runtime, IPC, CLI, MCP wiring
jalki-codegen/    runtime BPF gen from BTF (frozen; avoid)
jalki-sdk-meta/   SDK source of truth
eval/oracle/      standalone contract tests (NOT in workspace)
```

### 3.2 Build order (matters)
```bash
cargo run -p xtask -- build-ebpf [--release]   # eBPF FIRST — needs nightly + Linux
cargo build -p jalki                            # userspace — needs Linux (aya)
```

### 3.3 What builds where
- **macOS (no aya):** `false-protocol`, `jalki-common`, `jalki-evidence`, `jalki-sdk-meta`, `xtask`,
  `eval/oracle`. Use these for fast unit-test loops.
  ```bash
  cargo test -p jalki-evidence
  cargo test -p jalki-common            # size tests
  cargo test --manifest-path eval/oracle/Cargo.toml
  ```
- **Linux full build:** the aya crates (`jalki`, `jalki-codegen`, `jalki-mcp`). Use the Lima VM
  `ubuntu`. **Set `CARGO_TARGET_DIR` to a VM-local path** (e.g. `/home/<user>/jalki-target`) or you
  corrupt the host macOS `target/`.
- **Kernel-in-the-loop** (probe + enrichment) requires a real Linux kernel ≥5.5 with BTF + root /
  `CAP_BPF`+`CAP_PERFMON`. Run in Lima or a CI Linux runner.

### 3.4 vartio
Elixir umbrella (`apps/vartio_core`, `apps/vartio_runtime`, `apps/vartio_ahti_client`).
```bash
mix deps.get && mix compile
mix test                              # ExUnit
mix test apps/vartio_core/test/.../importer/jalki_test.exs
```

---

## 4. Conventions & guardrails (apply throughout — from dev-practices / rust-infra)

- **No `.unwrap()`/`.expect()` in library/userspace code.** Propagate with `?`; add context. `anyhow`
  for binary entry points, `thiserror` for library error enums. eBPF code is the only `unsafe` zone —
  document why each block is correct.
- **Errors are data.** Extend `SinkError`/`ProbeError` variants rather than stringly-typed errors.
  Distinguish retryable (`Unavailable`/`Timeout`/`Backpressure`) from terminal (`Rejected`/
  `Unauthorized`/`InvalidRecord`) — never collapse them.
- **Make illegal states unrepresentable.** Enrichment result is an enum, not a bag of `Option`s with
  implicit rules (e.g. `Binding::Bound { pod_uid, container_id, .. } | Binding::Unbound`).
- **Fail fast at boundaries.** Validate config at startup (e.g. missing node name, no k8s access) and
  hard-fail, not at runtime per-event.
- **`no_std` stays `no_std`.** Don't pull std into `jalki-common`/`jalki-ebpf`.
- **Never log secrets/raw payloads/argv.** (AGENTS.md change rule.)
- **`tracing`, not `println!`,** in library code. Structured fields, log at boundaries, thread a
  correlation id.
- **Don't hold a lock across `.await`.** Use tokio sync primitives; prefer restructuring.
- **Boring deps.** For the k8s client prefer `kube`/`k8s-openapi` (well-maintained). Justify any new dep.

---

## 5. The tasks

### TASK 1 — Node-local `cgroup → container → pod` enrichment  *(linchpin)*

**Goal.** Given a kernel event carrying `cgroup_id` (and `pid`), resolve `container_id`, `pod_uid`,
`namespace`, `service_account`, and pod labels (incl. the ARC run-id), so Plane B evidence is
**strongly bound**. Unbound events must be representable and handled (drop-with-metric or emit
unbound for Plane A only — see acceptance).

**Where.** New module/crate in `jalki` (e.g. `jalki/src/enrich.rs` or a `jalki-enrich` crate).
**Not** in `jalki-evidence` (keep that aya-free / no k8s client). The enriched binding attaches to the
`EvidenceRecord` *before* it reaches the sink.

**Design (recommended — confirm before deviating):**
- **`cgroup_id → container_id`:** the kernel cgroup id equals the cgroupfs directory inode. Maintain a
  cache by scanning `/sys/fs/cgroup` (and/or reading `/proc/<pid>/cgroup`), matching `st_ino ==
  cgroup_id`, and parsing the container id from the leaf (`cri-containerd-<id>.scope`,
  `docker-<id>.scope`, `crio-<id>.scope`). Capture `cgroup_id` in eBPF via `bpf_get_current_cgroup_id()`.
- **`container_id → pod metadata`:** run a **K8s watch** (`kube`) over pods with
  `fieldSelector=spec.nodeName=$NODE_NAME`; build `container_id → {pod_uid, namespace,
  service_account, labels}` from `pod.status.containerStatuses[].containerID`. Refresh on watch events.
  (Alternative: CRI gRPC `ListPodSandbox`/`ListContainers`. Pick one; document why.)
- **Cache:** bounded LRU with declared size (agent config), Prometheus gauges for size + hit ratio.
- **Provenance (ADR-0002 §D5 / `local-agent-state.md` §6):** `evidence_level = observed` when the
  lookup is deterministic and fresh; `derived` when served from a possibly-stale cache.

**Rust shape (illustrative):**
```rust
pub enum Binding {
    Bound {
        container_id: String,
        pod_uid: String,
        namespace: String,
        service_account: Option<String>,
        labels: BTreeMap<String, String>,   // includes actions.github.com/run-id when present
        provenance: Provenance,             // Observed | DerivedFromCache
    },
    Unbound { reason: UnboundReason },       // HostProcess | CacheMiss | NoCgroup
}

#[async_trait] // or a sync resolve backed by an internally-synchronized cache
pub trait Enricher: Send + Sync {
    fn resolve(&self, cgroup_id: u64, pid: u32) -> Binding;
}
```
Wire it into the reader→sink path in `jalki/src/runtime.rs` so each record gets a `Binding` before
batching. Add the binding to the record as `correlation_keys` (`k8s_pod_uid:…`, etc.) + payload/labels
matching §2.

**Tests (qa — pyramid):**
- *Unit (host-portable):* cgroup-path parsing (containerd/docker/crio/systemd-slice forms, hostproc,
  malformed) — `cgroup_path_parses_containerd_id`, `host_process_yields_unbound`. Table-driven.
- *Unit:* cache provenance — fresh→Observed, stale→DerivedFromCache; eviction emits the right metric.
- *Integration (Linux/Lima):* against a live kubelet/CRI or a fake CRI server — `resolve_binds_known_pod`,
  `resolve_unknown_container_is_unbound`.
- Mock at the boundary (CRI/K8s API), not the parser.

**Acceptance:**
- A TCP-connect event from a pod-bound process gains `k8s_pod_uid`+`k8s_container_id`+`k8s_namespace`.
- A host process resolves to `Unbound` and is **excluded from Plane B** (counted in a metric), while
  still available on Plane A.
- No `.unwrap()`; cache bounded + observable; enrichment never blocks the drain loop (offload k8s/CRI
  IO; `resolve` reads cache only).

---

### TASK 2 — `process.exec` probe (`bprm_execve`, fexit)

**Goal.** Emit `kernel.process.exec` evidence — the type Vartio wants first (Tetragon parity). fexit
so you get the return value (success/failure).

**Why fexit, not fentry:** you need the result/errno of the exec. (`CLAUDE.md` fentry-vs-fexit.)

**Steps (the 4-step "Adding a Probe" flow + the evidence variant):**
1. **`jalki-common/src/events.rs`:** add `#[repr(C)] ProcessExecEvent` — fields (pad to 8-byte align):
   `pid: u32, ppid: u32, uid: u32, gid: u32, cgroup_id: u64, ret: i32, comm: [u8; 16],
   filename: [u8; N], argv_hash: [u8; 32]` (+ explicit padding). Add a **size test** and an
   `aya::Pod` impl under `#[cfg(feature = "userspace")]`. Do **not** change existing struct sizes.
2. **`jalki-ebpf/src/exec.rs`:** `#[fexit(function = "bprm_execve")]`. First line: `if
   is_self_filtered() { return Ok(()); }`. Capture pid/tgid, uid/gid, `bpf_get_current_cgroup_id()`,
   `comm` via `bpf_get_current_comm`, the binary path, and the return value. Compute `argv_hash`
   **in-kernel or in userspace** (hash only — never raw argv; AGENTS.md). Register a dedicated 4MB
   ring buffer map; wire it in `main.rs`.
3. **`jalki-evidence/src/event.rs`:** add `KernelEvent::ProcessExec(ProcessExecEvent)` + `from_bytes`
   (length-checked, `read_unaligned`). **`normalize.rs`:** map to an `Occurrence` (`source
   "jalki/process_exec"`, `type "kernel.process.exec"`). Keep it **neutral** (Plane B): set
   `process_data`, `correlation_keys`, resource ref `executable:<filename>`; **do not** add product
   severity or `OccurrenceError` enrichment here.
4. **`jalki/src/probes/exec.rs`:** `impl Probe` — `attachments` = `[Fexit { function: "bprm_execve" }]`,
   `program_name` = the `#[fexit]` fn name, `ring_buffer_map`, and `decode_event` (delegate to
   `ProcessExecEvent::from_bytes`). `to_evidence`/`probe_metadata` come from defaults.
5. **`knowledge/process.json`:** add the catalog entry (only if certain; wrong KB misleads agents).

**eBPF best-practices (ebpf skill — verifier will enforce):**
- Prefer **fentry/fexit + CO-RE** over kprobes (you're already on fexit — good; type-safe via BTF).
- Read kernel struct fields via aya's CO-RE-style helpers / `bpf_probe_read_kernel`, never raw deref —
  "invalid mem access" otherwise.
- **Stack ≤512 bytes:** the `filename`/`argv_hash` buffers are large — use a **per-CPU array map as
  scratch space**, not stack locals. Reserve+submit on the **ring buffer** (`bpf_ringbuf_reserve` /
  `submit`); ring buffer > perf buffer always.
- **Bounded loops only** (for any path copy / hashing) — `#[unroll]` or a fixed bound.
- Keep `SEC("license") = "GPL"` (aya handles this) — many helpers require GPL.
- Handle map-lookup NULL; don't sleep/alloc in the program.

**Tests:**
- *Unit (macOS):* `ProcessExecEvent` size test; `from_bytes` round-trip incl. too-short →
  `ProbeError::TooShort`; `normalize` produces neutral occurrence with the right type + resource ref.
- *Kernel-in-the-loop (Lima/CI):* load the generated/compiled object, run `/bin/true`, assert one
  `kernel.process.exec` with correct pid/comm/ret. **This is the test the codegen path lacks — make
  sure exec has it.**
- Oracle: add an event-schema case if the suite covers exec.

**Acceptance:** exec events captured on a live kernel, neutral, with `cgroup_id` for Task 1 to enrich;
argv never present in raw form; size test passes; no verifier rejection.

---

### TASK 3 — Polku→Vartio `EvidenceSink`

**Goal.** A new `EvidenceSink` impl that ships `EvidenceBatch`es to Vartio via Polku, behind the
existing seam. **Vendor-neutral** name (e.g. `PolkuSink` or `PipelineSink`) — jälki shouldn't hardcode
"vartio".

**Where.** `jalki-evidence/src/sink.rs` is fine *if* the transport client stays aya-free and optional;
if it needs heavy deps (tonic/reqwest), put the sink in the `jalki` crate to keep `jalki-evidence`
lean. Prefer the latter unless the client is trivial.

**Design (rust-infra):**
- Implement the 3 methods: `name`, `append_batch(EvidenceBatch) -> Result<AppendResult, SinkError>`,
  `health() -> HealthStatus`. Reuse the existing `encode_ndjson`/`into_occurrences()` projection.
- Map transport failures onto `SinkError` precisely: conn refused/5xx→`Unavailable`, 429→`Backpressure`,
  401/403→`Unauthorized`, 4xx/serde→`Rejected`/`InvalidRecord`, 207→`PartialFailure`, bad URL→
  `Misconfigured`. (These variants already exist.)
- Transport = Polku's library/egress (see polku repo: `polku-core`, `polku-fp`; the Tetragon adapter
  uses `polku_ahti_emitter` — for jälki the egress targets **Vartio's SourceAdapter ingress**, not
  Ahti). If the concrete Polku→Vartio wire isn't settled, **define a narrow `PipelineClient` trait**
  and ship a default impl (HTTP POST of ndjson to the Vartio ingress URL) so the sink is testable now
  and the transport can be swapped — coordinate the real wire with the polku/vartio owners.
- Select via the existing `--sink`/`--also-sink` flags (`main.rs` `sink_from_spec`). Production runs it
  inside a `CompositeSink` (so it can co-exist with `stdout`/`file` during rollout).
- **Backpressure:** the drain→sink path uses a bounded `mpsc`. On `Backpressure`/`Unavailable`, the
  retry buffer (Task 5) holds records; do not block the kernel drain indefinitely (that drops events).

**Tests:**
- *Unit (macOS):* `FakeSink`-style test for the `PipelineClient` trait — success→`AppendResult`
  accepted count; injected 429→`SinkError::Backpressure`; partial→`PartialFailure` with warnings.
- *Integration:* against a stub HTTP server asserting the posted ndjson shape matches what
  `Importer.Jalki` expects (Task 4 fixtures are the contract).

**Acceptance:** a batch round-trips to a stub ingress; every transport error maps to the correct
`SinkError`; `health()` reflects reachability; composes under `CompositeSink`.

---

### TASK 4 — `VartioCore.Importer.Jalki` (+ SourceAdapter ingress)  *(vartio repo)*

**Goal.** Normalize jälki's native evidence shape → `[%ObservedEvent{}]`, registered as a Vartio
importer. **Mirror `VartioCore.Importer.Tetragon`** exactly in discipline.

**Steps:**
1. `apps/vartio_core/lib/vartio_core/importer/jalki.ex`:
   - `@behaviour VartioCore.Importer`; implement all 6 callbacks.
   - `@namespace "vartio-jalki"`, `occurrence_types` = `["kernel.process.exec", "kernel.tcp.connect", …]`,
     `schema_ref` e.g. `"vartio.jalki.kernel.v1"`.
   - `normalize/1`: **pure** (no IO). Require strong binding (`pod_uid` or `container_id`) → else
     `{:error, :unbound_runtime_evidence}`. Emit `correlation_keys` (`:k8s_pod_uid`,
     `:k8s_container_id`, `:k8s_namespace`, optional `:github_run_id`), a typed `subject_ref`
     (`Ref.external_uri`), `ResourceRef` per §2, `observed_at`/`ingested_at` distinct, `argv_hash` only.
   - Build a validated `Manifest.new!/1` (source_key `:jalki`, provider `:jalki`, evidence_fields,
     redaction `%{fields: []}` since redaction already happened, fixtures path).
2. Register `VartioCore.Importer.Jalki` in the static `@importers` list in `importer_registry.ex`.
3. Add a `SourceAdapter` (high-rate/streaming) ingress route so jälki's Polku egress lands as
   `ProviderEvidence{namespace: "vartio-jalki", raw, source}` → `Pipeline`/`ProjectPreview` →
   Vartio writes Ahti. (Vartio's `source_ingress.ex`/`source_adapter.ex` define the contract; it's
   "adapter-pending" — wire it.)
4. **Fixtures** under the manifest's `fixtures/` path — these are the cross-repo contract; jälki's sink
   output (Task 3) must match them. The oracle/ExUnit validates against them.

**Tests (ExUnit, names as specs — qa/dev-practices):**
- `normalize/1 binds exec event with pod uid`, `normalize/1 refuses host process as unbound`,
  `normalize/1 emits github_run_id when arc label present`, `normalize/1 hashes argv (never raw)`,
  `normalize/1 sets network_endpoint resource for tcp connect`.
- Test through the importer's public contract only; use fixtures.

**Acceptance:** jälki evidence flows webhook/Polku → `Importer.Jalki` → `ObservedEvent` → chain →
Ahti write; unbound evidence refused; fixtures shared with jälki's sink tests.

---

### TASK 5 — gap / lifecycle / retry buffer + interpretation firewall

**Goal.** No silent loss (ADR-0002 §D7 / `local-agent-state.md` §5), agent observability, and a hard
guarantee that Plane B is neutral.

**Sub-tasks:**
- **Retry buffer:** bounded (declared `max_bytes`/`max_records`/`max_age_seconds`; defaults 256MB /
  1M / 600s). Loss policy `emit_gap_and_drop_oldest` (default). Prometheus fill-ratio + drop counters.
  Sits between the drain loop and the `PolkuSink`; absorbs `Backpressure`/`Unavailable`.
- **`jalki.agent.gap`:** emit on retry overflow, ring-buffer overflow, restart, clock jump, probe
  unload — with `cause`, `gap_start`/`gap_end`, `affected_probes`. Neutral occurrence on Plane B.
- **`jalki.agent.lifecycle`:** emit on attach/detach/capability-snapshot/start/stop.
- **Interpretation firewall:** ensure the Plane-B projection strips/omits the `OccurrenceError`
  `why_it_matters`/`possible_causes` and any product severity that `normalize.rs` adds for Plane A.
  Cleanest: make normalization produce a **neutral** record, and let Plane A *add* interpretation
  from the KB at read time (IPC/`ask`), rather than baking it into the record. Add a test that asserts
  a Plane-B `Occurrence` carries no interpretation fields.

**Tests (qa — deterministic, incl. failure injection):**
- `retry_buffer_drops_oldest_and_emits_gap_on_overflow`, `gap_emitted_on_ringbuffer_overflow`,
  `plane_b_occurrence_has_no_interpretation`, `lifecycle_emitted_on_attach_and_detach`.
- Make time/randomness injectable so these are deterministic (no sleeps; control the clock).

**Acceptance:** synthetic Polku outage longer than `max_age_seconds` → exactly one `gap` with the
right window; Plane-B neutrality test passes; counters exported.

---

## 6. Testing strategy (overall — qa skill)

- **Pyramid:** many unit tests (host-portable in `jalki-common`/`jalki-evidence`/parsers), fewer
  integration (enrichment vs fake CRI/K8s; sink vs stub ingress; Vartio importer vs fixtures), fewest
  kernel-in-the-loop (Lima/CI: probe load + capture).
- **Names are specs** (`thing_does_x_when_y`). One logical assertion each. Deterministic, isolated.
- **Mock at boundaries** (CRI/K8s API, Polku/Vartio ingress, clock), never the domain logic.
- **The oracle** (`eval/oracle/`) tests the contract from files — when a case fails, fix the system or
  the data, **never the test**. Add cases for new event schemas / binding rules / gap behavior.
- **Cross-repo contract = the fixtures** in Task 4. jälki sink output and Vartio importer input must
  share them.
- Run the macOS-buildable test set every loop; gate kernel/Vartio tests in CI.

---

## 7. Git workflow (git-workflow skill + repo specifics)

- **Branch first** — never commit to `main`. Naming: `feature/<area>-<desc>`, e.g.
  `feature/enrich-cgroup-pod`, `feature/probe-process-exec`, `feature/sink-polku-vartio`,
  `feature/vartio-importer-jalki`, `feature/agent-gap-retry`.
- **One concern per PR** (AGENTS.md: keep PRs small). The five tasks → ~five PRs. Task 4 is a PR in
  the **vartio** repo.
- **Conventional commits:** `feat(enrich): resolve cgroup_id→pod via kube watch`,
  `feat(probe): add bprm_execve fexit process.exec probe`, `test(enrich): cgroup path parsing table`,
  `feat(sink): PolkuSink behind EvidenceSink`, `fix(...)`, `docs(...)`. Body = what + why, not how.
- **End every commit message with:**
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- **Push:** origin is `git@github.com:false-systems/jalki.git` (SSH). Push the branch, open a PR.
  **PR body ends with:** `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
- **PR description:** What / Why (link ADR-0002) / How / Testing / Checklist. Self-review the diff first.
- Rebase on `main` before opening; `--force-with-lease` for branch updates.
- **Agent ledger** (AGENTS.md §): leave a run summary in the PR body / `agent-ledger.jsonl`.

---

## 8. Definition of Done (overall)

- [ ] Plane B path works end-to-end on a live kernel: exec + tcp.connect events, enriched, neutral,
      delivered via Polku to Vartio, normalized by `Importer.Jalki`, written to Ahti **by Vartio**.
- [ ] jälki writes **nothing** to Ahti; no Ahti creds in jälki.
- [ ] Unbound evidence is excluded from Plane B (metric), not silently emitted as noise.
- [ ] Plane A (`ask`/MCP/SDK/KB) still works unchanged; interpretation is firewalled off Plane B
      (test proves it).
- [ ] No silent loss: synthetic outage → `gap` occurrence; retry buffer bounded + observable.
- [ ] `jalki-evidence` stays aya-free (builds on macOS). `jalki-common` stays `no_std` with size tests.
- [ ] No `.unwrap()` in userspace; eBPF `unsafe` documented; verifier accepts all probes (kernel test).
- [ ] Tests green: macOS unit set, oracle, Lima kernel-in-the-loop, Vartio ExUnit. CI updated.
- [ ] Docs: update `CLAUDE.md` ("Adding a Probe" already lists steps) and the relevant
      `docs/jalki/*` bodies (runtime-evidence-model exec payload; local-agent-state enrichment now
      implemented). Each PR links ADR-0002.

---

## 9. Decisions to SURFACE, not guess

Raise these with the owner before locking them (don't silently pick):
1. **Enrichment source:** K8s API watch (`kube`) vs CRI gRPC vs cgroupfs-only. (Recommend K8s watch +
   cgroupfs inode map.)
2. **Polku→Vartio wire:** the concrete egress (HTTP POST to Vartio SourceAdapter vs Polku gRPC hub vs
   `polku-fp` library link). Coordinate with polku/vartio owners; until settled, ship behind the
   narrow `PipelineClient` trait.
3. **Unbound policy:** drop-with-metric (recommended for Plane B) vs emit-for-Plane-A-only.
4. **Where the sink lives:** `jalki-evidence` (if client is light) vs `jalki` (if it needs tonic/kube).
   Default to `jalki` to keep `jalki-evidence` aya-free and macOS-testable.
5. **argv hashing site:** in-kernel vs userspace `/proc/<pid>/cmdline`. (Userspace is simpler; note the
   TOCTOU caveat.)

---

*Architecture authority: `docs/jalki/adr/0002-evidence-through-polku-to-vartio.md`. If anything here
conflicts with that ADR, the ADR wins — and flag the conflict.*
