# Jälki Runtime Evidence for Vartio — v1 Proposal

**Status:** Proposed repository contract. `RuntimeSubjectV1` support for
`process.exec` is implemented on the accompanying branch; the continuous
surfaces, receipts, and execution-binding path below remain future work.

**Canonical product meaning:** Vartio's
`docs/vartio/architecture-proposal.md`. This document owns only the Jälki
implementation boundary.

## 1. Purpose

Jälki should give Vartio a trustworthy factual account of:

- which Linux process lifetime existed;
- its observed parent, executable transitions, and placement;
- selected runtime operations it was observed performing;
- which probes and capture surfaces were actually active;
- where capture or delivery may have lost evidence.

Jälki does not decide which Actor owns a process, which authority an action
represents, whether an Operational Chain is correct, or whether absence proves
that nothing happened.

## 2. Two lanes

```text
Jälki core

continuous evidence                 dynamic interrogation
  process identity                    ask
  process lifecycle                   watch
  runtime placement                   stream
  new network connections             generated/targeted probes
  collector integrity
  IntervalReceipt
```

The continuous lane supports historical reconstruction and interval coverage.
The dynamic lane answers questions from the moment a probe successfully
attaches. It never creates retroactive coverage.

Both lanes use the existing capture, normalization, and `EvidenceSink`
boundaries. Evidence reaches Ahti only through Vartio.

## 3. Current reality

| Capability | Current state | v1 target |
|---|---|---|
| native Vartio sink | implemented | keep |
| probe attach/detach and dynamic queries | implemented | keep |
| ring-buffer drop counters | implemented for current probe families | include in surface receipts |
| `process.exec` | implemented | use canonical RuntimeSubject identity |
| `RuntimeSubjectV1` on exec | implemented on this branch | extend across lifecycle and network evidence |
| fork/exit lifecycle | not implemented | continuous surface |
| process placement intervals | point enrichment exists | explicit temporal relationships |
| TCP connect/close/retransmit | implemented | add RuntimeSubject and socket identity |
| socket create/accept provenance | not implemented | continuous surface where kernel support is adequate |
| collector epochs and positive receipts | not implemented | required for interval coverage |
| authenticated execution binding | not implemented | opt-in launcher + pidfd path |
| startup reconciliation | not implemented | enumerate and mark pre-existing processes honestly |

Missing Pod/container enrichment must eventually weaken placement resolution,
not discard otherwise admissible node-bound process evidence.

## 4. RuntimeSubjectV1

`RuntimeSubjectV1` identifies one Linux thread-group/process lifetime:

```text
RuntimeSubjectTupleV1 {
  node_identity
  boot_id
  host_tgid
  leader_start_boottime_ns
  canonicalization_version
}
```

The identifier is a versioned, domain-separated, length-delimited SHA-256 over
the complete canonical tuple. Jälki emits both the ID and source tuple so a
consumer can audit or recompute it.

Rules:

- host TGID identifies the process in the initial PID namespace;
- `task_struct.start_boottime` is read from the thread-group leader through
  BTF-resolved offsets;
- `boot_id` prevents reuse across node reboot;
- stable `node_identity` is deployment-provided; Kubernetes Node UID is the
  preferred anchor;
- mutable hostname is not silently promoted to canonical node identity;
- an incomplete tuple produces no canonical RuntimeSubject ID;
- Pod UID, container ID, cgroup ID, image, namespace, and ServiceAccount are
  relationships, not identity fields;
- `exec` changes the executable image but not the RuntimeSubject;
- a new thread group creates a new RuntimeSubject; `CLONE_THREAD` does not;
- process identity closes only when the thread group dies.

V1 is Linux-specific. Other runtime kinds must define separate versioned
contracts.

## 5. Continuous capture surfaces

Jälki should expose named, versioned surfaces instead of asking Vartio to infer
coverage from individual probe names.

### `collector_integrity/v1`

Required facts:

```text
collector start/stop/epoch
configuration generation and digest
probe attach/detach/error
kernel and BTF capability state
ring reservation failures
decode failures
queue drops
spool failures
delivery attempts/failures
sequence state
```

### `process_lifecycle/v1`

Required observations:

```text
process.fork
process.exec
process.exit
parent RuntimeSubject
```

The surface must define fork/clone/thread semantics, exec continuity, exit
closure, startup reconciliation, and every counter that can invalidate
completeness.

### `runtime_placement/v1`

Required temporal relationships when observable:

```text
RuntimeSubject contained_in cgroup
RuntimeSubject contained_in container
RuntimeSubject contained_in Pod UID
RuntimeSubject executed image digest
```

Placement changes carry `[valid_from, valid_to?)`. Names are context; immutable
UIDs identify external object instances.

### `network_new_connections/v1`

Target observations:

```text
socket.create
socket.connect
socket.accept
socket.close
```

Each event cites the RuntimeSubject observed performing the operation, a stable
socket identifier where available, network namespace, protocol, and endpoints.

This surface may support only “no new socket.connect occurrence observed.” It
cannot prove no network I/O: descriptors may predate the interval or be
inherited, duplicated, shared through `CLONE_FILES`, or transferred through
`SCM_RIGHTS`.

Credential transitions and sensitive-file surfaces are deferred until these
four foundational surfaces pass the adversarial corpus.

## 6. CaptureSurfaceDescriptorV1

Every surface version declares:

```text
surface_id and version
required hooks
optional hooks
kernel/BTF prerequisites
scope semantics
events claimed observable
explicit non-claims
loss counters and invalidation rules
clock basis
allowed negative statements
```

A probe being loaded is not enough. The descriptor plus observed attach state
and counters determine what a receipt can factually report.

## 7. IntervalReceiptV1

Jälki emits positive interval evidence:

```text
receipt_id
collector_identity and instance
failure_domain_id
node_identity and boot_id
collector_epoch
sequence identity/range
scope
active surface versions
configured and attached probes
probe/config versions and digest
interval [start,end)
clock basis and uncertainty
capture-loss counters
delivery-attempt state
collector factual state
```

Rules:

- capture loss and delivery loss remain separate;
- restart creates a new collector epoch;
- counter reset without a new understood epoch invalidates continuity;
- detach, scope change, or missing required hook splits the interval;
- a delivery attempt does not prove Vartio accepted the evidence;
- overlapping agents preserve separate failure-domain identities;
- no receipt means no positive coverage assertion.

Jälki emits the receipt as neutral evidence. Vartio composes it with consumer
acceptance and other source requirements into `IntervalCoverage`.

## 8. Startup reconciliation

If Jälki starts after processes already exist, it should:

1. attach lifecycle probes;
2. begin buffering live lifecycle events;
3. enumerate `/proc`;
4. construct RuntimeSubjects only when the tuple can be established;
5. reconcile the buffered events with the scan;
6. emit pre-existing process observations marked as discovered after start;
7. state that the earlier lifetime was unobserved.

The scan must never fabricate fork, exec, or parent history that was not
captured.

## 9. Execution binding

The preferred first integration is an opt-in `false-exec` launcher:

1. authenticate an `ExecutionDeclarationV1`;
2. create the child with `clone3(CLONE_PIDFD)` or obtain an equivalent pidfd;
3. send the declaration and pidfd to the local agent over an authenticated Unix
   socket;
4. resolve the child to its canonical RuntimeSubject;
5. emit `RuntimeBindingReceiptV1` before releasing the child to execute.

The pidfd prevents a PID-reuse race while binding. It is a live handle, not a
stored identity.

The local endpoint must validate peer credentials, declaration issuer/scope,
idempotency, replay state, and that the pidfd names a process visible to the
collector. Failure produces no strong binding.

DaemonSet-only deployments remain supported; they simply produce weaker Actor
resolution.

## 10. Adversarial acceptance

The v1 implementation must explicitly test:

```text
PID reuse
fork without exec
exec preserving identity
thread clone versus process clone
non-leader exec
process exit and late events
node reboot
container and Pod recreation
missing BTF fields
startup with pre-existing processes
missing Kubernetes enrichment
socket inheritance/duplication/transfer
collector restart and counter reset
ring-buffer loss and decode loss
delivery outage and spool exhaustion
probe detach and scope change
duplicate/out-of-order receipts
overlapping collectors
forged or replayed execution declarations
pidfd target exiting during binding
```

For each case, tests name emitted facts, omissions, receipt qualification, and
forbidden stronger claims.

## 11. Delivery plan

1. Extend RuntimeSubject identity from exec to fork/exit and parent lineage.
2. Add startup reconciliation.
3. Materialize temporal placement relationships without rejecting unbound
   process facts.
4. Define surface descriptors and collector epochs.
5. Emit IntervalReceiptV1 for collector integrity and process lifecycle.
6. Add RuntimeSubject/socket identity to network events, then accept/create as
   justified by kernel support.
7. Add the authenticated pidfd binding endpoint and `false-exec`.
8. Prove the contract through the Vartio Kubernetes/AWS vertical.
9. Package the proven machinery into false-agent later.

## 12. Boundary

Jälki's stronger job is:

> Give Vartio a trustworthy factual account of which Linux process existed,
> where it ran, which important runtime operations it was observed performing,
> and how well those facts were captured and delivered.

Jälki does not become an EDR, SIEM, broad syscall recorder, packet-capture
system, Actor oracle, authority engine, or policy/enforcement product.
