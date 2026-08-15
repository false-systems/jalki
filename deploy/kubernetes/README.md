# Deploying jälki

```bash
# 1. create the ingress token your sink expects
kubectl create namespace jalki
kubectl create secret generic jalki-vartio-token \
  --namespace jalki --from-literal=ingress-token='...'

# 2. edit the CHANGE-ME values in jalki.yaml, then
kubectl apply -f deploy/kubernetes/jalki.yaml

# 3. confirm it is actually collecting, not merely running
kubectl -n jalki logs ds/jalki | grep -iE 'spool|self-shedding|observability'
```

`jalki.yaml` is the deployment we run, with our site-specific values replaced
by `CHANGE-ME`. It is **checked against the live spec in CI** — see
[Why this file is trustworthy](#why-this-file-is-trustworthy).

## What you must change

| value | why |
| --- | --- |
| `JALKI_CLUSTER` | producer identity on every record |
| `JALKI_VARTIO_ENDPOINT` | where evidence is delivered. `http://` is for a Vartio in the SAME cluster; a remote Vartio must be `https://` — the sink then does TLS against the platform trust store (public CAs work; a bearer token over cleartext across a network you don't own is a published token) |
| `JALKI_NAMESPACES` | **scope this deliberately** — unscoped is the whole-node kernel firehose |
| `jalki-vartio-token` Secret | bearer token for the sink |
| `nodeSelector` | images are published for arm64 and amd64 |
| `image` | pin a tag or digest you control |
| `resources` | size against your own measurements |

## What you must not remove

Each of these fails in a way that looks like something else:

- **`pod-security.kubernetes.io/enforce: privileged`** on the namespace — at
  `baseline` or `restricted` the pod is rejected, which reads as a scheduling
  problem.
- **`privileged: true` + `runAsUser: 0`** — the image base is distroless
  `:nonroot`; without uid 0 the effective capabilities are cleared at exec and
  BPF map creation fails `EPERM` *even in a privileged pod*.
- **`dnsPolicy: ClusterFirstWithHostNet`** — with `hostNetwork` the default
  keeps the host's `resolv.conf`, so in-cluster Service names never resolve.
  This presents as the sink being permanently unreachable.
- **`hostPath` mounts for bpffs / debugfs / btf / cgroupfs** — without btf,
  CO-RE relocation fails; without cgroupfs, k8s enrichment cannot resolve
  `cgroup_id → container` and unbound evidence is dropped at the source.
- **The probe split.** `/healthz` consults nothing; `/readyz` reports whether
  evidence is *flowing*. Pointing liveness at anything sink-aware means a sink
  outage restarts the agent, which is how you lose the buffer you were holding.
  Pointing either at `/metrics` runs a full Prometheus encode per probe and
  makes the two probes incapable of reporting different things.
- **`JALKI_SPOOL_PATH` + the spool volume** — the spool is **off** unless the
  path is set. Without it, a restart during a sink outage destroys exactly the
  evidence that outage produced.

## Verifying it works

jälki states its own configuration at startup. These lines are the fastest way
to know what is actually armed — faster and more reliable than reading the
manifest back:

```
resolved RuntimeSubjectV1 node identity from Kubernetes Node UID identity=k8s-node-uid:...
backlog spool armed: buffered evidence survives a restart path=... existing_bytes=0
self-shedding armed: ... limit_bytes=1073741824 source=Cgroup("/sys/fs/cgroup/...")
observability server listening on :9090 (/metrics, /healthz, /readyz)
```

If you see `backlog spool OFF (set JALKI_SPOOL_PATH)` or `self-shedding OFF`,
the agent is running without the protection you think you configured. If the
identity line is a warning instead (`RuntimeSubjectV1 disabled`), process
identity is off — usually the `nodes: get` RBAC in this manifest was removed.

**A `started DEGRADED` warning is honest, not broken.** Kernels differ, and a
probe the eBPF verifier rejects on YOUR kernel is skipped rather than fatal
(the daemon refuses to start only when NO probe attaches). The warning names
the skipped probes; their evidence types are then **absent — which downstream
must read as no-coverage, never as nothing-happened**. Known case: stock
Ubuntu-class kernels reject `security_file_open` (jalki#87), so file evidence
is unavailable there today. There is no metric for the degraded state yet —
check the startup log line until there is; the first real deployment outside
our own clusters started exactly this way, by design.

The three HTTP paths answer differently, and that is worth checking once:

```bash
kubectl -n jalki port-forward ds/jalki 9090:9090
curl -s localhost:9090/healthz   # ok
curl -s localhost:9090/readyz    # queued_batches=0 ... status=ok
curl -s localhost:9090/metrics   # Prometheus registry dump
```

## What to alert on

jälki exports Prometheus metrics on `:9090/metrics`. Five of them cover every
failure mode we have seen in production; each threshold below has fired for a
real incident, not a guess. Alerting on anything less means finding out from
pod logs, later.

| Alert when | Why |
| --- | --- |
| `increase(jalki_ring_buffer_drops_total[15m]) > 0` | Kernel events overwrote the eBPF ring buffer before userspace drained it — the one loss nothing downstream can reconstruct or even describe. Any nonzero value is real. |
| `jalki_retry_oldest_age_seconds > 300` | Evidence has been undeliverable for 5+ minutes: the sink is down or refusing. Pairs with `/readyz` going NotReady — visible pressure, not a restart. |
| `jalki_spool_bytes > 0.8 * JALKI_SPOOL_MAX_BYTES` | The on-disk mirror is filling; when it caps, the next stop under continued outage is shedding. You want the warning while there is still budget. |
| `jalki_binding_cache_hit_ratio < 0.9` for 15m | Kubernetes enrichment is degrading, and unbindable evidence is dropped **at the source** by design. Expect a dip after agent restarts while caches warm (~15 min); sustained low is real. |
| `jalki_memory_ceiling_no_shed == 1` for 10m | The precise doomed condition (jalki#76): memory is over the shedding watermark AND dropping the entire retry buffer would not get back under it. Shedding cannot save the agent; an OOM kill is coming. This alert is the off-node copy of the state that the OOM it predicts will otherwise destroy. |

Two things deliberately **not** worth alerting on:

- `jalki_unbound_dropped_total_total` with `reason="host_process"` — that is the
  agent correctly refusing to attribute host-level noise to workloads. We
  alerted on the metric's name once; the metric's labels are the metric.
- Raw memory usage. The binary runs jemalloc as its allocator, so the working
  set stays flat and returns freed pages to the OS; no `MALLOC_*` tuning is
  needed, and a steady-state plateau is not a leak. The ceiling gauge above is
  the memory signal that means something.

## Why this file is trustworthy

A Helm chart used to live in `helm/`. It was retired not because it was broken
but because it was a **second, unenforced source of truth** — it agreed with
the live spec by hand and by luck, and nothing compared them. A copy that is
obviously stale gets ignored; one that is almost right gets trusted. The full
story is in [`helm/README.md`](../../helm/README.md).

This file exists only because it is mechanically checked. Our GitOps repo runs
a drift check that fetches this manifest and compares its **structural
surface** — security context, host namespaces, volumes, RBAC verbs, ports,
probe paths, and the names of load-bearing env vars — against the spec that is
actually deployed. Site-specific values are expected to differ and are ignored.

If the check fails, one of the two changed and the other did not.

**If you are deploying jälki and something here is wrong or missing, please
open an issue.** This manifest is only as good as the drift check plus the
people who try it.
