# Deploying jälki on Kubernetes

The Helm chart that used to live here was removed. **Not because it was
broken — because it was a second, unenforced source of truth.**

The deployment spec that matters lives in our GitOps repo. This chart was a
parallel copy of it, and nothing ever compared the two. It happened to agree
with the live spec on image, RBAC, namespace scope and resource limits, but
that agreement was maintained by hand and by luck. A copy that nothing checks
does not stay a copy; it becomes a second answer to the same question, and
there is no way to tell which one is current except by reading both.

That is the same failure mode as a ConfigMap mounted with `subPath`: two
things that look synchronized, with no mechanism keeping them so.

## What was actually wrong with it

One real defect: it still shipped a `Service` for MCP port 7777, which was
retired.

An earlier version of this file also claimed the chart had an empty
`ClusterRole`, a 256Mi memory limit under the retry buffer, and an image tag
CI never publishes. **Those three were wrong**, and are corrected here rather
than quietly deleted, because a public explanation that does not survive
checking is worse than none:

| earlier claim | what the chart actually had |
| --- | --- |
| empty `ClusterRole` against the mandatory k8s-enrichment watch | the deployment overlay set `k8sEnrichment: true`, so the rules rendered. Only the unused default in `values.yaml` was `false`. |
| 256Mi memory limit under the 128MiB retry buffer | `memory: 1Gi` for **both** requests and limits (requests==limits for Guaranteed QoS) — the same values the live DaemonSet runs today |
| image tag `0.1.0`, which CI never publishes | `repository: ghcr.io/false-systems/jalki`, `tag: "main"`, `pullPolicy: Always` — exactly the image running in the cluster. `0.1.0` was `Chart.yaml`'s `version`/`appVersion`, chart metadata that only becomes an image tag when the values tag is empty, which it was not. |

The chart tracked reality closely. That is what made it dangerous rather than
harmless: a stale copy that is obviously stale gets ignored, and one that is
almost right gets trusted.

## Deploying it yourself

There is currently **no deployable artifact in this repository**, which is a
gap we opened deliberately and are tracking in
[#73](https://github.com/false-systems/jalki/issues/73).

jälki needs privileged host access to function at all — `hostPID`,
`hostNetwork`, pinned BPF maps, a writable spool volume, and a read-only
Kubernetes RBAC surface for the cgroup→pod binding. Until #73 lands a
reference manifest with a drift check against the live spec, reconstructing
that from source is unfortunately the only route.

If you are deploying jälki and hit this, please say so on #73 — it moves the
priority.

## If you resurrect a chart here

Wire the drift check first, in CI, failing the build when this repo and the
live spec disagree. The retired `scripts/helm-drift-check.sh` existed but was
never wired into any workflow, which is exactly how the copies drifted. The
check is the part that matters; the chart is the easy half.
