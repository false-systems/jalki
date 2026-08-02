# Deploying jälki on Kubernetes

The Helm chart that used to live here was removed. It predated ADR-0003
(native Vartio sink) and deployed a broken agent: an empty ClusterRole
against the mandatory k8s-enrichment watch, a Service for the retired MCP
port 7777, a 256Mi memory limit under the 128MiB retry buffer, and an image
tag (0.1.0) that CI never publishes. Nothing compared it to what actually
runs, and it drifted until it could not have worked at all.

**The deployment authority is false-infra: `apps/jalki/`.** That manifest
set is what runs in the live cluster — DaemonSet with the correct RBAC for
pod-binding enrichment, the published image tags, and resource limits sized
for the retry buffer. Deploy from there; do not resurrect a parallel chart
here without wiring a drift check against the live spec first (see the
history of `scripts/helm-drift-check.sh`, removed together with the chart).
