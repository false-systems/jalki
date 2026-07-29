#!/usr/bin/env bash
# Prove the chart can still reproduce what is actually deployed (jalki #43).
#
# false-infra/apps/jalki is the source of truth for the live spec; this chart is
# for everyone else. The two drifted far enough that the checked-in chart could
# not have worked at all — no dnsPolicy under hostNetwork, no runAsUser 0
# against a distroless :nonroot base, no cgroupfs mount, an empty ClusterRole.
# Nobody noticed because nothing ever compared them.
#
#   scripts/helm-drift-check.sh              # against the live cluster
#   scripts/helm-drift-check.sh <file.yaml>  # against a saved DaemonSet manifest
#
# Compares only behaviour-determining fields; server-populated defaults
# (creationTimestamp, terminationMessagePath, resourceVersion, …) are ignored.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELM_IMAGE="${JALKI_HELM_IMAGE:-alpine/helm:3.19.0}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# kubectl doubles as the local YAML→JSON converter, so this needs no Python YAML.
docker run --rm -v "$REPO/helm:/h" -w /h "$HELM_IMAGE" \
  template jalki ./jalki -f ./jalki/values-false-infra.yaml -s templates/daemonset.yaml \
  | kubectl create --dry-run=client -o json -f - > "$WORK/rendered.json"

if [ $# -ge 1 ]; then
  kubectl create --dry-run=client -o json -f "$1" > "$WORK/live.json"
else
  kubectl get daemonset jalki -n jalki -o json > "$WORK/live.json"
fi

normalize() {
  python3 - "$1" <<'PY'
import json, sys

ds = json.load(open(sys.argv[1]))
spec = ds["spec"]["template"]["spec"]
c = next(x for x in spec["containers"] if x["name"] == "jalki")

def source(e):
    """Render valueFrom without the fields the API server fills in itself.

    `fieldRef.apiVersion` and `resourceFieldRef.divisor` are both defaulted on
    admission, so a live object always carries them and a rendered manifest
    never does. Comparing them would report drift on every downward-API env var
    forever, which trains people to ignore this check."""
    vf = json.loads(json.dumps(e.get("valueFrom")))
    if isinstance(vf, dict):
        if isinstance(vf.get("fieldRef"), dict):
            vf["fieldRef"].pop("apiVersion", None)
        if isinstance(vf.get("resourceFieldRef"), dict):
            vf["resourceFieldRef"].pop("divisor", None)
    return "<from:%s>" % json.dumps(vf, sort_keys=True)

env = {}
for e in c.get("env", []):
    env[e["name"]] = e["value"] if "value" in e else source(e)

def probe(p):
    """httpGet without the server-populated scheme."""
    g = (p or {}).get("httpGet")
    if not g:
        return None
    return {k: v for k, v in g.items() if k != "scheme"}

print(json.dumps({
    "image": c["image"],
    "imagePullPolicy": c.get("imagePullPolicy"),
    "args": c.get("args"),
    "securityContext": c.get("securityContext"),
    "resources": c.get("resources"),
    "env": env,
    "volumeMounts": sorted([m["name"], m["mountPath"]] for m in c.get("volumeMounts", [])),
    "livenessProbe": probe(c.get("livenessProbe")),
    "readinessProbe": probe(c.get("readinessProbe")),
    "hostPID": spec.get("hostPID"),
    "hostNetwork": spec.get("hostNetwork"),
    "dnsPolicy": spec.get("dnsPolicy"),
    "imagePullSecrets": spec.get("imagePullSecrets"),
    "nodeSelector": spec.get("nodeSelector"),
    "tolerations": spec.get("tolerations"),
    "volumes": sorted(v["name"] for v in spec.get("volumes", [])),
}, indent=2, sort_keys=True))
PY
}

normalize "$WORK/rendered.json" > "$WORK/a.json"
normalize "$WORK/live.json"     > "$WORK/b.json"

if diff -u "$WORK/a.json" "$WORK/b.json" > "$WORK/diff.txt"; then
  echo "no drift: the chart reproduces the live DaemonSet"
else
  echo "DRIFT — rendered chart (-) vs live DaemonSet (+):"
  echo
  cat "$WORK/diff.txt"
  exit 1
fi
