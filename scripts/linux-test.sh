#!/usr/bin/env bash
# Run the workspace test suite on Linux.
#
# `aya` is Linux-only, so `jalki`, `jalki-codegen` and `jalki-mcp` cannot be
# compiled — let alone tested — on a macOS workstation. Without this, changes to
# the daemon crate are unverifiable locally, and CI does not cover them either:
# the Container workflow is path-filtered to Dockerfile/Cargo/jalki-ebpf, so a
# source-only PR runs nothing (false-systems/vartio#254).
#
# Uses the same rust image as the Dockerfile builder so the toolchain matches
# what ships. The cargo registry and target dir are cached in named volumes, so
# the first run is slow and later ones are not.
#
#   scripts/linux-test.sh                  # whole workspace
#   scripts/linux-test.sh -p jalki         # one crate
#   scripts/linux-test.sh -p jalki backoff # one crate, filtered
#   JALKI_CARGO_CMD=clippy scripts/linux-test.sh --workspace --all-targets
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${JALKI_TEST_IMAGE:-rust:1.97-bookworm}"

CMD="${JALKI_CARGO_CMD:-test}"

# The target dir is a shared named volume and cargo locks it exclusively, so a
# second concurrent run serialises behind the first with no output of its own.
# Refuse instead, so a wait is never mistaken for a hang.
#
# (I first wrote this comment claiming a 33-minute silent block had been
# *observed* from that lock. It had not: the container was running a test that
# hung. Guard kept, claim corrected — an unverified cause in a comment is how
# the next person misdiagnoses the same symptom.)
if [ -n "$(docker ps -q --filter "label=jalki-linux-test" 2>/dev/null)" ]; then
  echo "error: another scripts/linux-test.sh is already running." >&2
  echo "       They share a cargo target volume; a second run would block on" >&2
  echo "       cargo's lock with no output. Wait, or:" >&2
  echo "         docker ps --filter label=jalki-linux-test" >&2
  exit 1
fi

exec docker run --rm -t \
  --label jalki-linux-test \
  `# Host cgroup namespace, so /proc/self/cgroup reports a nested path the way` \
  `# it does on a CI runner rather than the bare "/" a namespaced container` \
  `# sees. Without it this rehearsal disagrees with CI about anything that` \
  `# reads that file — which it did, and CI caught what the rehearsal missed.` \
  --cgroupns=host \
  --platform linux/arm64 \
  -v "$REPO:/w" -w /w \
  -v jalki-linux-test-registry:/usr/local/cargo/registry \
  -v jalki-linux-test-target:/w/target-linux \
  -e CARGO_TARGET_DIR=/w/target-linux \
  "$IMAGE" \
  sh -c 'if [ "$0" = clippy ]; then rustup component add clippy >/dev/null 2>&1; fi; exec cargo "$@"' \
  "$CMD" "$CMD" "$@"
