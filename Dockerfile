# jälki — eBPF daemon image (daemon + MCP server + SDK codegen + eBPF object).
#
# Build from the repo root (false-protocol is vendored in-repo, so the root is
# a self-contained context):
#
#   docker build -t ghcr.io/false-systems/jalki .
#
# Stages:
#   rust-base   the pinned stable toolchain (1.97.1) every stage starts from.
#               Not 1.97.0: that release miscompiles on x86_64
#               (rust-lang/rust#159035, fixed in 1.97.1), and the amd64
#               binaries this image ships are built with it.
#   chef        adds cargo-chef.
#   bpf-linker  compiles bpf-linker, in parallel with chef; only its binary
#               is used.
#   planner     reduces the workspace to recipe.json (manifests + Cargo.lock).
#   ebpf        the dated nightly from jalki-ebpf/rust-toolchain.toml plus
#               bpf-linker, then the eBPF object from xtask/, jalki-common/
#               and jalki-ebpf/ only. A userspace-only change does not rebuild
#               it, and BuildKit runs it in parallel with the builder.
#   builder     cooks the dependencies from the recipe, then builds the
#               workspace crates. A code-only change reuses the cooked layer
#               and recompiles only the workspace crates. The nightly and
#               bpf-linker are not in its layers, so a CI build that only
#               needs this stage does not import them from the cache.
#   runtime     distroless cc, nonroot.
#
# Bases are pinned by digest; Dependabot (.github/dependabot.yml) proposes
# digest refreshes.
FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS rust-base

# ── chef ───────────────────────────────────────────────────────────────────
FROM rust-base AS chef
# Same cargo-chef version as ahti.
RUN cargo install cargo-chef --version 0.1.78 --locked
WORKDIR /build

# ── bpf-linker: the final BPF link for the eBPF build ──────────────────────
FROM rust-base AS bpf-linker
# bpf-linker is PINNED: 0.11.0 (released 2026-08-12) requires system LLVM via
# llvm-config, which this stage does not carry, and the unpinned install broke
# every Container build within a day of the release — main and all branches at
# once. Same lesson as the runner-version incident: an unpinned tool in the
# build path is a time bomb someone else detonates. Bump deliberately, with
# the LLVM story decided, not by drift.
RUN cargo install bpf-linker@0.10.4 --locked

# ── planner: the dependency recipe ─────────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── ebpf: the eBPF object ──────────────────────────────────────────────────
# Build order still holds: the daemon embeds no object; it loads the file at
# runtime from JALKI_EBPF_PATH.
FROM chef AS ebpf
COPY --from=bpf-linker /usr/local/cargo/bin/bpf-linker /usr/local/cargo/bin/bpf-linker
# The eBPF nightly (with rust-src for build-std against bpfel-unknown-none).
# The date lives in jalki-ebpf/rust-toolchain.toml, and `rustup toolchain
# install` with no argument installs what that file names, so the image and a
# laptop use the same nightly. Only this layer reruns when the date moves.
# --no-self-update: otherwise rustup replaces itself with whatever release is
# current (1.29.0 in the base became 1.29.1 in a local build on 2026-09-26).
COPY jalki-ebpf/rust-toolchain.toml /opt/ebpf-toolchain/rust-toolchain.toml
RUN cd /opt/ebpf-toolchain && rustup toolchain install --no-self-update
# Only xtask's own dependencies are cooked here (debug, as `cargo run` builds
# it); the skeleton also gives cargo the workspace manifests it needs.
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --locked --recipe-path recipe.json -p xtask
COPY xtask xtask
COPY jalki-common jalki-common
COPY jalki-ebpf jalki-ebpf
RUN cargo run --locked -p xtask -- build-ebpf --release

# ── builder: userspace binaries ────────────────────────────────────────────
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
# The cook must match the build below exactly (same profile, same packages),
# or cargo resolves different features and recompiles dependencies anyway.
RUN cargo chef cook --release --locked --recipe-path recipe.json \
    -p jalki -p jalki-mcp -p jalki-sdk-meta
COPY . .
RUN cargo build --release --locked -p jalki -p jalki-mcp -p jalki-sdk-meta

# ── runtime: minimal image ─────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime

COPY --from=builder /build/target/release/jalki /usr/local/bin/jalki
COPY --from=builder /build/target/release/jalki-mcp /usr/local/bin/jalki-mcp
COPY --from=builder /build/target/release/jalki-sdk-codegen /usr/local/bin/jalki-sdk-codegen
COPY --from=ebpf /build/jalki-ebpf/target/bpfel-unknown-none/release/jalki-ebpf /usr/local/share/jalki/jalki-ebpf

# eBPF requires root + CAP_BPF/CAP_PERFMON at runtime; the "nonroot" base is
# overridden at deploy time via the DaemonSet/Helm securityContext.
ENV JALKI_EBPF_PATH=/usr/local/share/jalki/jalki-ebpf
ENV RUST_LOG=jalki=info

ARG VERSION=0.0.0-dev
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="jälki" \
      org.opencontainers.image.description="Programmable eBPF fentry/fexit framework: kernel evidence with runtime binding, delivered to Vartio (Plane B) and to agents (Plane A)." \
      org.opencontainers.image.source="https://github.com/false-systems/jalki" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}"

ENTRYPOINT ["/usr/local/bin/jalki"]
CMD ["--sink", "stdout"]
