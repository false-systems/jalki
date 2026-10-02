# jälki — eBPF daemon image (daemon + MCP server + SDK codegen + eBPF object).
#
# Build from the repo root (false-protocol is vendored in-repo, so the root is
# a self-contained context):
#
#   docker build -t ghcr.io/false-systems/jalki .
#
# Stages:
#   chef        ghcr.io/false-systems/rust-builder (see false-systems/base-images):
#               Rust 1.97.1 with cargo-chef already in it. Not 1.97.0: it has
#               a P-critical x86_64 miscompile (rust-lang/rust#159035) that
#               1.97.1 was released to fix, and the amd64 binaries this image
#               ships are built with it. rust-toolchain.toml names the same
#               version, so rustup downloads nothing here. RUSTUP_AUTO_INSTALL=0
#               (below) makes a mismatch fail the build instead of quietly
#               downloading the file's version and shipping it under this tag.
#   planner     reduces the workspace to recipe.json (manifests + Cargo.lock).
#   ebpf        rust-builder's -ebpf variant: the same stable toolchain plus
#               the dated nightly (with rust-src) and bpf-linker 0.10.4. Builds
#               the eBPF object from xtask/, jalki-common/, jalki-ebpf/ and the
#               root Cargo.toml only. A userspace-only change does not rebuild
#               it, and BuildKit runs it in parallel with the builder.
#   builder     cooks the dependencies from the recipe, then builds the
#               workspace crates. A code-only change reuses the cooked layer
#               and recompiles only the workspace crates. The nightly and
#               bpf-linker are not in its layers.
#   ebpf-object only the eBPF object, in one small layer. The runtime copies
#               from here, not from ebpf: a COPY --from=ebpf needs the whole
#               ebpf filesystem, so a code-only CI build would download the
#               nightly and the eBPF target dir from the cache just to take
#               one 20 KB file out of them.
#   runtime     distroless cc-debian13 (trixie), nonroot.
#
# The builders are Debian trixie, so the runtime is trixie too: a binary needs
# the newest glibc symbol version it was linked against, and bookworm's glibc
# (2.36) is older than trixie's (2.41). Move builder and runtime together.
#
# Bases are pinned by tag plus index digest; Dependabot (.github/dependabot.yml)
# proposes digest refreshes and leaves the Rust version alone. CI (ci.yml)
# also checks that every rust-builder tag here names rust-toolchain.toml's
# channel, so a mismatch is caught before the image build starts.

# ── chef ───────────────────────────────────────────────────────────────────
FROM ghcr.io/false-systems/rust-builder:1.97.1@sha256:4bda3366fd9c4bf9a1bb71971ec7e4362d9fb3a75aaa3cf68f815f95657c6d71 AS chef
# The guard. rustup auto-installs whatever toolchain a rust-toolchain.toml
# names, and cargo-chef carries that file into the recipe, so without this a
# tag/file mismatch builds green: every cargo stage downloads the file's
# version and the image ships it under the wrong tag. With it, the first cargo
# call fails with "toolchain '<version>' is not installed". planner and
# builder inherit it from here.
ENV RUSTUP_AUTO_INSTALL=0
WORKDIR /build

# ── planner: the dependency recipe ─────────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── ebpf: the eBPF object ──────────────────────────────────────────────────
# Build order still holds: the daemon embeds no object; it loads the file at
# runtime from JALKI_EBPF_PATH.
#
# bpf-linker is PINNED (0.10.4, in the image): 0.11.0 (released 2026-08-12)
# requires system LLVM via llvm-config, and the unpinned install broke every
# Container build within a day of the release — main and all branches at once.
# An unpinned tool in the build path is a time bomb someone else detonates.
# Bump it in base-images deliberately, with the LLVM story decided.
FROM ghcr.io/false-systems/rust-builder:1.97.1-ebpf@sha256:05822130b5588e49b1d9417a137440264ce27de717f47deb87d811dc0d5a3481 AS ebpf
# The same guard as in chef (this stage does not inherit it). It stops only
# implicit installs: the explicit `rustup toolchain install` for the eBPF
# nightly below still downloads a moved nightly, as described there.
ENV RUSTUP_AUTO_INSTALL=0
WORKDIR /build
# The eBPF nightly (with rust-src for build-std against bpfel-unknown-none).
# The date lives in jalki-ebpf/rust-toolchain.toml, and `rustup toolchain
# install` with no argument installs what that file names, so the image and a
# laptop use the same nightly. The -ebpf image already carries that nightly
# (its EBPF_NIGHTLY), so this is a no-op; if the date here moves ahead of the
# image, this layer downloads the new nightly instead of failing. Move
# base-images' EBPF_NIGHTLY in the same week so it stays a no-op.
# --no-self-update: rustup must not replace itself mid-build.
COPY jalki-ebpf/rust-toolchain.toml /opt/ebpf-toolchain/rust-toolchain.toml
RUN cd /opt/ebpf-toolchain && rustup toolchain install --no-self-update
# Only xtask's own dependencies are cooked here (debug, as `cargo run` builds
# it); the skeleton also gives cargo the workspace manifests it needs.
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --locked --recipe-path recipe.json -p xtask
COPY xtask xtask
RUN cargo build --locked -p xtask
# xtask is built against cargo-chef's skeleton, where the workspace version
# is masked to 0.0.1. jalki-common inherits its version from the root
# manifest, so the eBPF build (which does not pass --locked) would re-lock it
# to 0.0.1 in jalki-ebpf/Cargo.lock. The real root manifest goes in after the
# xtask build and before the eBPF one: a `cargo run --locked` against it
# fails, because the skeleton's member manifests carry masked versions too.
# Running the built binary is what `cargo run -p xtask -- build-ebpf` runs.
COPY Cargo.toml Cargo.toml
COPY jalki-common jalki-common
COPY jalki-ebpf jalki-ebpf
RUN ./target/debug/xtask build-ebpf --release

# ── builder: userspace binaries ────────────────────────────────────────────
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
# The cook must match the build below exactly (same profile, same packages),
# or cargo resolves different features and recompiles dependencies anyway.
RUN cargo chef cook --release --locked --recipe-path recipe.json \
    -p jalki -p jalki-mcp -p jalki-sdk-meta
COPY . .
RUN cargo build --release --locked -p jalki -p jalki-mcp -p jalki-sdk-meta

# ── ebpf-object: the eBPF object alone (see the header) ─────────────────────
FROM scratch AS ebpf-object
COPY --from=ebpf /build/jalki-ebpf/target/bpfel-unknown-none/release/jalki-ebpf /jalki-ebpf

# ── runtime: minimal image ─────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2 AS runtime

COPY --from=builder /build/target/release/jalki /usr/local/bin/jalki
COPY --from=builder /build/target/release/jalki-mcp /usr/local/bin/jalki-mcp
COPY --from=builder /build/target/release/jalki-sdk-codegen /usr/local/bin/jalki-sdk-codegen
COPY --from=ebpf-object /jalki-ebpf /usr/local/share/jalki/jalki-ebpf

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
