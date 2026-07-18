# jälki — eBPF daemon image (daemon + MCP server + SDK codegen + eBPF object).
#
# Build from the repo root (false-protocol is vendored in-repo, so the root is
# a self-contained context):
#
#   docker build -t ghcr.io/false-systems/jalki .
#
# Stage 1: build the eBPF object (nightly + rust-src for build-std against
# bpfel-unknown-none), then the userspace binaries on stable.
FROM rust:1.97-bookworm AS builder

# xtask invokes `cargo +nightly` for the eBPF build; rust-src is required for
# build-std against the bpfel-unknown-none target, and bpf-linker does the
# final BPF link (installed before COPY so the layer caches).
RUN rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker --locked

WORKDIR /build
COPY . .

# eBPF first — build order matters (the daemon embeds no object; it loads the
# file at runtime from JALKI_EBPF_PATH).
RUN cargo run -p xtask -- build-ebpf --release

RUN cargo build --release -p jalki -p jalki-mcp -p jalki-sdk-meta

# Stage 2: minimal runtime image.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /build/target/release/jalki /usr/local/bin/jalki
COPY --from=builder /build/target/release/jalki-mcp /usr/local/bin/jalki-mcp
COPY --from=builder /build/target/release/jalki-sdk-codegen /usr/local/bin/jalki-sdk-codegen
COPY --from=builder /build/jalki-ebpf/target/bpfel-unknown-none/release/jalki-ebpf /usr/local/share/jalki/jalki-ebpf

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
