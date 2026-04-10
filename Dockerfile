# Build context must include ../ahti/false-protocol.
# Run from parent directory: docker build -f jalki/Dockerfile -t jalki .
#
# Stage 1: Build eBPF programs + userspace binaries
FROM rust:1.87-bookworm AS builder

# Install nightly for eBPF compilation + build deps.
RUN rustup install nightly-2025-03-01 \
    && rustup component add rust-src --toolchain nightly-2025-03-01 \
    && rustup target add bpfel-unknown-none --toolchain nightly-2025-03-01

WORKDIR /build

# Copy workspace manifests first for dependency caching.
COPY Cargo.toml Cargo.lock ./
COPY jalki-common/Cargo.toml jalki-common/Cargo.toml
COPY jalki/Cargo.toml jalki/Cargo.toml
COPY jalki-mcp/Cargo.toml jalki-mcp/Cargo.toml
COPY xtask/Cargo.toml xtask/Cargo.toml
COPY jalki-ebpf/Cargo.toml jalki-ebpf/Cargo.toml

# Stub out sources for dependency pre-build.
RUN mkdir -p jalki-common/src jalki/src jalki-mcp/src xtask/src jalki-ebpf/src \
    && echo '#![no_std]' > jalki-common/src/lib.rs \
    && echo 'fn main() {}' > jalki/src/main.rs \
    && touch jalki/src/lib.rs \
    && echo 'fn main() {}' > jalki-mcp/src/main.rs \
    && echo 'fn main() {}' > xtask/src/main.rs \
    && echo '#![no_std] #![no_main]' > jalki-ebpf/src/main.rs

# Copy real sources.
COPY . .

# Touch sources to invalidate stubs.
RUN find jalki-common/src jalki/src jalki-mcp/src xtask/src jalki-ebpf/src -name '*.rs' -exec touch {} +

# Build eBPF programs.
RUN cargo run -p xtask -- build-ebpf --release

# Build userspace binaries.
RUN cargo build --release -p jalki -p jalki-mcp

# Stage 2: Minimal runtime image
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /build/target/release/jalki /usr/local/bin/jalki
COPY --from=builder /build/target/release/jalki-mcp /usr/local/bin/jalki-mcp
COPY --from=builder /build/jalki-ebpf/target/bpfel-unknown-none/release/jalki-ebpf /usr/local/share/jalki/jalki-ebpf

# eBPF requires running as root with capabilities. The "nonroot" base is
# overridden at deploy time via securityContext in the Helm chart.
ENV JALKI_EBPF_PATH=/usr/local/share/jalki/jalki-ebpf
ENV RUST_LOG=jalki=info

ENTRYPOINT ["/usr/local/bin/jalki"]
CMD ["--emit", "stdout"]
