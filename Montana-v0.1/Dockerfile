# Montana Node Dockerfile
# Multi-stage build for minimal production image

# Stage 1: Build Rust STARK library
FROM rust:1.75-slim-bookworm AS rust-builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Rust source
COPY montana-stark/ ./montana-stark/

# Build release
WORKDIR /build/montana-stark
RUN cargo build --release

# Stage 2: Build Python wheel
FROM python:3.11-slim-bookworm AS python-builder

WORKDIR /build

# Install Rust and maturin
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN pip install maturin

# Copy source
COPY montana-stark/ ./montana-stark/

# Build Python wheel
WORKDIR /build/montana-stark
RUN maturin build --release

# Stage 3: Production image
FROM python:3.11-slim-bookworm AS production

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 montana
USER montana

# Copy wheel from builder
COPY --from=python-builder /build/montana-stark/target/wheels/*.whl /tmp/

# Install wheel and dependencies
RUN pip install --user /tmp/*.whl && rm /tmp/*.whl

# Copy Python source
COPY --chown=montana:montana montana/ ./montana/
COPY --chown=montana:montana *.md ./

# Set Python path
ENV PYTHONPATH=/app
ENV PATH="/home/montana/.local/bin:${PATH}"

# Expose ports
# RPC API
EXPOSE 8545
# WebSocket
EXPOSE 8546
# P2P
EXPOSE 30303

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from montana.crypto.stark import STARK_AVAILABLE; assert STARK_AVAILABLE" || exit 1

# Default command
ENTRYPOINT ["python", "-m", "montana.cli.main"]
CMD ["--help"]
