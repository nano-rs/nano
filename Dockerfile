# =============================================================================
# Nano SIEM - Multi-stage Dockerfile
# =============================================================================
# Targets:
#   - api: The main REST API server (HTTP-only, no background jobs)
#   - search: The search microservice
#   - jobs: Background jobs service (detection, enrichment, tuning, cleanup)
#
# Uses cargo-chef for dependency caching: dependencies are only recompiled
# when Cargo.toml/Cargo.lock change. Source-only changes rebuild in seconds.
# =============================================================================

# -----------------------------------------------------------------------------
# Base: Rust with cargo-chef and build tools (cached layer)
# -----------------------------------------------------------------------------
FROM rust:bookworm AS chef

RUN cargo install cargo-chef --locked \
    && apt-get update && apt-get install -y \
        pkg-config \
        libssl-dev \
        mold \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTFLAGS="-C link-arg=-fuse-ld=mold"

WORKDIR /app

# -----------------------------------------------------------------------------
# Stage 1: Planner - Extract dependency recipe from source
# -----------------------------------------------------------------------------
FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# -----------------------------------------------------------------------------
# Stage 2: Builder - Cook dependencies, then compile source
# -----------------------------------------------------------------------------
FROM chef AS builder

# Edition flag (NAN-745). `enterprise` (default) compiles in the
# nanosiem-enterprise crate (cases, melod, notebooks, risk, incidents,
# tuning AI, custom + agent enrichment, AI siem health). `open` builds
# without it for the open-core release. Mirrors the frontend Vite default
# in nanosiem-web/Dockerfile.
ARG EDITION=enterprise
RUN test "$EDITION" = "enterprise" || test "$EDITION" = "open" \
    || (echo "Invalid EDITION='$EDITION' (expected 'enterprise' or 'open')" >&2 && exit 1)

# Air-gap bundle signing public key (NAN-1210). nanosiem-core/build.rs embeds
# this at compile time so verify_bundle trusts it; left empty -> the release
# guard refuses the dev placeholder (no bundles verify). Non-secret (it's the
# public half), passed as a build-arg from the build workflow. ENV so the
# `cargo build` step below (where build.rs runs) sees it.
ARG AIRGAP_BUNDLE_PUBLIC_KEY_HEX=""
ENV AIRGAP_BUNDLE_PUBLIC_KEY_HEX=${AIRGAP_BUNDLE_PUBLIC_KEY_HEX}

# Cook dependencies (cached unless Cargo.toml/Cargo.lock change).
#
# Deliberately workspace-wide, unlike the scoped build below (NAN-2363). Cook
# only warms the dependency cache; cargo will not reuse a unit compiled with a
# different feature set, so a wider cook cannot leak features into the shipped
# binaries — it just warms some units the scoped build won't use. Scoping this
# too would trade that small waste for a colder cache on the enterprise path.
COPY --from=planner /app/recipe.json recipe.json
RUN if [ "$EDITION" = "enterprise" ]; then \
        cargo chef cook --release --features enterprise --recipe-path recipe.json; \
    else \
        cargo chef cook --release --recipe-path recipe.json; \
    fi

# Build application (only source code recompiles).
# Built sequentially per-bin so the linker (mold) only holds one binary's
# objects in memory at a time — keeps peak RSS under Docker Desktop's
# default VM allocation. cargo's incremental compilation caches keep this
# ~as fast as a single multi-bin invocation.
#
# NOTE: Local Docker Desktop may still OOM during the full-LTO link step
# (~3-5GB peak per binary). If you hit "cannot allocate memory", either
# bump Docker Desktop's VM allocation to 6GB+ in Settings > Resources, or
# temporarily prepend `ENV CARGO_PROFILE_RELEASE_LTO=false` to the RUN
# commands below. CI has plenty of memory and uses the default (LTO on).
COPY . .
# NAN-2363: `-p` is load-bearing, do not drop it. Without an explicit package,
# cargo selects EVERY workspace member and unifies features across the whole
# selection. `nanosiem-enterprise` is a member and declares
# `nanosiem-core = { features = ["enterprise"] }`, so an open build silently
# compiled nanosiem-core WITH the enterprise feature — every
# `#[cfg(feature = "enterprise")]` in core took the enterprise branch in
# open-edition images.
#
# It hid well: nanosiem-api's OWN feature was correctly off, so
# `/api/capabilities` reported `edition: "open"` while core was built as
# enterprise underneath. Caught on a tenant when an edition-aware string in
# siem_health rendered the enterprise variant (NAN-2357).
#
# nanosiem-jobs and clickhouse_migrator are [[bin]] targets of nanosiem-api
# (nanosiem-api/Cargo.toml:13-23), hence `-p nanosiem-api` for all three.
RUN if [ "$EDITION" = "enterprise" ]; then \
        cargo build --release --features enterprise -p nanosiem-api --bin nanosiem-api \
        && cargo build --release --features enterprise -p nanosiem-search --bin nanosiem-search \
        && cargo build --release --features enterprise -p nanosiem-api --bin nanosiem-jobs \
        && cargo build --release --features enterprise -p nanosiem-api --bin clickhouse_migrator; \
    else \
        cargo build --release -p nanosiem-api --bin nanosiem-api \
        && cargo build --release -p nanosiem-search --bin nanosiem-search \
        && cargo build --release -p nanosiem-api --bin nanosiem-jobs \
        && cargo build --release -p nanosiem-api --bin clickhouse_migrator; \
    fi

# -----------------------------------------------------------------------------
# Stage 3: API Runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS api

# OCI image metadata. The `image.source` label is what binds the GHCR package
# to the nano-rs/nano open-core repo so it appears on the repo's Packages tab
# and on package pages. Only the open edition is published to GHCR (see workflow).
LABEL org.opencontainers.image.source="https://github.com/nano-rs/nano" \
      org.opencontainers.image.url="https://nano.rs" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="nano" \
      org.opencontainers.image.title="nano-api" \
      org.opencontainers.image.description="nano API server — REST API for the open-core SIEM"

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    wget \
    curl \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Deno for custom enrichment sandbox
# Pin to specific version for reproducible builds
ARG DENO_VERSION=2.1.4
RUN curl -fsSL https://deno.land/install.sh | DENO_INSTALL=/usr/local sh -s v${DENO_VERSION} \
    && deno --version

# Copy api binary and the standalone ClickHouse migrator (NAN-607).
# The api image hosts the migrator binary so the same image can be used as
# the entrypoint for the K8s pre-deploy Job / docker-compose `clickhouse-migrate`
# service — no separate image build / version drift between api and migrator.
COPY --from=builder /app/target/release/nanosiem-api /usr/local/bin/
COPY --from=builder /app/target/release/clickhouse_migrator /usr/local/bin/

# Copy ClickHouse schema (init.sql + numbered migrations). The migrator reads
# numbered files from `./clickhouse/`; the api uses the same files for the
# startup schema-version check.
COPY --from=builder /app/clickhouse ./clickhouse

# Create non-root user with explicit UID for K8s runAsNonRoot validation
RUN useradd -r -u 999 -s /bin/false nanosiem

# Create writable directories for vector config staging and marketplace data
RUN mkdir -p /app/config/vector/staging \
             /app/config/vector/backup \
             /app/config/vector/credentials \
             /app/config/vector/sources/parsers \
             /app/config/vector/sources/configs \
             /app/data \
    && chown -R nanosiem:nanosiem /app/config /app/data

USER 999

EXPOSE 3000

ENV RUST_LOG=info
ENV API_HOST=0.0.0.0
ENV API_PORT=3000

CMD ["nanosiem-api"]

# -----------------------------------------------------------------------------
# Stage 4: Search Runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS search

LABEL org.opencontainers.image.source="https://github.com/nano-rs/nano" \
      org.opencontainers.image.url="https://nano.rs" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="nano" \
      org.opencontainers.image.title="nano-search" \
      org.opencontainers.image.description="nano search microservice — query execution against ClickHouse"

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/nanosiem-search /usr/local/bin/

# Copy ClickHouse schema (init.sql + numbered migrations) for runtime schema management.
# PostgreSQL migrations are bundled into the binary by sqlx::migrate! at compile time,
# so they don't need to be on disk at runtime.
COPY --from=builder /app/clickhouse ./clickhouse

# Create non-root user with explicit UID for K8s runAsNonRoot validation
RUN useradd -r -u 999 -s /bin/false nanosiem
USER 999

EXPOSE 3002

ENV RUST_LOG=info
ENV SEARCH_PORT=3002

CMD ["nanosiem-search"]

# -----------------------------------------------------------------------------
# Stage 5: Jobs Runtime (background tasks: detection, enrichment, tuning, cleanup)
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS jobs

LABEL org.opencontainers.image.source="https://github.com/nano-rs/nano" \
      org.opencontainers.image.url="https://nano.rs" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="nano" \
      org.opencontainers.image.title="nano-jobs" \
      org.opencontainers.image.description="nano background jobs — detection, enrichment, tuning, cleanup"

WORKDIR /app

# Install runtime dependencies
# Needs git for repo sync schedulers, curl for Deno install
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    wget \
    curl \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Deno for custom enrichment scheduler (Deno sandbox)
ARG DENO_VERSION=2.1.4
RUN curl -fsSL https://deno.land/install.sh | DENO_INSTALL=/usr/local sh -s v${DENO_VERSION} \
    && deno --version

# Copy binary from builder
COPY --from=builder /app/target/release/nanosiem-jobs /usr/local/bin/

# Copy ClickHouse schema (init.sql + numbered migrations) for runtime schema management.
# PostgreSQL migrations are bundled into the binary by sqlx::migrate! at compile time,
# so they don't need to be on disk at runtime.
COPY --from=builder /app/clickhouse ./clickhouse

# Create non-root user with explicit UID for K8s runAsNonRoot validation
RUN useradd -r -u 999 -s /bin/false nanosiem

# Jobs needs data dir for repo syncs and marketplace
RUN mkdir -p /app/data \
    && chown -R nanosiem:nanosiem /app/data

USER 999

EXPOSE 3001

ENV RUST_LOG=info
ENV JOBS_PORT=3001

CMD ["nanosiem-jobs"]
