# =============================================================================
# Nano SIEM - Multi-stage Dockerfile
# =============================================================================
# Targets:
#   - api: The main REST API server (HTTP-only, no background jobs)
#   - search: The search microservice
#   - jobs: Background jobs service (detection, enrichment, tuning, cleanup)
#   - connector-runner: Pull-feed runner (NAN-4914; open core, no enterprise code)
#
# Uses cargo-chef for dependency caching: dependencies are only recompiled
# when Cargo.toml/Cargo.lock change. Source-only changes rebuild in seconds.
# =============================================================================

# -----------------------------------------------------------------------------
# Base: Rust with cargo-chef and build tools (cached layer)
# -----------------------------------------------------------------------------
FROM rust:1.95-bookworm AS chef

RUN cargo install cargo-chef --locked \
    && apt-get update && apt-get install -y \
        pkg-config \
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
# NAN-4983: the workspace [patch.crates-io] points at vendor/sqlx-core (NAN-4955);
# chef cook needs that path dependency present before the source copy.
COPY vendor ./vendor
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
# The stripped open-core mirror deliberately has no enterprise overlay. Keep
# the runtime mount source present there so one conditional, ephemeral mount
# can serve both editions without copying enterprise SQL into an open layer.
RUN mkdir -p /app/clickhouse-enterprise
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

# A lab may build a later candidate that carries one real migration without
# adding that fixture to the production migration tree. Both arguments are
# required, the fixture stays under scripts/tests, and release workflows leave
# both at their fail-closed defaults. Keep this after compilation so guarded
# and release-image proofs share the expensive Rust build layer.
ARG NANO_NON_RELEASE_BUILD=0
ARG NANO_LAB_UPGRADE_MIGRATION_FIXTURE=0
RUN case "$NANO_NON_RELEASE_BUILD:$NANO_LAB_UPGRADE_MIGRATION_FIXTURE" in \
      0:0) ;; \
      1:1) \
        cp scripts/tests/fixtures/upgrade/clickhouse/999999999lab_upgrade_probe.sql \
          clickhouse/999999999lab_upgrade_probe.sql \
        && printf 'non-release migration fixture\n' > clickhouse/.nano-test-upgrade-migration ;; \
      *) \
        echo "NANO_LAB_UPGRADE_MIGRATION_FIXTURE=1 requires NANO_NON_RELEASE_BUILD=1; all other combinations are refused" >&2; \
        exit 1 ;; \
    esac

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
    wget \
    curl \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Deno runs custom enrichment and collector code (nanosiem-enterprise only).
# NAN-3485 / NAN-4908: pinned version, SHA-256-checked official release zip
# (no `curl | sh`); the version and per-arch sums live in
# scripts/ci/install-deno.sh. The open edition is built without
# --features enterprise and never spawns deno, so its image does not ship it.
ARG EDITION=enterprise
ARG TARGETARCH
RUN --mount=type=bind,source=scripts/ci/install-deno.sh,target=/tmp/install-deno.sh \
    if [ "$EDITION" = "enterprise" ]; then \
      bash /tmp/install-deno.sh /usr/local/bin; \
    else \
      echo "EDITION=$EDITION: no Deno (sandbox code is enterprise-only)"; \
    fi

# Copy api binary and the standalone ClickHouse migrator (NAN-607).
# The api image hosts the migrator binary so the same image can be used as
# the entrypoint for the K8s pre-deploy Job / docker-compose `clickhouse-migrate`
# service — no separate image build / version drift between api and migrator.
COPY --from=builder /app/target/release/nanosiem-api /usr/local/bin/
COPY --from=builder /app/target/release/clickhouse_migrator /usr/local/bin/

# Upgrade coordinators use this immutable image capability marker to decide
# whether API mutations can be drained in place. Older source images lack it,
# so their API container is stopped as part of the exact durable writer plan.
RUN mkdir -p /usr/local/share/nano/capabilities \
    && touch /usr/local/share/nano/capabilities/backup-mutation-fence-v1

# Copy ClickHouse schema (init.sql + numbered migrations). The migrator reads
# numbered files from `./clickhouse/`; the api uses the same files for the
# startup schema-version check.
COPY --from=builder /app/clickhouse ./clickhouse
# Enterprise-only overlay: the builder directory is mounted read-only for this
# RUN and therefore never enters an open-edition layer. Enterprise images copy
# it into the final filesystem; open images assert that it remains absent.
RUN --mount=from=builder,source=/app/clickhouse-enterprise,target=/tmp/clickhouse-enterprise,ro \
    if [ "$EDITION" = "enterprise" ]; then \
      test -n "$(find /tmp/clickhouse-enterprise -maxdepth 1 -type f -name '*.sql' -print -quit)" \
      && cp -a /tmp/clickhouse-enterprise ./clickhouse-enterprise; \
    else \
      test ! -e ./clickhouse-enterprise; \
    fi

# Create non-root user with explicit UID for K8s runAsNonRoot validation
RUN useradd -r -u 999 -s /bin/false nanosiem

# Create writable directories for vector config staging and marketplace data
RUN mkdir -p /app/config/vector/staging \
             /app/config/vector/backup \
             /app/config/vector/credentials \
             /app/config/vector/sources/parsers \
             /app/config/vector/sources/configs \
             /app/vector-validation \
             /app/data \
    && chown -R nanosiem:nanosiem /app/config /app/data /app/vector-validation

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
# Needs git for repo sync schedulers; curl and unzip for the Deno install
RUN apt-get update && apt-get install -y \
    ca-certificates \
    wget \
    curl \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Deno for the custom enrichment and collector schedulers (enterprise only);
# see the api stage and scripts/ci/install-deno.sh (NAN-3485 / NAN-4908).
ARG EDITION=enterprise
ARG TARGETARCH
RUN --mount=type=bind,source=scripts/ci/install-deno.sh,target=/tmp/install-deno.sh \
    if [ "$EDITION" = "enterprise" ]; then \
      bash /tmp/install-deno.sh /usr/local/bin; \
    else \
      echo "EDITION=$EDITION: no Deno (sandbox code is enterprise-only)"; \
    fi

# Copy binary from builder
COPY --from=builder /app/target/release/nanosiem-jobs /usr/local/bin/

# Copy ClickHouse schema (init.sql + numbered migrations) for runtime schema management.
# PostgreSQL migrations are bundled into the binary by sqlx::migrate! at compile time,
# so they don't need to be on disk at runtime.
COPY --from=builder /app/clickhouse ./clickhouse
# Enterprise jobs performs the same startup schema-version check as the API.
# Keep the closed overlay out of open layers by mounting it only for this RUN.
RUN --mount=from=builder,source=/app/clickhouse-enterprise,target=/tmp/clickhouse-enterprise,ro \
    if [ "$EDITION" = "enterprise" ]; then \
      test -n "$(find /tmp/clickhouse-enterprise -maxdepth 1 -type f -name '*.sql' -print -quit)" \
      && cp -a /tmp/clickhouse-enterprise ./clickhouse-enterprise; \
    else \
      test ! -e ./clickhouse-enterprise; \
    fi

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

# -----------------------------------------------------------------------------
# Stage 6: Connector runner (NAN-4914 phase 4) — pull feeds
# -----------------------------------------------------------------------------
# Its own open-only cargo invocation: nano-connector has no enterprise
# feature, so the image is identical for both editions. One binary: the
# runner re-execs itself as the sandboxed VRL worker (`vrl-worker`).
FROM chef AS connector-builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*
COPY --from=planner /app/recipe.json recipe.json
COPY vendor ./vendor
RUN cargo chef cook --release --recipe-path recipe.json -p nano-connector
COPY . .
# The open-core tree is stripped of the nanosiem-enterprise workspace member,
# so its Cargo.lock still lists that member and the deps only it pulled in.
# Prune those stale workspace entries offline (every remaining dependency is
# already cooked above, and `-w` never bumps a dependency version), then keep
# --locked so any other drift still fails the build. A no-op for the source tree.
RUN cargo update --workspace --offline \
    && cargo build --release --locked -p nano-connector --bin nano-connector-runner

FROM debian:bookworm-slim AS connector-runner

LABEL org.opencontainers.image.source="https://github.com/nano-rs/nano" \
      org.opencontainers.image.url="https://nano.rs" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="nano" \
      org.opencontainers.image.title="nano-connector-runner" \
      org.opencontainers.image.description="nano pull-feed runner — scheduled SaaS audit-log collectors delivering through HEC"

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 999 -s /bin/false nanosiem \
    && mkdir -p /run/nano-connector && chown 999:999 /run/nano-connector

COPY --from=connector-builder /app/target/release/nano-connector-runner /usr/local/bin/

USER 999
ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/nano-connector-runner"]

# -----------------------------------------------------------------------------
# nano-backup: scheduled backups (NAN-5204), opt-in `backup` Compose profile.
# -----------------------------------------------------------------------------
# Based on the exact PostgreSQL image the stack runs (same digest as
# docker-compose.opensource.yml), so pg_dump matches the server major. The
# service has no Docker socket: it dumps PostgreSQL over the network as the
# dedicated read-only `nano_backup` role, reads the lookup-table rows through
# ClickHouse SQL as the least-privilege `nano_backup` ClickHouse user, and
# reads .env / certificates from a read-only mount of the install directory.
FROM postgres:17@sha256:0027bef26712baaee437a4ea48fdf3d2d2e2bc5f0d81615374408ca320f3c7e3 AS backup

LABEL org.opencontainers.image.source="https://github.com/nano-rs/nano" \
      org.opencontainers.image.description="nano scheduled backups: PostgreSQL + configuration + lookup tables to a path or S3-compatible bucket"

RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/nano-backup-scheduler.py scripts/nano-manifest.py /opt/nano-backup/
RUN printf '#!/bin/sh\nexec python3 -I /opt/nano-backup/nano-backup-scheduler.py "$@"\n' > /usr/local/bin/nano-backup \
    && chmod 0755 /usr/local/bin/nano-backup /opt/nano-backup/*.py

# Compose runs it as the install owner's uid:gid (it must read the 0600 .env).
USER 999
ENTRYPOINT ["/usr/local/bin/nano-backup"]
CMD ["--install-dir", "/install", "serve"]
