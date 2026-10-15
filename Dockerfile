# =============================================================================
# Nano SIEM - Multi-stage Dockerfile
# =============================================================================
# Targets:
#   - api: The main REST API server (HTTP-only, no background jobs)
#   - search: The search microservice
#   - jobs: Background jobs service (detection, enrichment, tuning, cleanup)
#   - lake-control: Lakekeeper/RustFS bootstrap tooling (no query engine)
#   - lake-cell: open-core lean cell
#   - connector-runner: open-core connector runner
#   (gen1 lake-query / lake-maintenance / lake-gen1-* targets were retired
#   with the gen1 lake code in NAN-3861; NAN-3901 removed their stages)
#
# Uses cargo-chef for dependency caching: dependencies are only recompiled
# when Cargo.toml/Cargo.lock change. Source-only changes rebuild in seconds.
# =============================================================================

# Rust link parallelism for the release builders. 1 was the Mac-era memory
# guard; the Linux build box (32 cores / 48 GB) overrides it per build.
ARG CARGO_BUILD_JOBS=1
# NAN-3407: pinned by digest. The shared sccache keys on the exact rustc, and the
# mutable `rust:bookworm` tag resolved to 1.98.1 on one host and 1.99.0 on another
# (0 cross-host hits). Bump the tag and the digest together
# (`docker buildx imagetools inspect rust:<ver>-bookworm`).
ARG NANO_RUST_BUILD_BASE=rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6
# Portable (x86-64-v2) amd64 libchdb, NAN-2950; see the chdb-runtime stage.
# Receipt: deploy/lake-images/receipts/chdb-portable/ (run 36379646914).
ARG CHDB_PORTABLE_AMD64_IMAGE=us-central1-docker.pkg.dev/nano-rs/chdb-portable/libchdb-x86-64-v2@sha256:9b6df33db09f275e7d601948ad6f3ad97b00fda522b45d85080363071e412f3e
ARG CHDB_PORTABLE_AMD64_SHA256=7e51474c820621fbc5f2941da8cc0ccac6f6fa5f16b93e478ee4af10599d2565

# -----------------------------------------------------------------------------
# Base: Rust with cargo-chef and build tools (cached layer)
# -----------------------------------------------------------------------------
FROM ${NANO_RUST_BUILD_BASE} AS chef

RUN cargo install cargo-chef --locked \
    && apt-get update && apt-get install -y \
        pkg-config \
        libssl-dev \
        mold \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTFLAGS="-C link-arg=-fuse-ld=mold"

# NAN-3407: shared sccache (R2 bucket nano-sccache) so every build host reuses
# compiled crates; BuildKit's layer cache is per host and gets evicted. Pinned
# release, checksummed. The cargo RUNs below source nano-sccache-env, which turns
# the wrapper on only when the `sccache` build secret is mounted
# (`--secret id=sccache,src=<env file>`); without it they build exactly as before.
ARG TARGETARCH
RUN set -eu; \
    v=0.18.0; \
    case "${TARGETARCH:-amd64}" in \
      amd64) t=x86_64; sum=45f1447fbe231e3037bde351ef70677dd212216c8d62ae7ca409fecc4d6acc89 ;; \
      arm64) t=aarch64; sum=2b3284d5da3b46a47dc4229e75bb7b88ac4aa99c8d754fb7d2f84997e5a4354a ;; \
      *) echo "no pinned sccache for ${TARGETARCH}; cargo RUNs build without it"; exit 0 ;; \
    esac; \
    d=sccache-v$v-$t-unknown-linux-musl; \
    curl -fsSL --retry 5 --retry-all-errors -o /tmp/sccache.tgz "https://github.com/mozilla/sccache/releases/download/v$v/$d.tar.gz"; \
    echo "$sum  /tmp/sccache.tgz" | sha256sum -c -; \
    tar -xzf /tmp/sccache.tgz -C /tmp "$d/sccache"; \
    install -m 0755 "/tmp/$d/sccache" /usr/local/bin/sccache; \
    rm -rf /tmp/sccache.tgz "/tmp/$d"; \
    sccache --version
COPY scripts/ci/nano-sccache-env.sh /usr/local/bin/nano-sccache-env
# Inherited by every builder stage (ENV survives FROM chef; a bare ARG would not).
ARG CARGO_BUILD_JOBS
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

WORKDIR /app

# -----------------------------------------------------------------------------
# Stage 1: Planner - Extract dependency recipe from source
# -----------------------------------------------------------------------------
FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# -----------------------------------------------------------------------------
# Stage 2: Builders - Cook dependencies, then compile source
# -----------------------------------------------------------------------------
# NAN-3178: two chained stages so the `api` target compiles only what it ships.
#   api-builder: cook + nanosiem-api, clickhouse_migrator, postgres_migrator
#                (exactly the three binaries the `api` runtime stage copies)
#   builder:     FROM api-builder, + nanosiem-search and nanosiem-jobs
# `--target api` therefore never compiles search/jobs (on the slow spot runners
# those two cost ~33 min of a ~97 min api build), while a later
# `--target search` / `--target jobs` on the same builder reuses every
# api-builder layer, so nothing is ever compiled twice. Each cargo command is
# unchanged; only the order moved (migrators now link before search/jobs).
FROM chef AS api-builder

# Edition flag (NAN-745). `enterprise` compiles in the
# enterprise crate (cases, melod, notebooks, risk, incidents,
# tuning AI, custom + agent enrichment, AI siem health). `open` (the default) builds
# without it for the open-core release. Mirrors the frontend Vite default
# in nanosiem-web/Dockerfile.
ARG EDITION=open
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
COPY vendor ./vendor
RUN --mount=type=secret,id=sccache,required=false \
    . /usr/local/bin/nano-sccache-env && if [ "$EDITION" = "enterprise" ]; then \
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
# NOTE: Local Docker Desktop may still OOM during the LTO link step (thin
# LTO since NAN-3450; fat LTO peaked ~3-5GB per binary). If you hit "cannot
# allocate memory", either bump Docker Desktop's VM allocation to 6GB+ in
# Settings > Resources, or
# temporarily prepend `ENV CARGO_PROFILE_RELEASE_LTO=false` to the RUN
# commands below. CI has plenty of memory and uses the default (thin LTO,
# codegen-units = 16, from .cargo/config.toml).
COPY . .
# NAN-2363: `-p` is load-bearing, do not drop it. Without an explicit package,
# cargo selects EVERY workspace member and unifies features across the whole
# selection. The enterprise crate is a member and declares
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
# nanosiem-jobs, clickhouse_migrator, and postgres_migrator are [[bin]] targets
# of nanosiem-api, hence `-p nanosiem-api` for each one.
RUN --mount=type=secret,id=sccache,required=false \
    . /usr/local/bin/nano-sccache-env && if [ "$EDITION" = "enterprise" ]; then \
        cargo build --release --features enterprise -p nanosiem-api --bin nanosiem-api \
        && cargo build --release --features enterprise -p nanosiem-api --bin clickhouse_migrator \
        && cargo build --release --features enterprise -p nanosiem-api --bin postgres_migrator; \
    else \
        cargo build --release -p nanosiem-api --bin nanosiem-api \
        && cargo build --release -p nanosiem-api --bin clickhouse_migrator \
        && cargo build --release -p nanosiem-api --bin postgres_migrator; \
    fi

# The search and jobs binaries, on top of api-builder (see the stage comment
# above). A build ARG does not cross FROM, so EDITION is re-declared for the
# branch below; ENV from api-builder (CARGO_BUILD_JOBS, RUSTFLAGS,
# AIRGAP_BUNDLE_PUBLIC_KEY_HEX) is inherited unchanged.
FROM api-builder AS builder
ARG EDITION=open
RUN --mount=type=secret,id=sccache,required=false \
    . /usr/local/bin/nano-sccache-env && if [ "$EDITION" = "enterprise" ]; then \
        cargo build --release --features enterprise -p nanosiem-search --bin nanosiem-search \
        && cargo build --release --features enterprise -p nanosiem-api --bin nanosiem-jobs; \
    else \
        cargo build --release -p nanosiem-search --bin nanosiem-search \
        && cargo build --release -p nanosiem-api --bin nanosiem-jobs; \
    fi

# NAN-3901: compile once per arch x edition. The lake bootstrap and the open
# lake cell build ON TOP of `builder`, reusing its cooked dependencies and its
# target/ (every unit whose features match is fresh), instead of each cooking
# and compiling the shared graph again in its own chef stage. Each keeps its
# own cargo invocation with the same flags as before, so cargo resolves exactly
# the same features for the shipped binaries: no feature unification with the
# api/search/jobs selection. The release workflow builds api -> search -> jobs
# -> these in one job, so every stage below `builder` is a local BuildKit hit.
FROM builder AS lake-control-builder
RUN --mount=type=secret,id=sccache,required=false \
    . /usr/local/bin/nano-sccache-env && cargo build --release -p nanosiem-lake-worker --bin lake_catalog_bootstrap

# Open-core lean cell: scoped packages, no enterprise feature and no gen1 bins.
# FROM builder (NAN-3901, see lake-control-builder). The release workflow passes
# EDITION=open so `builder` is the open graph it already built for api/search/
# jobs. The scoped cargo invocations below never pass --features, so the cell's
# binaries do not depend on EDITION (only which target/ they reuse does).
# AIRGAP_BUNDLE_PUBLIC_KEY_HEX is inherited from api-builder's ENV.
FROM builder AS open-lake-cell-builder
RUN --mount=type=secret,id=sccache,required=false \
    . /usr/local/bin/nano-sccache-env \
    && cargo build --release --locked -p nanosiem-lake-cell --bin nanosiem-lake-cell \
    && cargo build --release --locked -p nanosiem-lake-worker \
       --bin lake_part_ingest --bin lake_part_query --bin lake_job_runner \
       --bin lake_result_gc --bin lake_otel_ingest --bin lake_lean_enrichment_coordinator \
       --bin lake_local_audit_deliver --bin lake_landing_ingest \
    && cargo build --release --locked -p nanosiem-core --bin lake_query_compile \
    && mkdir -p /app/open-cell-bin \
    && install -m 0755 target/release/nanosiem-lake-cell target/release/lake_job_runner \
       target/release/lake_result_gc target/release/lake_otel_ingest \
       target/release/lake_lean_enrichment_coordinator target/release/lake_query_compile \
       target/release/lake_local_audit_deliver target/release/lake_landing_ingest /app/open-cell-bin/ \
    && install -m 0755 target/release/lake_part_ingest /app/open-cell-bin/nanosiem-lake-ingest \
    && install -m 0755 target/release/lake_part_query /app/open-cell-bin/nanosiem-lake-query

# chDB publishes a standalone C ABI artifact separately from its Python wheel.
# Nano loads this exact library directly from Rust; Python is not present in
# the runtime image. The library is pinned per architecture, and its digest is
# kept alongside it for generated worker configurations.
#
# amd64 (NAN-2950): Nano's portable x86-64-v2 build of the same chdb-core tag.
# Upstream's linux-x86_64 asset is x86-64-v3 and SIGILLs (AVX2 in its ELF
# initializer) on the pre-AVX2 lake nodes. It is published by
# .github/workflows/chdb-portable.yml, proven on a non-AVX2 runner, and receipted
# in deploy/lake-images/receipts/chdb-portable/. scripts/build-publish-lake-cell.sh
# reads these same two pins. Only BuildKit resolves the stage for the target
# arch, so arm64 builds never pull it.
FROM --platform=linux/amd64 ${CHDB_PORTABLE_AMD64_IMAGE} AS chdb-portable-amd64

FROM debian:bookworm-slim AS chdb-runtime-amd64
ARG CHDB_PORTABLE_AMD64_SHA256
COPY --from=chdb-portable-amd64 /libchdb.so /opt/nano-chdb/libchdb.so
RUN echo "${CHDB_PORTABLE_AMD64_SHA256}  /opt/nano-chdb/libchdb.so" | sha256sum -c - \
    && printf '%s\n' "${CHDB_PORTABLE_AMD64_SHA256}" > /opt/nano-chdb/libchdb.sha256 \
    && chmod 0555 /opt/nano-chdb/libchdb.so \
    && chmod 0444 /opt/nano-chdb/libchdb.sha256

# arm64: upstream release asset (no pre-AVX2 concern).
FROM debian:bookworm-slim AS chdb-runtime-arm64
ARG CHDB_CORE_VERSION=26.7.0
ARG CHDB_ARM64_ARCHIVE_SHA256=d934104b492848d2500b48c0a67c580afc50bd968bebbe435c1b13970ef20384
RUN apt-get update && apt-get install -y ca-certificates curl \
    && curl -fsSL --retry 3 \
         "https://github.com/chdb-io/chdb-core/releases/download/v${CHDB_CORE_VERSION}/linux-aarch64-libchdb.tar.gz" \
         -o /tmp/libchdb.tar.gz \
    && echo "${CHDB_ARM64_ARCHIVE_SHA256}  /tmp/libchdb.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/nano-chdb \
    && tar -xzf /tmp/libchdb.tar.gz -C /opt/nano-chdb libchdb.so \
    && sha256sum /opt/nano-chdb/libchdb.so | cut -d ' ' -f 1 \
         > /opt/nano-chdb/libchdb.sha256 \
    && chmod 0555 /opt/nano-chdb/libchdb.so \
    && chmod 0444 /opt/nano-chdb/libchdb.sha256 \
    && rm -rf /var/lib/apt/lists/* /tmp/libchdb.tar.gz

FROM chdb-runtime-${TARGETARCH} AS chdb-runtime

# RustFS's official CLI is used only by the one-shot bucket initializer. Pin
# both the version and architecture-specific checksum so an upstream release
# cannot silently change what enters the image.
FROM debian:bookworm-slim AS rustfs-cli

ARG TARGETARCH
ARG RUSTFS_CLI_VERSION=0.1.31
RUN apt-get update && apt-get install -y ca-certificates curl \
    && case "$TARGETARCH" in \
         amd64) RUSTFS_CLI_SHA256=129ac825f495fe44583505233d849045f7fc1801edb483a042cee7a563e922d7 ;; \
         arm64) RUSTFS_CLI_SHA256=04803754ffd8b3699392bacec04276ab75f200b71177e03141dcdf9718f3e8b9 ;; \
         *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
       esac \
    && curl -fsSL \
         "https://github.com/rustfs/cli/releases/download/v${RUSTFS_CLI_VERSION}/rustfs-cli-linux-${TARGETARCH}-v${RUSTFS_CLI_VERSION}.tar.gz" \
         -o /tmp/rustfs-cli.tar.gz \
    && echo "${RUSTFS_CLI_SHA256}  /tmp/rustfs-cli.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/rustfs-cli.tar.gz -C /usr/local/bin rc \
    && chmod 0755 /usr/local/bin/rc \
    && rm -rf /var/lib/apt/lists/* /tmp/rustfs-cli.tar.gz

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

# Deno runs tenant enrichment and collector code (enterprise edition only).
# NAN-3485: pinned version, SHA-256-checked official release zip; the version
# and per-arch sums live in scripts/ci/install-deno.sh (shared with CI). The
# open edition is built without --features enterprise and never spawns deno,
# so its image does not ship the binary.
ARG EDITION=open
ARG TARGETARCH
RUN --mount=type=bind,source=scripts/ci/install-deno.sh,target=/tmp/install-deno.sh \
    if [ "$EDITION" = "enterprise" ]; then \
      bash /tmp/install-deno.sh /usr/local/bin; \
    else \
      echo "EDITION=$EDITION: no Deno (sandbox code is enterprise-only)"; \
    fi

# Copy the API and standalone database migrators. Hosting them in the API image
# avoids build/version drift between application and pre-deploy jobs.
COPY --from=api-builder /app/target/release/nanosiem-api /usr/local/bin/
COPY --from=api-builder /app/target/release/clickhouse_migrator /usr/local/bin/
COPY --from=api-builder /app/target/release/postgres_migrator /usr/local/bin/
# Use the same open compiler artifact as the lean cell.
COPY --from=open-lake-cell-builder /app/open-cell-bin/lake_query_compile /usr/local/bin/

# Copy ClickHouse schema (init.sql + numbered migrations). The migrator reads
# numbered files from `./clickhouse/`; the api uses the same files for the
# startup schema-version check.
COPY --from=api-builder /app/clickhouse ./clickhouse

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
# Use the same open compiler artifact as the lean cell.
COPY --from=open-lake-cell-builder /app/open-cell-bin/lake_query_compile /usr/local/bin/

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
    libssl3 \
    wget \
    curl \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Deno for the custom enrichment and collector schedulers (enterprise only);
# see the api stage and scripts/ci/install-deno.sh (NAN-3485).
ARG EDITION=open
ARG TARGETARCH
RUN --mount=type=bind,source=scripts/ci/install-deno.sh,target=/tmp/install-deno.sh \
    if [ "$EDITION" = "enterprise" ]; then \
      bash /tmp/install-deno.sh /usr/local/bin; \
    else \
      echo "EDITION=$EDITION: no Deno (sandbox code is enterprise-only)"; \
    fi

# Copy binary from builder
COPY --from=builder /app/target/release/nanosiem-jobs /usr/local/bin/
# Use the same open compiler artifact as the lean cell.
COPY --from=open-lake-cell-builder /app/open-cell-bin/lake_query_compile /usr/local/bin/

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

# -----------------------------------------------------------------------------
# Lake control-plane runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS lake-control

LABEL org.opencontainers.image.source="https://github.com/nano-rs/nano" \
      org.opencontainers.image.url="https://nano.rs" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="nano" \
      org.opencontainers.image.title="nano-lake-control" \
      org.opencontainers.image.description="Nano object-lake catalog and RustFS bootstrap tooling"

RUN apt-get update && apt-get install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 999 -d /var/lib/nano-lake -s /bin/false nanosiem \
    && mkdir -p /var/lib/nano-lake \
    && chown -R nanosiem:nanosiem /var/lib/nano-lake

COPY --from=lake-control-builder /app/target/release/lake_catalog_bootstrap /usr/local/bin/
COPY --from=rustfs-cli /usr/local/bin/rc /usr/local/bin/rc

USER 999
ENV HOME=/var/lib/nano-lake

CMD ["lake_catalog_bootstrap", "--help"]

# -----------------------------------------------------------------------------
# Open-core lean runtime. Runs as root so the supervisor can drop each role's
# uid and capabilities. Deployment must supply the cell jail capability set.
# chdb-runtime selects the existing pinned artifact for each architecture:
# portable x86-64-v2 on amd64, upstream aarch64 on arm64.
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS lake-cell
LABEL org.opencontainers.image.source="https://github.com/nano-rs/nano" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.title="nano-lake-cell" \
      org.opencontainers.image.description="Open-core single-tenant lean lake cell" \
      io.nano.edition="open"
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libgcc-s1 libssl3 libstdc++6 python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/local/lib/nano-lake
COPY --from=rustfs-cli /usr/local/bin/rc /usr/local/bin/rc
COPY --from=open-lake-cell-builder /app/open-cell-bin/ /usr/local/bin/
# trusted-local init records the stable worker entrypoint names
# nanosiem-lake-ingest / nanosiem-lake-query; open-lake-cell-builder installs them.
COPY --from=chdb-runtime /opt/nano-chdb/ /usr/local/lib/nano-chdb/
RUN sha256sum /usr/local/bin/lake_query_compile | cut -d ' ' -f 1 \
      > /usr/local/lib/nano-lake/lake_query_compile.sha256 \
    && chmod 0444 /usr/local/lib/nano-lake/lake_query_compile.sha256
ENTRYPOINT ["/usr/local/bin/nanosiem-lake-cell"]
CMD ["probe"]

# The dedicated connector runner has a separate open-only cargo invocation.
FROM chef AS open-connector-builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --locked --release -p nano-connector --bin nano-connector-runner --bin nano-connector

FROM debian:bookworm-slim AS connector-runner
ARG NANO_SOURCE_REVISION=unknown
LABEL org.opencontainers.image.revision="${NANO_SOURCE_REVISION}" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/nano-rs/nano"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/nano-connector && chown 999:999 /run/nano-connector
COPY --from=open-connector-builder /app/target/release/nano-connector-runner /usr/local/bin/
COPY --from=open-connector-builder /app/target/release/nano-connector /usr/local/bin/
USER 999:999
ENTRYPOINT ["/usr/local/bin/nano-connector-runner"]
