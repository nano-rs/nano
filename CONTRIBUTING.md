# Contributing to nano

Thank you for considering a contribution. nano is an open-core SIEM and we
take community patches seriously — this guide covers how to set up a dev
environment, the conventions we follow, and the contributor licensing
agreement (CLA) you'll be asked to sign on your first PR.

## Contributor License Agreement

Every contributor must sign the [Individual Contributor License Agreement
(ICLA)](./.github/ICLA.md) before we can merge a patch. The
[cla-assistant](https://cla-assistant.io) bot will gate your first PR — sign
once via the GitHub OAuth flow, and you're set for all future PRs.

**Why a CLA, not DCO?** nano is open-core: the engine is AGPL-3.0, the
enterprise add-ons (Cases, pivt, meloD, risk) live in a separate proprietary
crate. To accept community patches into the engine and still ship the
enterprise build, Nano LLC needs the right to sublicense your contribution.
DCO grants too little; an ICLA is the smallest tool that does the job. The
text is adapted from the Apache ICLA — it gives you a copyright, doesn't
take it away.

## Dev environment

Prerequisites:

- Rust stable (we test on the latest stable; nightly not required)
- Node 20+ and npm
- PostgreSQL 18+
- Docker (the local lake runs in compose)
- Optional: `cargo-watch`, `sqlx-cli`

> **Note on the local-dev story.** Events live in the lake (OCSF 1.9 Parquet,
> queried by chDB); there is no ClickHouse server. Run the lake services with
> `COMPOSE_PROFILES=lake docker compose -f docker-compose.opensource.yml up -d`
> and the Rust services from source with `./scripts/start-microservices-dev.sh --lake`
> (see `docs/getting-started/open-core-operations.md` §7), or follow the
> bare-host path below against a local Postgres. The legacy ClickHouse edition
> lives on branch `legacy/clickhouse`, unsupported.

Bare-host setup:

```bash
git clone https://github.com/nano-rs/nano.git
cd nano

# Run migrations against your local Postgres
cargo run --bin postgres_migrator

# Start services
cargo run --bin nanosiem-api &       # :3000
cargo run --bin nanosiem-search &    # :3002

# Privileged cell fixtures (requires delegated mount/cgroup sandbox)
cargo test -p nanosiem-lake-cell --features sandbox-integration --test isolation --test zero_downtime_roll

# Frontend
cd nanosiem-web && npm ci && VITE_EDITION=open npm run dev   # :5173
```

The exact env-var contract is in
`nanosiem-api/src/config.rs` — at minimum you'll set the Postgres connection
string plus `NANO_LOG_QUERY_BACKEND=lake` and `NANO_SCHEMA_PROFILE=ocsf`.

OpenAPI / Swagger is at <http://localhost:3000/swagger-ui>.

## Branch & commit conventions

- Branches: `feat/short-desc`, `fix/short-desc`, `chore/short-desc`,
  `refactor/short-desc`.
- One PR = one logical change. Keep them reviewable.
- Commit messages: imperative present (`add`, `fix`, `update`), wrap the
  body at ~72 cols.
- Rebase on `main` before opening for review. Don't merge `main` in.

## Tests

```bash
# Backend
cargo test                                   # default OSS suite
cargo test --workspace --features enterprise # enterprise build (if you have access)
cargo test -p nanosiem-api openapi::tests    # OpenAPI spec + contract self-check

# Privileged cell fixtures (requires delegated mount/cgroup sandbox)
cargo test -p nanosiem-lake-cell --features sandbox-integration --test isolation --test zero_downtime_roll

# Frontend
cd nanosiem-web
npm test
VITE_EDITION=open npm run build               # vite + tsc strict
```

For changes touching the nPL compiler or VRL parsers, run the relevant
integration suite (see `tests/`). Generated VRL templates need a
`vrl::compiler::compile` round-trip in tests — Rust can't see inside string
literals.

## Code review

We expect:

- **No SOLID violations introduced.** New files should not balloon
  responsibility — pull a service or repository if a handler grows past
  ~200 lines.
- **No unbounded queries.** Log queries must carry a time range and
  respect the default row limit.
- **Parameterized SQL only.** Bind every value with sqlx on the Rust
  side; no string-format SQL anywhere.
- **OpenAPI annotations on every new handler.** Follow the handler-local
  `utoipa::path` and `ApiDoc` registration pattern. The `openapi::tests` suite enforces path counts and API contracts.

Before pushing, run `cargo fmt`, `cargo clippy --all-targets --workspace`,
and `cargo test`. The CI will, but doing it locally is faster than a round
trip.

## Reporting bugs / requesting features

Use the [issue templates](./.github/ISSUE_TEMPLATE/). For security issues,
see [SECURITY.md](./SECURITY.md) — please don't file them as public issues.

## Code of Conduct

We follow the [Contributor Covenant v2.1](./CODE_OF_CONDUCT.md). Conduct
issues go to [conduct@nano.rs](mailto:conduct@nano.rs).

## License

By contributing, you agree your contribution is licensed under AGPL-3.0
(matching the rest of the engine) and that the ICLA grants Nano LLC the
sublicensing rights described therein.
