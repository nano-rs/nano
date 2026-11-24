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
enterprise build, nano, LLC needs the right to sublicense your contribution.
DCO grants too little; an ICLA is the smallest tool that does the job. The
text is adapted from the Apache ICLA — it gives you a copyright, doesn't
take it away.

## Dev environment

Prerequisites:

- Rust 1.100 or newer. `rust-toolchain.toml` pins the exact toolchain and rustup
  installs it on the first build; nightly is not required
- Node 22 LTS and npm (`.nvmrc` pins the major for local tools and CI; the web image builds on the same major)
- PostgreSQL 16 to 18 (nano ships 17)
- ClickHouse 26.3.62.3 (LTS) or newer; see
  [Supported versions](docs/administration/supported-versions.md)
- Optional: `cargo-watch`, `sqlx-cli`

> **Note on the local-dev story.** A polished `docker-compose.yml` +
> `.env.example` for one-command setup is in flight. Until that lands, run
> Postgres + ClickHouse via whatever local tooling you prefer (Homebrew,
> the official ClickHouse / Postgres container images directly, etc.) and
> follow the bare-host path below.

Bare-host setup:

```bash
git clone https://github.com/nano-rs/nano.git
cd nanosiem

# Run migrations against your local Postgres + ClickHouse
cargo run --bin clickhouse_migrator
sqlx migrate run --source migrations/postgres

# Start services
cargo run --bin nanosiem-api &       # :3000
cargo run --bin nanosiem-search &    # :3002

# Frontend
cd nanosiem-web && npm install && npm run dev   # :5173
```

The exact env-var contract is in
`nanosiem-api/src/config.rs` — at minimum you'll set the Postgres and
ClickHouse connection strings.

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
cargo test --workspace                       # full suite (open build)
cargo test --workspace --features enterprise # enterprise build (if you have access)
cargo test -p nanosiem-api openapi::tests    # OpenAPI spec + contract self-check

# Frontend
cd nanosiem-web
npm test
npm run build                                # vite + tsc strict — catches what dev hides
```

For changes touching ClickHouse schema or VRL parsers, run the relevant
integration suite (see `tests/`). Generated VRL templates need a
`vrl::compiler::compile` round-trip in tests — Rust can't see inside string
literals.

## Code review

We expect:

- **No SOLID violations introduced.** New files should not balloon
  responsibility — pull a service or repository if a handler grows past
  ~200 lines.
- **No unbounded queries.** ClickHouse code paths must filter on
  `timestamp` and respect the 100k default row limit.
- **Parameterized SQL only.** sqlx with compile-time verification on the
  Rust side; no string-format SQL anywhere.
- **OpenAPI annotations on every new handler.** See `CLAUDE.md` for the
  pattern. The `openapi::tests` suite enforces path counts and API contracts.

Before pushing, run `cargo fmt`, `cargo clippy --all-targets --workspace`,
and `cargo test`. The CI will, but doing it locally is faster than a round
trip.

### CI and the `ready-to-merge` label

Most PR checks run once, at merge time, rather than on every push. A
maintainer adds the `ready-to-merge` label when the PR is reviewed; that runs
every relevant gate, and any later push reruns them. Without the label only
workflow lint runs. See `docs-internal/ci-runner-pools.md` for the details.

## Reporting bugs / requesting features

Use the [issue templates](./.github/ISSUE_TEMPLATE/). For security issues,
see [SECURITY.md](./SECURITY.md) — please don't file them as public issues.

## Code of Conduct

We follow the [Contributor Covenant v2.1](./CODE_OF_CONDUCT.md). Conduct
issues go to [conduct@nano.rs](mailto:conduct@nano.rs).

## License

By contributing, you agree your contribution is licensed under AGPL-3.0
(matching the rest of the engine) and that the ICLA grants nano, LLC the
sublicensing rights described therein.
