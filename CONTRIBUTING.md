# Contributing to nano

Thank you for considering a contribution. nano is an open-core SIEM and we
take community patches seriously. This guide covers how to set up a dev
environment, the conventions we follow, and the contributor licensing
agreement (CLA) you'll be asked to sign on your first PR.

## Contributor License Agreement

Every contributor must sign the [Individual Contributor License Agreement
(ICLA)](./.github/ICLA.md) before we can merge a patch. The
[cla-assistant](https://cla-assistant.io) bot will gate your first PR. Sign
once via the GitHub OAuth flow, and you're set for all future PRs.

**Why a CLA, not DCO?** nano is open-core: the engine is AGPL-3.0, the
enterprise add-ons (Cases, pivt, meloD, risk) live in a separate proprietary
crate. To accept community patches into the engine and still ship the
enterprise build, nano, LLC needs the right to sublicense your contribution.
DCO grants too little; an ICLA is the smallest tool that does the job. The
text is adapted from the Apache ICLA: it gives you a copyright, doesn't
take it away.

## Dev environment

Prerequisites:

- Rust 1.100 or newer. `rust-toolchain.toml` pins the exact toolchain and rustup
  installs it on the first build; nightly is not required
- Node 22 LTS and npm (`.nvmrc` pins the major for local tools and CI; the web image builds on the same major)
- PostgreSQL 16 to 18 (nano ships 17)
- ClickHouse 26.3.62.3 (LTS) or newer
- Optional: `cargo-watch`, `sqlx-cli`

The quickest path is the dev script. It reads `.env`, sets local-only
defaults for everything else, starts PostgreSQL, ClickHouse and Vector in
Docker from `docker-compose.yml`, then builds and runs `nanosiem-api` (:3000),
`nanosiem-search` (:3002), `nanosiem-jobs` and the web UI (:5173):

```bash
git clone https://github.com/nano-rs/nano.git
cd nano
scripts/dev-env.sh                  # writes .env with fresh local secrets
(cd nanosiem-web && npm install)
EDITION=open NANO_SCHEMA_PROFILE=ocsf ./scripts/start-microservices-dev.sh
```

Set `EDITION=open`: this repository has no enterprise code, and the script
defaults to the enterprise build. Set `SKIP_INFRA=1` if you already run
PostgreSQL and ClickHouse yourself.

To run the binaries by hand instead, export the same settings the script
does (see the top of `scripts/start-microservices-dev.sh`). The services
refuse to start without these:

- `DATABASE_URL` and `CLICKHOUSE_URL` (plus `CLICKHOUSE_DATABASE`,
  `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`)
- `CLICKHOUSE_RAWSQL_PASSWORD` and `CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD`
- `JWT_SECRET` (32+ characters) and `NANOSIEM_ENCRYPTION_KEY`, or
  `NANOSIEM_ALLOW_DEFAULT_KEYS=true` for local development only

The full list is in `nanosiem-api/src/config.rs`.

The API docs are at <http://localhost:3000/swagger-ui/> once you sign in.

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
npm run build                                # vite + tsc strict; catches what dev hides
```

For changes touching ClickHouse schema or VRL parsers, run the relevant
integration suite (`nanosiem-core/tests/`, `nanosiem-api/tests/` and the
black-box scenarios in `e2e/tests/`). Generated VRL templates need a
`vrl::compiler::compile` round-trip in tests, because Rust can't see inside string
literals.

## Code review

We expect:

- **No SOLID violations introduced.** New files should not balloon
  responsibility: pull a service or repository if a handler grows past
  ~200 lines.
- **No unbounded queries.** ClickHouse code paths must filter on
  `timestamp` and respect the 100k default row limit.
- **Parameterized SQL only.** sqlx with compile-time verification on the
  Rust side; no string-format SQL anywhere.
- **OpenAPI annotations on every new handler.** Add `#[utoipa::path(...)]`
  to the handler and register it in the `*ApiDoc` struct at the bottom of its
  file. The `openapi::tests` suite enforces path counts and API contracts.

Before pushing, run `cargo fmt`, `cargo clippy --all-targets --workspace`,
and `cargo test`. The CI will, but doing it locally is faster than a round
trip.

### CI and the `ready-to-merge` label

Most PR checks run once, at merge time, rather than on every push. A
maintainer adds the `ready-to-merge` label when the PR is reviewed; that runs
every relevant gate, and any later push reruns them. Without the label only
workflow lint runs.

## Reporting bugs / requesting features

Use the [issue templates](./.github/ISSUE_TEMPLATE/). For security issues,
see [SECURITY.md](./SECURITY.md). Please don't file them as public issues.

## Code of Conduct

We follow the [Contributor Covenant v2.1](./CODE_OF_CONDUCT.md). Conduct
issues go to [conduct@nano.rs](mailto:conduct@nano.rs).

## License

By contributing, you agree your contribution is licensed under AGPL-3.0
(matching the rest of the engine) and that the ICLA grants nano, LLC the
sublicensing rights described therein.
