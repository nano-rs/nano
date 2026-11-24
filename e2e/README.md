# nano-e2e: scenario harness

Black-box end-to-end scenarios for the nano ClickHouse product (NAN-4920).
The runner brings up a throwaway stack, the Python scenarios drive it over
HTTP (and real cloud test resources), and everything is torn down afterwards.

Python is used here because these are tests of the app through its API. No
product code lives in this directory.

## Quick start

```bash
scripts/e2e.sh doctor             # prerequisites + which cloud credentials are present
scripts/e2e.sh run base           # up + base suite + down
scripts/e2e.sh run fast           # base + ingest
scripts/e2e.sh run all            # every suite (cloud scenarios skip without credentials)

# Iterate against a kept stack:
scripts/e2e.sh up                 # prints the stack.env path
scripts/e2e.sh run ingest -- -k rotate -x   # reuses the live stack from `up`
scripts/e2e.sh down --run <runid> [--purge]
```

Suites map to `e2e/tests`: `base`, `ingest`, `onboarding`, `detection`,
`search_jobs`, `pull` (the directory), `ui` (browser, phase 2), `enterprise`,
`content_acceptance` (NAN-4955's signed local publisher + GitHub sinkhole),
`zero_clicks` (NAN-5763, below), or `all` / `fast`.
Anything after `--` goes to pytest.

### Trust config: release by default (NAN-5771)

A bare `up` builds what a release build trusts: production content and
catalog keys only. The non-shippable test-key composition
(`--cfg nano_content_acceptance` with `NANO_NON_RELEASE_BUILD=1`) is opt-in.
It needs a native enterprise stack, and you get it from any of these:

- `up --acceptance-trust`
- `up --profile soar-lab` (the SOAR lab transport exists only under the cfg)
- `run content_acceptance`, `run soar`, `run all`, or a bare `run`. These
  suites set it themselves.

The trust config is printed at bring-up, with a loud `TEST BUILD` banner for
test trust. It is recorded as `E2E_TRUST` (`production` or
`production+acceptance`) in `run.env` and `stack.env`, and shown by `status`.

Every check fails closed:

- The build never takes trust from the caller's environment. A `RUSTFLAGS`,
  `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS` or
  `CARGO_TARGET_*_RUSTFLAGS` carrying the cfg is refused, and an inherited
  `NANO_NON_RELEASE_BUILD` is stripped.
- `nanosiem-api` and `nanosiem-jobs` print their compiled trust with
  `--print-content-trust`. The harness checks both after the build and before
  every native start (`up`, `run` reuse, `svc start|restart`), so a stale
  `--no-build` binary is refused.
- After the admin bootstrap, `GET /api/content/channels` must report
  `E2E_TRUST`. A 500, 401/403, network error or bad body fails like a
  mismatch. The only exception is a 404 on a published image
  (`--app image:<tag>`), which predates the endpoint: that prints a warning.
  On `--defer-admin` stacks, `nano_e2e.firstrun` runs the same check
  (`nano_e2e.trust`) once it mints the key.
- A reused stack must match what the run asked for: `--acceptance-trust` or
  `--profile soar-lab` never reuse a production stack.
- Test trust with `--release`, a non-native app mode, `--edition open` or
  `--target existing` is refused. A set-but-empty `CARGO_ENCODED_RUSTFLAGS`
  counts as set.

Use a default `up` for any fresh-install or trust check.

### What `up` does

1. It creates the compose project `nanoe2e-<runid>` (`runid` = `<user>-<8 hex>`)
   from `docker-compose.opensource.yml` plus `dev/e2e/compose.e2e.yml`. The
   stack runs PostgreSQL 17, ClickHouse 26.10 (single node), Valkey and the
   Vector 0.61 fork. Every port is an ephemeral `127.0.0.1` port. Containers
   are named `nanoe2e-<runid>-*`. It never touches `nanoch-*` or any other
   project.
2. It starts the app:
   - **native** (the macOS default): `cargo build` with the repo's
     `rust-toolchain.toml` (1.100), then the migrator, `nanosiem-search`,
     `nanosiem-jobs` and `nanosiem-api` as host processes on free ports.
   - **docker** (the Linux default): `docker build --target api|search|jobs`
     from this tree.
   - **image:\<tag\>**: published release images. `--edition open` pulls the
     open-core `ghcr.io/nano-rs/nano-*`; `--edition enterprise` pulls the
     enterprise build (`E2E_ENTERPRISE_IMAGE_PREFIX`, default
     `us-central1-docker.pkg.dev/nano-rs/nanosiem-customer/nanosiem`; needs a
     registry login). A released enterprise image starts license-locked.
3. It creates the local admin through `/api/setup/initialize` and mints an
   admin API key.
4. It writes `target/e2e/<runid>/stack.env` (mode 0600). This one file holds
   every legacy test env-var spelling:
   - ClickHouse: `NANOSIEM_TEST_CLICKHOUSE_URL`, `CLICKHOUSE_TEST_URL`,
     `CLICKHOUSE_URL`, `SOAR_TEST_CLICKHOUSE_*`, `MIGRATOR_BOOTSTRAP_CH_*`,
     `CLICKHOUSE_SELF_*`.
   - PostgreSQL: `DATABASE_URL`, `TEST_DATABASE_URL`,
     `NANOSIEM_TEST_DATABASE_URL`, `NANO_TEST_DATABASE_URL`.
   - Redis: `NANOSIEM_TEST_REDIS_URL`, `REDIS_URL`.
   - Other: `NANOSIEM_TEST_VECTOR_IMAGE`, `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1`,
     the app URLs, and `NANOSIEM_API_KEY`.

   To export it into a shell:
   `set -a; . "$(scripts/e2e.sh env)"; set +a`.

Secrets are generated for each run, never printed, and scrubbed from
artifacts.

### Artifacts

Each run writes to `target/e2e/<runid>/artifacts/`:

- `build.log`, `migrator.log`, compose logs, and native service logs
  (`logs/`)
- the rendered Vector source configs and Vector `/metrics` at the end
- ClickHouse `system.query_log` and `system.errors` for the run window
  (`ch-query-log.tsv`, `ch-errors.tsv`)
- a redacted `stack.env`
- JUnit XML
- per scenario (`scenarios/<test>/`): `api.jsonl` (every API exchange,
  secrets redacted) and `timeline.jsonl` (each step, its time and what it
  observed)

### Restarts from scenarios

`scripts/e2e.sh svc restart|stop|start|kill api|search|jobs|vector --run <id>`
behaves the same way in native and docker mode. Scenarios call it through
`Stack.svc()`, for example to restart Vector in the middle of a pull.

### Licensing enterprise stacks (offline C05 trial)

Enterprise stacks start license-locked. An offline C05 license is bound to the
installation identity (`installation_id`, `organization_id`). The enterprise
migration generates a random identity, so without a pin every `--fresh` stack
would need its own license. Pin the identity once and one trial license serves
every run:

1. Get an identity to license. Pick two ids matching
   `^[a-z0-9][a-z0-9_-]{0,63}$` (for example `e2e-inst` and `e2e-org`).
   Or bring up a stack and read its generated ids:
   `scripts/e2e.sh up --edition enterprise`, then
   `scripts/e2e.sh license-ids [--run <id>]`. That prints `installation_id=`,
   `organization_id=` and whether a license is installed.
2. Issue the trial. In app.nano.rs go to admin → Licenses, issue a
   **Self-run trial** for those two ids, and download the offline license
   file.
3. Store the file outside the repository, readable only by you:

   ```bash
   mkdir -p ~/.nano-e2e && mv ~/Downloads/<license>.json ~/.nano-e2e/c05-trial.json
   chmod 600 ~/.nano-e2e/c05-trial.json
   ```

4. Set the env vars (for example in your shell profile).
   `NANO_E2E_INSTALLATION_ID` and `NANO_E2E_INSTALLATION_ORG_ID` must be the
   exact ids **the license file is bound to**, not ids you picked or remember.
   If they differ, the import fails with a binding mismatch. Read them from
   the file's binding block. This prints only the two ids, never the
   signature or other claims:

   ```bash
   jq -r '.claims.entitlement.binding | "installation_id=\(.installation_id)\norganization_id=\(.organization_id)"' \
     ~/.nano-e2e/c05-trial.json
   ```

   Then export them, read straight from the same file:

   ```bash
   export NANO_E2E_C05_LICENSE_FILE=~/.nano-e2e/c05-trial.json
   export NANO_E2E_INSTALLATION_ID="$(jq -r '.claims.entitlement.binding.installation_id' "$NANO_E2E_C05_LICENSE_FILE")"
   export NANO_E2E_INSTALLATION_ORG_ID="$(jq -r '.claims.entitlement.binding.organization_id' "$NANO_E2E_C05_LICENSE_FILE")"
   ```

What the harness does with them (enterprise edition only; `--edition open`
ignores them with a warning):

- `up` validates them before it creates anything. The two ids must be set
  together and match the pattern. The file must be an absolute path to a
  regular file you own (not a symlink), mode 0600, 1 byte to 256 KiB, and
  outside this checkout. `scripts/e2e.sh doctor` runs the same checks.
- After the migrator runs and **before any app process starts**, `up`
  replaces the identity the migration generated with the pinned one. Nothing
  else depends on the identity yet: the fingerprint is derived from the two
  ids, and license state, the license ledger and the ClickHouse clock witness
  only exist after an import. The update runs in one locked transaction. It
  refuses (and `up` fails) if any license state or ledger row exists, and it
  is a no-op when the identity already matches. There is no product-side way
  to set the identity; only the harness does this, directly in its throwaway
  PostgreSQL.
- Once the stack is healthy and the admin exists, `up` imports the file with
  `POST /api/license/import` and fails loudly unless `GET /api/license` then
  reports `state=active`, `valid=true` and the pinned identity. With
  `--defer-admin` (the `ui` and `personas` suites), the deferred first-run
  setup imports it right after it mints the admin key.
- The file's contents are never printed, logged, journaled or copied. Errors
  name the file and the API status, never its bytes. The artifact guard
  scrubs the contents by reading the file where it lives
  (`--secret-file`); they are never written into the run dir.

A trial expires. When it does, imports fail with "license NOT active"; issue a
new trial for the same two ids and replace the file.

## UI coverage manifest: adding coverage with a feature (NAN-5681)

Every user-facing surface has an entry in `e2e/coverage/ui-surfaces.json`,
and the release preflight refuses a release when one is missing. Surfaces
are every route in `nanosiem-web/src/App.tsx` (redirects excepted), every
rail nav item (`AppLayout.tsx`) and Settings section
(`components/layout/settings/sections.ts`), plus hand-added `action:<name>`
entries for major actions inside a page.

When you build a feature with UI:

1. Write its e2e scenario next to the closest existing one (`tests/ui/` for
   open core, `tests/enterprise/ui/` for enterprise, a persona journey under
   `tests/personas/`). Act as a throwaway `limited_user` with explicit
   permissions, compare what the page shows with the API, register cleanup.
2. Add or update its manifest entry. The key is the route exactly as
   `App.tsx` spells it (`/automation/flows/:id`) or an `action:` id:
   ```json
   "/my/new-page": {"tests": ["tests/ui/test_my_page.py::test_it_lists_things"], "smoke": true},
   "action:soar.case-steps": {"tests": ["tests/enterprise/ui/test_v2034_soar_case_steps.py"]}
   ```
   A reference is a `test_*.py` module and a `test_*` function in it.
   `"smoke": true` puts a static page in `tests/ui/test_page_smoke.py`, which
   visits each such page and fails on an error boundary, the client-side 404
   page, an error toast, a console error or any failed request; cite the smoke
   test only together with `"smoke": true`. `"edition": "enterprise"` keeps it
   off open stacks. A surface the harness truly cannot reach gets
   `"skip": "<why, in a sentence>"` instead of `tests`; skips are listed on
   every check, so keep them honest.
   A product bug found by a scenario is pinned on the failing STEP only, never
   the whole test:
   ```python
   from nano_e2e.known_bugs import known_bug
   with known_bug("NAN-5687", r"Run failed to queue"):
       assert not failed, "Run failed to queue"
   ```
   The step is XFAIL while the signature matches, any other failure propagates,
   and the test FAILS once the step passes (remove the wrapper then). The
   signature must describe the bug's own symptom (`re.search` on the message
   of a `raises=` type, default `AssertionError`, plus an optional `when=`
   predicate): catch-alls (a pattern matching the empty string, a driver
   timeout, bare assertion text, an HTTP error or a static `BUG <slug>`) and
   `raises=Exception` are refused with `ValueError`. Keep the step's healthy
   preconditions outside the `with` (`selftest/test_known_bugs.py`). A test
   using `known_bug` or `xfail` never counts as covering a surface: an entry
   whose only tests are such needs `"known_broken": "NAN-<id> ..."`.
3. Add the release's items to `e2e/coverage/releases/v<x.y.z>.json` (the
   sidecar of `deploy/release/notes/v<x.y.z>.json`):
   `{"title": "...", "pr": 123, "ui": true, "surfaces": ["action:..."]}`, or
   `"ui": false, "reason": "..."` for backend-only work. EVERY surface a UI
   item names must have passing tests; otherwise the item carries a reasoned
   `"gap"`, printed on every run.
4. Check it (static, under a second, no browser):
   ```bash
   python3 scripts/release/check-e2e-coverage.py --release <x.y.z>
   python3 scripts/release/check-e2e-coverage.py --suggest   # tests that already visit missing surfaces
   ```
   The `e2e coverage manifest` workflow runs it on every PR that touches
   `App.tsx`, the nav files, `e2e/coverage/` or `e2e/tests/`;
   `scripts/release/preflight.sh` runs it with `--release` for the version
   being cut; `scripts/e2e.sh selftest` proves the gate catches each kind of
   drift. The gate is release tooling: the open-core mirror strips it with
   `scripts/release/` (its selftest and the release sidecars go too; the
   manifest stays for the smoke walk).

## Layout invariants on every page (NAN-5762)

Every browser scenario measures the layout of every state it reaches. There is
nothing to call: `UiPage.op` (`nano_e2e/ui.py`) runs the driver's
`layout_check` after each op, and the driver scans the page whenever its
fingerprint changes (route and query string, viewport width, theme, open
panels, selected / active / expanded controls, DOM size, loading state). The scan is `nanosiem-web/tests/e2e/ui/layout.mjs`:

| check | fails when |
|---|---|
| `overflow` | a scroll container scrolls sideways (`scrollWidth > clientWidth + 1`), or an element sticks out past the right edge of the main pane or a flyout / drawer / dialog. The app shell clips horizontal overflow at the document, so `document.scrollWidth` proves nothing; the main pane and each container are measured instead |
| `escape` | a visible element leaves its nearest card or panel by more than 2 px (8 px for absolutely positioned badges); text spilling out of its own box counts |
| `clipped` | the same inside a card that hides overflow: the part past the edge is cut off |
| `overdrawn` | a sampled link or button is not what `elementFromPoint` hits at its centre: a sibling is painted over it. Sticky headers, floating buttons, toasts and tooltips are ignored; under a modal only the modal's controls are sampled |

**Cards and panels.** The shared `<Card>` sets `data-layout-card`; sheets,
dialogs and drawers set `data-layout-panel`. Hand-rolled cards are detected
too: any box at least 120x32 px with a border on all four sides and rounded
corners that is not itself a control. `data-layout-card="off"` opts a box out.

**A failure** names the check, the route, the offending element and its card
or container (nearest `data-testid` first), writes `layout-<n>.png` with the
offenders outlined in magenta and appends
`layout.jsonl` in the scenario's `ui/` artifacts. A violation is confirmed by
a second scan 450 ms later (an animating sheet is not a bug), is never dropped
once confirmed, and is reported once per scenario. The final check at teardown
is forced.

**Secrets fail closed.** No screenshot is taken, and no element text goes into
`layout.jsonl`, while the page has a password field (even an empty one), a
known reveal-once element (API key, ingest token, invite password, MFA secret
or QR code, backup codes), a field a secret was typed into, or a registered
secret in the DOM, rendered text or a field value. Pending API bodies are read
first, so issued keys are known. Element text that is written is scrubbed of
registered secrets and of token-shaped strings (JWTs, key prefixes, long
mixed-case base64 runs). A violation a scenario swallowed (an `eventually` retry catches
`AssertionError`) still fails it at teardown.

**Intentional exceptions** go in `e2e/coverage/layout-allowlist.json`, each
with a reason: wide data tables and code blocks scroll sideways by design. A
bug that is being fixed can be allowlisted while its PR is open with
`"temporary": true, "issue": "NAN-<id>"`; the coverage gate lists every
temporary entry on each run, so remove it when the fix merges. A product bug
with no fix in flight is pinned like any other (`known_bug` on the step).

```bash
NANO_E2E_LAYOUT=report scripts/e2e.sh run ui ...   # record only (calibration); layout.jsonl per scenario
NANO_E2E_LAYOUT=off    scripts/e2e.sh run ui ...   # skip the scan
```

The coverage gate (`scripts/release/check-e2e-coverage.py`) fails when the
hook is gone from `UiPage.op`, when a covered surface has no covering test that
opens a browser page (so nothing measures it; an `action:` with nothing to
render, such as zero-click install content, says so in `"no_layout": "<why>"`), or when an allowlist entry has
no reason, no matcher, an unknown check, a surface that is not in the
manifest, or (temporary) no issue. `selftest/test_layout_invariants.py` proves
each check fires on the bug shape it exists for.

## Harness conventions

- **Run markers.** Every event carries `nano-e2e-<runid>-<hash(test)>`, and
  every assertion filters by it. Route keys and source types are
  `e2e_<hash>`.
- **No blind sleeps.** `waits.eventually()` and `waits.stays()` poll for an
  observable condition. On timeout they report the last value they saw.
- **Retries cover infrastructure only.** A request that never reached the
  server (connection refused or reset) is retried with backoff. Any HTTP
  response is the product talking and is never retried.
- **Search, not ClickHouse.** Assertions read through the search API, with
  `x-nano-cache-bypass: 1` and `use_cache: false`. Direct ClickHouse reads
  are for diagnostics only (the `query_log` artifact).
- **Editions.** Enterprise-only scenarios live in `tests/enterprise/` and are
  marked `@pytest.mark.enterprise`. They skip on `EDITION=open` and are
  dropped from the open-core mirror.
- **Schema profile.** Stacks come up OCSF (`NANO_SCHEMA_PROFILE=ocsf`), the
  install default. Set `NANO_SCHEMA_PROFILE=udm` explicitly for the legacy UDM
  profile. A scenario that only holds on UDM (its parser emits no `class_uid`,
  or it hunts on UDM columns) is marked `@pytest.mark.udm_only("<reason>")` and
  skips with that reason on OCSF. `nano_e2e.schema.is_ocsf()` is the one place
  scenarios read the profile. Porting the remaining `udm_only` scenarios is
  NAN-5594.

## Scenarios (phase 1)

| Suite | Scenario | Status on clickhouse/dev |
|---|---|---|
| base | health (api, search, jobs, Vector HEC); setup is one-shot; capabilities edition; login (bad password 401); API key create, use on api and search, least privilege, delete leads to 401 | runs |
| ingest | per-source token: HEC + HTTP land as the token's source; a spoofed sourcetype is kept only as the claim; unknown token 401; rotate (old 401, new 200); revoke 401; two sources isolated | runs |
| onboarding | draft source ingests before its parser is published; connect status `receiving_unparsed`; publish leads to new events being parsed | runs (udm only, NAN-5594) |
| vector_render | a draft (`http` spelling) deploys live, then a normal source, then a parser publish; a deploy Vector refuses is reported failed, rolled back, the draft disabled again, and the next deploy goes live; `${...}`/`$NAME` in parser VRL refused at save; `$` anchors, `$1` captures and the literal form run as written (NAN-4952/4953) | runs (udm only, NAN-5594) |
| delete_race | a bound Kafka pull parser, then its source config, deleted back to back: no Vector reload refused, a later publish goes live (NAN-4956) | runs (udm only, NAN-5594) |
| hec_ocsf_lane | the connector delivery (platform token, `sourcetype=okta`) to the published `okta_ocsf` from nano-rs/parsers: parsed as User Management 3007, `metadata.log_source = okta`, found by `metadata.log_source="okta"` and `source_type="okta"`, not by `"unknown"` (NAN-4963) | runs |
| detection | Alerting rule: an alert carries the event. Live rule: a match is recorded, no alert | runs |
| search_jobs | durable job completes and its results page without loss or duplicates; `async_mode` returns a job handle; cancel | runs |
| pull | `aws_s3` (S3 to SQS notifications), `aws_sqs` payload, `gcp_pubsub` lifecycle: create, then events land, then a Vector restart (no loss, bounded duplicates), then pause/resume, then credential rotate, then delete | real cloud; skips without credentials |
| pull | `azure_event_hubs` lifecycle | real cloud (NAN-4914) |
| ui: search URLs (NAN-4927) | a legacy `?q=` link migrates the hunt into the fragment and a reload never sends it in a page URL; a relative range stays relative through run and reload; `view=rarity` opens rarity; hunt in API GET query strings is an xfail finding | runs (ocsf) |
| ui: Nano Pipe (NAN-4919) | Add step > Filter, Save draft (nano-pipe-v2 plan in the API), paste sample + Run preview == `/pipe-preview`, publish twice, History > Rollback == versions API | runs (`NANO_PIPE_PREVIEW_ENABLED`) |
| ui: audit (NAN-4930) | API-key actor label == audit API; Action filter round-trips the URL; Export CSV == rows on screen, every cell quoted, a formula-shaped name neutralized | runs |
| ui: SSO (v2 entitlements) | login shows no SSO without providers; open build says the deployment lacks SSO; enterprise: every licensed capacity mounts the provider page, including retired tier inputs normalized to `licensed` | runs |
| ui: RBAC persona matrix (NAN-5686) | every built-in role (from the migrations) and one custom role, as throwaway users: every top-level page opens, or shows `route-forbidden` having fetched no data first; neither rail (every group opened) shows a refused or dead item; core and enterprise API actions succeed or answer a clean 403; gated controls hide. Expectations are generated from `App.tsx`, the rails and `/api/roles` (`nano_e2e.rbac_matrix`) and cross-checked against the hand-maintained `e2e/coverage/rbac-baseline.json` (sensitive pages, APIs and never-held permissions per role), so widening access fails until the baseline is edited on purpose; unknown permission strings and an unexpected `*` fail | runs |
| ui: source-restricted users (NAN-5686) | run-unique B data is absent for a non-granted analyst from search, stats, field values/stats, the stream, search jobs (export), dashboard panels, prevalence, risk, hunts leads, alerts (list, by rule, 404 by id) and cases (list, 404 by id, search), and from every API response the browser received; a granted analyst is the positive control on each surface | runs |
| ui: deep detection engineering (NAN-5686) | nPL rule typed in the editor: Invalid with the reason, Test rule == test API, Create persists frontmatter; staging records nothing, live counts matches with no alert, alerting fires; matches page == matches API; MITRE coverage page; RBA entity risk; save v2 and revert to v1; "Automated" folder and the folder chip; retro-hunt form; alert cooldown round trip; repository import and Update available | runs |
| ui: deep onboarding, lookups, IOC, admin (NAN-5686) | HTTP JSON wizard with a VRL compile error then a valid OCSF parser, published and searchable; parser editor draft, test lab, publish v2; lookup CSV upload, add row, `| lookup` in search and a rule; IOC list stamps events and fires an alert; users invite/disable/enable/delete, custom role, API key revoke, TOTP enrollment, session revoke, retention, SIEM Health, notification channel, AI provider dummy key | runs (live tap skips without a tap relay) |
| ui: lookups (NAN-4924) | delete of a table a rule uses is refused naming the rule; Replace data swaps schema and rows (rows API + table page); delete succeeds once the rule is gone | runs |
| ui: IPinfo bundle-only (NAN-4959) | catalog entry has no credential field and the configure API refuses a BYO `download_url` (422); retired IPinfo configure / sync / auto-sync endpoints 404; the IPinfo Lite inventory drawer and the connection drawer Config tab show the bundle status (revision == platform feed status, last update, next refresh) with no inputs and no Configure / Uninstall | runs |
| ui: edition affordances | open: every enterprise route shows the entitlement panel or redirects (5 answer "Access Denied": xfail finding), every rail link opens a page, no uncaught page errors; enterprise: none of those routes serves the open placeholder | runs |
| enterprise ui: SOAR (NAN-4911) | switched on in Settings > SOAR (the API refuses an API key); flow run from its row (No-op + Search): run detail == run/steps API; Approval step suspends, a second user approves from Approvals, run resumes; requester cannot approve; `soar:view` cannot run | runs (jobs executor) |
| enterprise `soar` closeout (NAN-4911) | signed catalog import and tamper refusal; real ClickHouse detection → Search → deterministic Judge → two-person Okta suspend → Mailpit STARTTLS email; case wall and secret-free run trace; `iam.suspend_user` playbook; RFC1918/analyst denial; disable cancellation fence | runs (native app + owned `soar-lab` and `ai-stub` profiles; udm only until NAN-5594: `NANO_SCHEMA_PROFILE=udm scripts/e2e.sh run soar`) |
| enterprise `soar` storm (NAN-5618) | 5,000 alerts against a live alert flow: the hourly cap admits 60, records 540 as skipped, the spike breaker pauses the flow and counts the rest; a second flow runs its 60 to completion while the shared Okta connection stays at or under 30 calls per minute; a failing flow pauses after 5 failed runs; audit rows, SIEM Health finding, audited resume (`-- -k storm`) | runs (native app + `soar-lab`; OCSF) |
| enterprise ui: risk watchlists (NAN-4926) | a risk rule fires on OCSF events for a user; New watchlist (weight 0.5): rail == API; Risk index ×1.50 badge, effective and base == `/api/risk/entities`; detail sheet; `risk:view` alone sees no weight | runs |
| content_acceptance (NAN-4955) | fresh OCSF enterprise install consumes signed parser, rule, playbook, marketplace, model, MITRE ATT&CK and SOAR channels from a loopback app publisher while a deny-all proxy sinkholes GitHub; real catalogs + browser surfaces populate; tamper retains last-good; raw air-gap import advances the channel | `scripts/e2e.sh run content_acceptance --fresh` (native only) |
| zero_clicks (NAN-5763) | fresh install, data flowing, NOTHING clicked: open channels (parsers, rules, enrichments, MITRE ATT&CK) install and apply, official rules + parsers sync, the MITRE catalog comes from its channel; enterprise adds the playbooks / integrations / models channels, the SOAR catalog applied, official playbooks and hunts in the library, scheduled recon's profile + capability binding for the flowing source, hunt templates; the audit log holds no sync / import / check / recon action by a user or API key | `scripts/e2e.sh run zero_clicks [--edition open]` (runs alone on a stack it creates; skips anywhere else). Adds `--profile recon-fast` itself (scheduled recon is on in real installs, off on other e2e stacks). Every step is a plain assertion (guards NAN-5755, NAN-5757, NAN-5768, NAN-5769) |
| pull | connector feeds: Okta, Google Workspace, Slack, Netskope (`saas_api`) + a rejected credential | runs with the mock-vendor profile (phase 2, below) |
| enterprise | Nano Pipe pipelines (5 stubs) | skips: lands with NAN-4919 |

### Zero clicks (NAN-5763)

NAN-5755 (playbooks never reached the library) and NAN-5757 (recon never ran)
shipped because every scenario that looked at that content called the sync or
recon endpoint first. `zero_clicks` checks the install itself. It brings up a
fresh stack. First-run setup and the C05 license import run as an operator
would do them. Then it starts one log source with its own token, sending OCSF
Authentication events for the whole session, and only reads from then on.

- It must run alone, on a stack it creates: `run zero_clicks` refuses `--run`
  and other suites, and only then exports `E2E_ZERO_CLICKS=1`. Under `run all`
  or on a reused stack the scenarios skip.
- One budget for every wait (`E2E_ZERO_CLICKS_BUDGET_S`, default 900 s), so
  the run stays bounded however much is missing. A wait that runs out fails
  with the symptom (counts, channel status), which is what `known_bug`
  signatures match. The SOAR catalog wait runs last, on its own bounded
  slice: 360 s after the license import finished (`up` records the import
  window as `E2E_LICENSE_IMPORT_STARTED_AT` / `_FINISHED_AT`). An active
  license is asserted first. An enterprise `run zero_clicks` without the C05
  license env is refused.
- Two guards hold the no-clicks premise. In-process, every non-GET API
  request outside `ALLOWED_WRITES` (the data-flow source) is refused. Each
  module's last scenario asserts that the audit log (not degraded, fully
  paged, with this run's own setup rows present) holds none of
  `nano_e2e.zero_clicks.FORBIDDEN_ACTIONS` from a user or API key. That
  includes the manual playbook sync and import endpoints, which audit their
  caller (NAN-5784).
- It runs against the real content channels (`api.nano.rs`; enterprise
  channels use the imported license). Shared helpers are in
  `nano_e2e/zero_clicks.py`. The open-core module is `tests/zero_clicks/`; the
  enterprise companion is `tests/enterprise/zero_clicks/`, which the mirror
  strips.

## Phase 2: UI scenarios and the mock-vendor profile (NAN-4937)

```bash
scripts/e2e.sh run ui                     # own stack: OCSF profile, mock-vendor, first-run in the browser
scripts/e2e.sh run ui --edition open      # open core: enterprise scenarios report as SKIPPED
scripts/e2e.sh run ui --run <id> -- -k search   # against a kept stack
E2E_UI_HEADED=1 scripts/e2e.sh run ui ... # watch the browser
scripts/e2e.sh run personas              # all five role-based journeys
scripts/e2e.sh run personas --edition open # core paths + explicit AI boundary
```

On `--edition open`, the scenarios expect what the open build really shows
(NAN-5747):

- A capability-gated route renders the license panel ("<Feature> is not
  licensed", testid `licensed-feature-unavailable`).
- An `@/enterprise` stub without a capability gate renders "Available in nano
  paid plans".
- Persona and role permission sets are narrowed to the build's
  `GET /api/permissions`, through `nano_e2e.rbac.edition_permissions`. On
  enterprise a missing permission fails instead.

The panel copy lives in `nano_e2e/edition.py`. The release preflight runs
`python3 -I e2e/nano_e2e/edition.py` and stops when the web UI no longer
contains it.

### Persona journeys and deterministic AI

`run personas` is a UI suite: it builds the matching web edition, leaves
first-run setup to the browser harness, and uses the install-default OCSF
profile. Enterprise runs automatically add the `ai-stub` compose profile. The
stub is an owned, loopback-published OpenAI-compatible provider configured
through the product's normal provider/model settings APIs; no meloD path is
bypassed. Its artifact journal contains response kind, model, and a request
digest only—never prompts, log samples, or authorization headers. Open runs
exercise every core step and assert that pivt controls are absent.

An optional real-provider pass uses the same journeys and assertions without
starting the stub:

```bash
E2E_PERSONA_AI_MODE=real scripts/e2e.sh run personas --fresh --edition enterprise
```

Supply `NANO_E2E_AI_API_KEY`, `NANO_E2E_AI_BASE_URL`, and
`NANO_E2E_AI_MODEL` through the normal e2e credentials file or Doppler;
`NANO_E2E_AI_CONTEXT_WINDOW` defaults to `128000`. The endpoint must be a
public OpenAI-compatible API. This opt-in sends only the suite's synthetic
persona samples externally and may incur provider charges.

The shared framework is `nano_e2e.personas`: throwaway role/group/user login,
seeded OCSF ground truth, UI/API comparison helpers, source onboarding, and
acceptance checkpoints. Add later persona modules under `tests/personas/` and
reuse those helpers. Every browser context retains the normal automatic
failure screenshot/HTML/network artifacts; journeys also capture an explicit
final screenshot.

The suite's role and edition matrix is:

| Persona | Open core | Enterprise | Boundary proof |
| --- | --- | --- | --- |
| SOC analyst | Search, saved hunt, dashboard; pivt absent | Same journey plus deterministic pivt summary | Dashboard delete is hidden and API-forbidden |
| SIEM engineer | Source/parser lifecycle and RBAC | Same journey | User/role administration is hidden and API-forbidden |
| Detection engineer | nPL staging/live/alerting, signal and alert; Cases and pivt absent | Same lifecycle plus AI detection drafts and case creation | Rule delete is hidden and API-forbidden |
| Incident responder | Cases, notebooks, and SOAR are concretely absent | Alert pickup, auto-investigation and evidence, peer handoff, two-person SOAR, resolve/close, audit | Case delete is hidden and API-forbidden; requester cannot self-approve |
| Platform admin | Scoped API key and audit export; SSO/license surfaces and APIs absent | Same journey plus SSO configuration and license status | Read-only key viewer sees no create control and receives API 403 |

Persona roles declare explicit permission tuples. Created rules, cases, SOAR
flows, OIDC providers, API keys, users, groups, roles, sources, tokens, and
dashboards register strict cleanup as soon as their concrete identity is
known; cleanup runs every action and accepts only HTTP 200, 204, or 404.
Suite-wide AI provider/model/agent bindings and mutable case/SOAR settings are
snapshotted and restored from fixture finalizers, including on failures.

### Exploratory persona runs (NAN-5291)

Scripted journeys prove what we thought of; exploratory agents look for the
rest. Each agent follows a charter in `e2e/personas-explore/` against a kept
stack, using three tools (all read the kept stack's `stack.env`; `--run <id>`
picks one):

```bash
# VECTOR_MEM_LIMIT: all 67 first-party OCSF parsers OOM the 512M compose default
VECTOR_MEM_LIMIT=3G scripts/e2e.sh run personas --fresh --keep --edition enterprise --app image:<tag>
PY=e2e/.venv/bin/python
$PY -m nano_e2e.corpus                    # parsers-ocsf samples -> every OCSF class has data
$PY -m nano_e2e.field_invariants --ui --json /tmp/fi.json   # OCSF field-name invariants
$PY -m nano_e2e.explore start --persona soc_analyst         # step-by-step browser
$PY -m nano_e2e.explore search '*' --start 2000-01-01T00:00:00Z
$PY -m nano_e2e.explore screenshot /tmp/shot.png ; $PY -m nano_e2e.explore stop
```

- `nano_e2e.corpus` imports every `parsers-ocsf/*` parser LINKED from the
  stack's synced nano-rs/parsers copy, publishes it (the OCSF gate runs) and
  posts its bundled samples (the ~787 the gate checks) to Vector HEC with the
  platform token and `sourcetype=<lane>`. Samples keep native timestamps:
  search wide.
- `nano_e2e.field_invariants` collects every field name the API (schema,
  ext/unmapped keys, field stats, field usage, rule-validate suggestions,
  rule-repo coverage) and, with `--ui`, the browser (search autocomplete,
  results sidebar, rule editor, dashboard editor) shows, and checks it against
  `system.columns`, the JSON paths present in `event`/`unmapped` and the
  embedded OCSF contract: no doubled segment (`unmapped.unmapped`), no `ext.`,
  no absent `unmapped.<k>`, no UDM alias shown as a field. Also a scenario:
  `scripts/e2e.sh run field_invariants --run <id>`.
- `nano_e2e.explore` keeps one browser per `--session` in a background daemon
  (logged in as a throwaway persona user, deleted on `stop`). Every command
  prints JSON with the console errors and failed requests (>= 400) since the
  previous command. `idle N --reload` checks the return-after-idle page.

### Against an existing stack (`--target existing`, NAN-5586)

Some walks are worth running on a stack the harness did not create (a
developer's local tenant with real data and real AI):

```bash
E2E_TARGET_CREDS_FILE=~/.nano-e2e/local-user.txt \
  scripts/e2e.sh run ui --target existing -- -k hunts_ui_walk
```

- Nothing is brought up, restarted or torn down. Only scenarios marked
  `@pytest.mark.existing_target` run; every other scenario is skipped, because
  the rest of the suite assumes a throwaway stack it may reset.
- `E2E_TARGET_CREDS_FILE` is a `key=value` file, mode 0600, outside the repo:
  `email`, `password` and `api_key` of a NON-admin user the scenario acts as
  (a login as the install's admin can evict the owner's sessions), and
  optionally `lane_token` (an HEC ingest token for scenario data). Values are
  read in code, never printed, and scrubbed from the artifacts. The file always
  wins over a key or password already exported in the shell; a file naming
  the install admin (`E2E_TARGET_FORBIDDEN_EMAILS`, default `admin@nano.local`)
  or holding a secret under 8 characters is refused.
- `E2E_TARGET_WEB_URL` / `_API_URL` / `_SEARCH_URL` / `_HEC_URL` default to the
  local dev stack (`:5173`, `:3000`, `:3002`, `:8088`).
- The browser logs in through the UI and, at the end, ends only ITS OWN
  session (`DELETE /api/sessions/{id}`), never `POST /api/auth/logout`.
- A scenario marked `existing_target` must mutate only objects it creates, tag
  them, and remove them at the end.

### Deep Search, Dashboards and Notebooks workflows (NAN-5684)

`tests/ui/test_deep_search.py`, `tests/ui/test_deep_dashboards.py` and
`tests/enterprise/ui/test_deep_notebooks.py` work the product the way an
analyst does, on a realistic dataset, and compare what the page shows with
the API and with the seeded truth.

- **Data.** The session fixture `soc` (`nano_e2e.soc_seed`,
  `nano_e2e.fixtures_soc`) writes ~3,100 OCSF events into
  `nanosiem.ocsf_logs_raw` (what Vector writes): four source types
  (`deep_<tag>_auth|net|proc|dns`), 24 hosts, 15 users, 72 hours with a
  day/night shape and a dense last 30 minutes, a brute-force burst, and values
  seen exactly once (a service account, a binary and its SHA-256, a
  destination, a domain). The rows are generated from a fixed seed and the
  ground truth is computed from them. A kept stack re-run reuses the rows it
  already has.
- **Acting user.** One throwaway analyst per module (`deep.module_persona`):
  every login counts against the install's login rate limit, which a
  per-scenario login exhausts.
- **Known bugs.** A product bug found here is pinned with
  `known_bug("NAN-…", signature)` around the failing step, and its own
  narrow scenario; `deep.bug_assert` photographs the page first
  (`E2E_BUG_SCREENSHOT_DIR` collects the shots).
- **Hooks.** The scenarios read `data-testid`s added for them (results count,
  event rows, field values and sidebar rows, inspector tabs, time picker,
  saved-query rows, history, rarity dots with `data-rare` and
  `data-host-count`, dashboard panels with `data-panel-status`, notebook rows
  and entries).

### Realistic seed profile (NAN-5764)

Layout bugs such as NAN-5758 and NAN-5759 only show up with real-world volume
and string lengths, and the default e2e stack is nearly empty. The realistic
profile seeds a lived-in install before the first UI scenario:

```bash
scripts/e2e.sh run ui --seed realistic             # or E2E_SEED_PROFILE=realistic
e2e/.venv/bin/python -m nano_e2e.realistic_seed --run <id>   # by hand, on a kept stack
```

- **Content** (`nano_e2e.realistic_plan`, pure and deterministic, seed 5764):
  ~1,400 OCSF events (Authentication, Network and Process Activity) from 441
  hosts and 339 users, including unicode, apostrophes, a one-character user
  and 80+ character UPNs and FQDNs. It also holds 14 log sources: the
  publishing OCSF lane, four each of the push methods (`routed`,
  `splunk_hec`, `vector`) with long and unicode names, and one deleted. Fetch
  methods are left out: without a bound source configuration with real cloud
  credentials they break every Vector render (NAN-5789). There
  are 38 detection rules with snake_case names in the `Automated` folder, in
  every mode, with up to 18 tags; some are archived, two were imported and
  then deleted, and six fire real alerts. There are 30 cases with long
  unicode titles, in every status, one at the 32-tag limit, one untagged and
  two deleted. Six hunts have long titles and many tags; one is archived and
  three carry findings with long narratives. There are two profile drafts
  and three dashboards with long names. SOAR has every catalog pack
  installed and four manual flows whose runs leave 24 pending approvals, 10
  of them case-linked.
- **API only.** Events arrive through Vector HEC with the seed source's own
  ingest token. Everything else is created, archived, deleted, run or
  installed through the API. Hunt findings come from a registered desktop
  runner that claims a sweep and files a report whose evidence is the seeded
  events' ids. SOAR is switched on, and the flows are saved and run, by the
  stack admin's own interactive session, which is ended afterwards. Nothing
  writes to PostgreSQL or ClickHouse directly.
- **Idempotent.** Every name carries the stable `rs5764` key (no run id), so
  each step lists what is there and adds only what is missing. Events are
  matched by `metadata.uid`. Objects the plan deletes are found in the audit
  log, and pending approvals are topped up to 24 (they expire after at most
  24 h). A second run on the same stack creates nothing. On a fresh local
  enterprise stack the first run takes about 3.5 minutes (mostly the case
  tags and the 24 approval runs) and a re-run about 4 seconds.
- **Opt-in.** The autouse fixture `nano_e2e.fixtures_seed` does nothing
  unless the profile is selected, so the default UI run keeps its speed.
- **Throwaway stacks only, with no override** (`realistic_seed.check_target`).
  Before the first request, the seed checks every one of these:
  - the run dir is this checkout's `target/e2e/<run id>/`, and its
    `compose.env` marker names the project `nanoe2e-<run id>`, this checkout
    as owner, and the OCSF profile;
  - the stack's containers carry the harness's `nano.e2e.project` and
    `nano.e2e.owner` labels;
  - the API, search and HEC URLs are loopback on ephemeral ports.

  It refuses `--target existing`, the UDM profile, Dan's dev ports
  (3000/3002/5173), any `*.nano.rs` host and any non-loopback host. The CLI
  exits 2 on a refusal, and the runner rejects `--seed` with
  `--target existing`, with `zero_clicks`, or with an unknown profile.
- **Resumable.** Each item is checked on its own, so an interrupted run is
  finished by the next one:
  - a source left as a draft is published;
  - a source, case or imported rule the plan deletes is deleted if it still
    exists;
  - hunt findings go only onto their own hunt's sweep. A claim that returns
    another hunt's sweep is never reported on, and a sweep that an
    interrupted run still holds is reported under its fence;
  - pending approvals are counted as the seeded flows' unfinished runs.
- **Secrets.** The session's access and refresh tokens and each ingest token
  are registered with the artifact guard and the API journal. Ingest tokens
  are revoked once the events are in, and the CLI scrubs the run's
  artifacts before it exits.
- **Gaps.** A step the stack cannot do is recorded as a gap, not a failure,
  for example when the SOAR catalog channel has not applied within
  `E2E_SEED_CATALOG_WAIT_S` (default 420 s) or on the open edition (no
  cases, hunts or SOAR). Gaps are printed and written to
  `<artifacts>/realistic-seed.json` with the per-step counts and timings.
  `E2E_SEED_STRICT=1` makes any gap a failure.
- **Selftests:**
  - `selftest/test_realistic_seed.py` keeps the plan from shrinking back: the
    issue's minimums, unicode and long strings, dead objects, snake_case
    rules in `Automated`, OCSF only, and determinism.
  - `test_realistic_seed_apply.py` runs `apply()` against an in-memory API
    (`selftest/fake_nano_api.py`). A re-run creates nothing and lists flows
    once. The seed is interrupted at nine risky steps and must resume
    without duplicates, a foreign sweep must never be reported on, and the
    test checks token revocation and secret scrubbing.
  - `test_realistic_seed_guard.py` covers every refusal.

### Hunts UI walk (NAN-5586)

`tests/enterprise/ui/test_hunts_ui_walk.py` walks every hunts page as an
analyst and does the work in the UI: a hunt from a template, the playbook
edited, Run now and the sweep sheet, the findings inbox, dismiss / promote /
acknowledge, Memory, Rulings, Campaigns, Escalations, Runners, the gate copy,
Agent Models, and basic pivt (a question answered; a "publish X" proposal that
changes nothing until Apply). Every page is checked for console errors, failed
API calls (403 allowed), horizontal overflow at 1440 and 1280, and is
photographed light and dark. Steps are soft: `walk/walk-results.json` lists
pass / fail / skip per step and the health of each page; a step needing a
feature the target lacks skips with the reason. Real AI spend is reported and
asserted under `E2E_UIWALK_MAX_USD` (default 3; the sweep's investigator and
reviewer tokens, an unpriced model charged at a conservative rate). On a
throwaway stack the walk runs only with `E2E_UIWALK=1`.

**The server hunt runner on a native stack (NAN-5732).** Native jobs reaches
ClickHouse on 127.0.0.1, and Agent Lane refuses a loopback HOST IP. Without a
fix the runner stays "unavailable" and every server sweep stays queued, so the
hunter personas time out. `up` asks ClickHouse which address it sees for this
host (the Docker bridge gateway, e.g. `172.22.0.1`) and exports it as
`NANO_HUNTS_RUNNER_CIDR` in `app.env`. A `NANO_HUNTS_RUNNER_CIDR` already set
in your shell wins. Docker and image app modes don't need this, because there
the runner derives its container IP, as Compose and Helm installs do.

### Deep SOC workflows (NAN-5685)

`tests/enterprise/ui/test_deep_*.py` work alerts, cases, hunts and SOAR as a
team of throwaway people (`nano_e2e.soc_team`: tier 1, tier 2, a manager;
never an admin) over real alerts from real rules on OCSF events:

```bash
scripts/e2e.sh run soar ui --fresh --edition enterprise --keep -- -k test_deep_
```

| File | What a team does |
|---|---|
| `test_deep_alert_triage.py` | list search / severity / status filters and the Sev sort == API; detail tabs; acknowledge, bulk acknowledge, assign (notification), close as false positive with each refusal; Add to case; a rule's next alert grouped into its first alert's case; a risk notable's RBA breakdown |
| `test_deep_cases_team.py` | New investigation, assign / reassign (bell, Mine), a note, v2.0.34 tags, case search, every pending kind and Resume, close (False positive, Inconclusive) and reopen, tier 1 refused close, escalation, a bounced handoff (API: no UI), workflow events and the audit trail |
| `test_deep_hunts.py` | template -> floor, duplicate window (invalid refused), charter v1/v2 and restore, schedule, enable, Run now; seeded findings: manual ruling, dismiss with expiry, promote -> case close -> case_close ruling that follows a reclose; Main / My team / Private queues, held promote / dismiss, Mark wrong from the case |
| `test_deep_soar.py` | a live alert flow (case steps around an approval) on a real detection: requester and tier 1 refused, tier 2 approves on the case, Automation pane, run trace; breaker banner and audited resume; live save bumps vN; pack browsing and install |

Open bugs are pinned with `known_bug` on the failing step. The steps for
NAN-5689, NAN-5690, NAN-5691, NAN-5692 (fixed in #10110), NAN-5697,
NAN-5698, NAN-5700 (fixed in #10107) and NAN-5720 (fixed in #10117) assert
normally. Set `E2E_BUG_SHOT_DIR` to
collect the pinned bugs' screenshots in one place.

### The browser layer

- The browser is driven by `nanosiem-web/tests/e2e/ui/driver.mjs`. It uses
  puppeteer-core, the dependency the repo already ships for
  `crawl-404.mjs`, and a locally installed Chrome or Chromium (`CHROME_PATH`,
  otherwise the usual install paths). No second browser dependency is used.
- The Python harness starts one driver per session and talks to it over JSON
  lines (`nano_e2e.ui`). Each op performs a UI action and returns what the
  page shows, and the scenario compares that to the API or ClickHouse.
- Each scenario gets its own browser context, logged in through the login UI
  (`page`), or a logged-out one (`anon_page`).
- `run ui` builds `nanosiem-web` for the stack's edition, cached under
  `target/e2e/web/<edition>-<tree hash>`, and checks for Chrome and
  `puppeteer-core`. `E2E_WEB_DIST=<dir>` drives another branch's build
  instead.
- **The edge.** `up` starts `edge`, an nginx rendered from the shipped
  `config/nginx/nginx.opensource.conf`. Only its upstreams are rewritten, and
  the SPA is served from the run dir. The browser, the copied Add-source
  snippets (`NANO_INGEST_PUBLIC_BASE_URL` points at it) and the OpenTelemetry
  Collector all go through it, exactly like a customer's install (`/api`,
  `/ingest`, `/otlp` with its `auth_request`). A stack without an edge falls
  back to the in-process proxy, `nano_e2e.web.WebServer`.
- **Secrets** reach the driver only over stdin. The driver's environment has
  them stripped, every artifact is scrubbed of them, and fields that held one
  are blanked before a screenshot. Scenarios also assert that a token or
  credential never shows again, both in the DOM (`page.contains`) and in API
  responses (`page.responses_containing`, which returns `METHOD /path` only).
- **Artifacts,** under `artifacts/scenarios/<test>/ui/`:
  - always: `console.log` (including accepted dialogs);
  - on failure: `failure.png`, `page.html` and `network.jsonl`.
  - on a layout violation (NAN-5762): `layout-<n>.png` and `layout.jsonl`.
- **Logins.** The driver waits for in-flight `/api/auth/*` requests before it
  navigates. Navigating away mid-refresh loses the rotated refresh cookie, and
  the next page is then logged out (finding below).

**Ingestion layout (NAN-4941).** The ingestion scenarios target the Log
Sources tabs:
- `/ingestion/log-sources/{credentials,cloud-pull,pull-feeds,repositories}`;
- a source config at `/ingestion/log-sources/inputs/:id`;
- the test ids `cloud-pull-sources`, `add-source-connection`,
  `credential-picker[-selected]`, `add-credential-sheet` and
  `pull-feeds-page` / `pull-feeds-region`.

On Cloud pull, the connection and the credential are part of the add sheet,
and secrets are entered inline. The scenarios detect the layout from what the
build renders (`ui_pull.ingestion_layout`) and fall back to the pre-4941 pages
on a build without the tabs. `test_ingestion_redirects.py` asserts that the
retired paths (`/ingestion/source-configurations[/:id]`,
`/ingestion/credentials*`, `/ingestion/pull-feeds`,
`/ingestion/connector-feeds`) redirect, with their id, `add` or `cred` intact.
It skips, naming NAN-4941, until the tabs are in the build.

To drive another branch's UI against a stack, set
`E2E_WEB_DIST=<its vite build dir> scripts/e2e.sh run ui --run <id>`.

**First-run setup.** A stack that `run ui` brings up itself starts with
`up --defer-admin`. The session's `stack` fixture then performs first-run setup
on `/setup` in the browser and logs in (`nano_e2e.firstrun`). After that it
mints the admin key and writes it into `admin.env` and `stack.env`.
`tests/ui/test_auth.py` asserts the outcome against the API. On a stack that was
initialized at `up`, that one scenario skips with the reason.

**Schema profile.** Every stack the harness brings up uses
`NANO_SCHEMA_PROFILE=ocsf`, the install default, for every suite (see
Conventions). The OCSF sidebar scenario skips, with the reason, on a stack you
pinned to udm. Every other UI scenario runs on both profiles.

### Mock vendors (`--profile mock-vendor`)

`up --profile mock-vendor` (native app mode) builds and starts
`nano-connector-runner` in lab mode. The only relaxation is the runner's own
sanctioned seam, `CONNECTOR_TEST_MODE=1` plus
`CONNECTOR_TEST_MOCK_URL=http://127.0.0.1:<E2E_MOCK_VENDOR_PORT>`
(`nano-connector/src/loopback.rs`).

- **What stays enforced:** every vendor request still passes the spec's host
  policy (https, the vendor's host suffix, path prefixes) before it is sent to
  the mock. The SSRF guard is not relaxed.
- **How the mock routes:** the request arrives over plain HTTP, with the
  original host in `x-mock-host`.
- **Where the mock runs:** in the pytest process (`mock_vendor` session
  fixture, `nano_e2e.mockvendor`).
- **When the profile is on:** `run pull|ui|all` adds it to a stack it brings up
  itself.
- **How to check it:** `svc restart connector` and `status` cover the runner.

Each mocked vendor checks credentials the way the real one does. Each one also
filters by the requested window, and pages with a page size of 2, so paging is
always exercised.

| connector | mock routes (from `nano-connector/specs`) | auth checked |
|---|---|---|
| `okta_system_log` | `<OKTA_DOMAIN>/api/v1/logs`, `Link: rel="next"` | `SSWS <API_TOKEN>` |
| `google_workspace` | `oauth2.googleapis.com/token`, `admin.googleapis.com/.../applications/<app>`, `nextPageToken` | RS256 service-account JWT verified against the seeded key; issued bearer token |
| `slack` | `slack.com/api/team.accessLogs`, `next_cursor` | bearer `USER_TOKEN` |
| `netskope` (`saas_api` provider) | `<TENANT_HOST>/api/v2/events/dataexport/events/<item>`, a server-side iterator (`epoch`/`next`/`resend`) | `Netskope-Api-Token` |

`selftest` checks every mock route against the specs' `allow` lists, so the
mock cannot drift away from what the runner is permitted to call.

**Lanes.** A feed needs a deployed HEC log source per lane
(`require_deployed_parsers`). `nano_e2e.feeds.ensure_lane_source` deploys one
with a lane parser that emits an OCSF Base Event (see the findings below).

**SOAR destructive actions.** `scripts/e2e.sh run soar --app native` owns the
complete enterprise closeout lane. The harness creates a per-run CA, a
loopback HTTPS Okta fixture and a pinned Mailpit container. Product traffic
still passes the signed pack policy, DNS pinning, TLS validation, approval and
receipt machinery. The loopback dial mapping and RFC 8032 fixture signer are
available only in `nanosiem-enterprise`, only in the explicitly non-shippable
`nano_content_acceptance` debug composition, only with both
`NANOSIEM_DEV_MODE=true` and `SOAR_E2E_LAB=1`, and only for loopback socket
addresses. Release composition refuses the cfg before linking. Teardown removes
the CA and private key with the owned stack.

### Scenarios (phase 2)

| Suite | Scenario | Status |
|---|---|---|
| ui: auth | first-run setup in the browser; login shows the admin (`/api/auth/me`) and survives a reload; sign out ends the session; wrong password stays out (attempt counter, API 401) | runs |
| ui: Add source (NAN-4922) | wizard per transport (HEC, HTTP JSON, OTLP through a real OTel Collector and the nginx edge): token shown once, snippet copied from the clipboard and executed as copied, first event green, highlighted row == API, delivery receiving, health total and tooltip == health-series, drill-down on `metadata.log_source`, credentials card revoke leads to a 401, token never in the DOM or API again; `?source=` resume; draft receives before a parser | runs |
| ui: Log Sources tabs (NAN-4941) | tab strip and routes; Credentials: ingest token issue, rotate and revoke (old and new tokens 401 at the right time); push listeners == API; Repositories (rail): nano-rs/parsers and nano-rs/rules followed with no clicks on `main`, synced, listed like the API (NAN-4940); a role without `credentials:*` sees and mutates no secret; a role without `log_sources:view` lands on Cloud pull; retired URLs redirect (ids and `add`/`cred` kept) | runs (layout detected from the build) |
| ui: cloud pull | AWS SQS, Azure Event Hubs and GCP Pub/Sub (ADC) set up in the UI with the secret entered inline; deploy, events land == API == search UI. AWS also: masked secret, rotate in place with a second real key, versions, rollback, delete refused naming the source, undeploy; the secret never returns from the API | real clouds |
| ui: pull feeds | Okta, Google Workspace and Slack created in the UI against the mock vendor; row == feed API; pause and resume; reset (Okta re-anchors; fan-out and watermark streams are refused visibly); Okta rotate from the row (the vendor then accepts only the new token) | mock-vendor |
| ui: search (OCSF) | keyword; `stats count by actor.user.name`; the `user=` alias == `actor.user.name`; live tail with waves plus a same-millisecond burst (every arrival once, header count never blanks or goes backwards) | runs (ocsf) |
| ui: OCSF sidebar | `actor.user.name`, `src_endpoint.ip`, `device.hostname`: unique, events and percentages == `stats count by`; no UDM names; `metadata.log_source` is an xfail finding | runs (ocsf) |
| pull | connector feeds Okta / GWS / Slack / Netskope land exactly once; a rejected credential fails visibly | mock-vendor |
| soar | full enterprise detection-to-response closeout, including Mailpit and the live vendor action path described above | owned local fixtures; no cloud credentials |
| placeholders | features not on dev yet (NAN-4928 search backend, NAN-4933 key ring; enterprise NAN-4931 threat intel, NAN-4946 Marketplace) and merged features whose scenarios are still to write (timechart buckets, histogram edges, fired-match pivot, case intake, negative ingestion paths) | explicit skips naming the issue and branch |

The enterprise UI scenarios live in `tests/enterprise/ui/`, which the mirror
strips. `run ui` runs them with `tests/ui/` as a companion path, which is not
coverage-gated on its own. On an `EDITION=open` stack they report as
`SKIPPED (enterprise-only scenario; stack runs EDITION=open)`.

### Findings recorded by phase 2 (11-03)

- **Search sends the hunt in API GET query strings.** With the query in the
  page fragment (G10), `/api/search/explanation?q=` and `/api/fields/ext?query=`
  still carry it, so it lands in the edge access log. Pinned as a non-strict
  xfail.
- **The edge stalled every proxied request for ~25 s once (native mode,
  E2E-INFRA).** nginx in Docker reaches the host app through
  `host.docker.internal`; for ~25 s no proxied request reached the API (which
  was idle and logged nothing), the SPA sat on its spinner and the token
  refresh was aborted. Not reproduced in 300 direct probes; the root cause is
  unconfirmed. The native-mode edge now pools keepalive connections to the
  upstreams (routing unchanged), and the stall has not recurred since.
- **ClickHouse memory pressure drops audit events.** On a 4G probe stack the
  full UI suite drove ClickHouse to ~3.2 GiB RSS with almost no data; queries
  and inserts then failed with code 241 ("memory limit exceeded"), `GET
  /api/audit` returned 500, and the API logged "Security-critical audit event
  not durably persisted" (run `dan-098e16fd`). After the NAN-4948 feed
  bundles landed, 6G hit 241 too (a 22 ms keyword search and Vector INSERTs,
  run `dan-bb9e22ae`). Probe stacks now default to 8G
  (`E2E_CLICKHOUSE_MEM_LIMIT`); the audit scenario retries a 241 briefly.
- **Deleting a pull source config right after its parser wedged Vector
  (fixed, NAN-4956).** The config's undeploy rewrote only `source_router`'s
  inputs, so `enrichment_router` (same inputs) and a parser still claiming the
  route kept naming the removed `<config>_route`; Vector refused every reload
  for ~5 min (runs `dan-ce83a096`, `dan-b0f6bae4`). A source-config change now
  re-renders the whole parser tree, and a fetch parser whose route is not on
  disk is left out of it. `test_delete_race.py` deletes both back to back and
  asserts no reload is refused; the cloud-pull cleanup deletes deployed configs
  again.
- **A credential rotate or rollback delays in-flight SQS messages by the
  visibility timeout.** The reload that activates the new credential version
  shuts down the running `aws_sqs` source; messages it had received but not
  yet deleted reappear only after `visibility_timeout_secs` (Vector default
  300 s), so a few events land ~5 min late (runs `dan-6aed6ccc`,
  `dan-8987d15e`). At-least-once, not loss; the rotate/rollback steps allow
  for it (`SQS_REDELIVERY`). The rotate and rollback UI explains the default
  300-second delay and that delivery remains at-least-once.
- **Lookup Replace reader gap (fixed, NAN-4958).** Right after Replace data,
  `GET /api/lookup-tables/<t>/rows` could answer 404 ("Lookup table not found:
  lookup_<t>", run `dan-b0f6bae4`). Readers now validate the registry pointer
  after reading and retry across a swap; the scenario fails on any 404.
- **SOAR requester/API-key provenance gap (fixed, NAN-4958).** The requester's
  card used to offer Approve because auth used a TypeID while SOAR returned a
  UUID, and API-key runs were stored as `requested_source: "ai"` and rendered
  as pivt. IDs are now normalized for the self-approval gate, while API-key
  runs and approvals use `requested_source: "api_key"` and an API key label.
- **Open build: enterprise routes answer the admin with "Access Denied".**
  `/risk/watchlists`, `/automation`, `/automation/flows`, `/playbooks` and
  `/playbooks/repositories` are absent from the open rail, but a direct URL
  tells the admin "you don't have permission" instead of showing the
  "Available in nano paid plans" panel (the route guard checks an enterprise
  permission the open build never defines). Every other enterprise route shows
  the panel or the SSO panel; every rail link opens a page. Pinned as xfails in
  `tests/ui/test_edition_affordances.py`.
- **A repository import ignores the name typed in the wizard.** Step 1 shows
  the source as the typed name, but the imported source is stored under the
  catalog's display name (e.g. `Generic JSON (OCSF)`). Pinned as an xfail at
  the end of the import scenario (its import/link/deploy assertions pass first).
- **SOAR's switch refuses API keys.** `PUT /api/soar/settings` returns 403
  "require an interactive admin session"; the scenarios flip it in the browser.

- **Events stranded by a Vector topology reload.** Issuing or revoking an
  ingest token rewrites the tokens file, and Vector reloads its topology about
  1 s later. HEC events that were accepted (200) during that reload sat for
  about 2.5 minutes, until a later reload flushed them. `token_source(...,
  settle=True)` waits for a fresh probe to become searchable, so UI scenarios
  do not race it.
  The same hits pull connectors: a feed that starts right after its lane is
  published delivered 5 events (run status success, `ack:2`) of which only 3
  were searchable 5.5 minutes later (open run `dan-0af7f774`, Google Workspace;
  enterprise `dan-7f27d383`, Okta, 4 of 5). The pull-feed UI scenarios now wait
  for Vector's reloads to go quiet before starting the feed
  (`waits.vector_reloads_quiet`). Fixed by NAN-4936 (Vector 0.61.0-nano.4, the
  disk-buffer visibility stall); `tests/pull/test_reload_stranding.py` now
  requires every event acked during a lane's reloads to land (strict).
- **On an OCSF stack, a published non-OCSF parser makes its events invisible
  to search.** Output without `class_uid` leaves on the UDM path, which the
  OCSF search plane does not read. Vector metrics still count those events.
- **HEC-lane parser output on OCSF is stored with `source_type=unknown`**
  unless the parser sets `metadata.log_source`. The prepare step reads
  `%source_type`, which the HEC lane does not set.
- **A pull parser without a live source config wedges every deploy.** This
  covers a pull-transport log source with no `dispatch_source_config_id`, or one
  whose source config was deleted. It is accepted with a 201. After that, every
  Vector deploy fails with "no usable source-configuration dispatch". Deploys
  run on every log-source delete, so even deleting that parser fails.
  Recovery: `PUT {"source_type":"routed"}` on that log source, then delete it
  (`feeds.delete_log_source` does this).
- **A parser bound to an undeployed source config broke the Vector
  generation (fixed, NAN-4956).** Its filter named `<config>_route` before the
  config was deployed, and Vector rejected the whole generation. The render
  now leaves such a parser out until its config deploys; the config's deploy
  re-renders the parser tree and brings it in.
- **Navigating while a token refresh is in flight logs the user out.** Refresh
  tokens rotate. If a page is left mid-refresh, the browser never stores the
  new cookie, and the next page's refresh is refused with a 400, which logs
  the user out. Fast in-app navigation can hit this.
- **Log Sources "Continue setup" opens Connect, not Sample & parse.** The link
  carries `?stage=parse`, but the wizard rewrites it to `stage=connect`. It is
  pinned as a strict xfail.
- **The OCSF fields sidebar lists `source_type`, not `metadata.log_source`.**
  Result chips and the API use `metadata.log_source`. It is pinned as a strict
  xfail.
- **Fan-out pull feeds report their lane as the spec template** (`gws_{{item}}`)
  in the feed API and the Pull feeds table.
- **"Deploy changes" left the source config "Pending" forever.** `deploy()`
  stamped `deployed_at` only on the first deploy. A redeploy applied the new
  routing, but the UI's pending check (rules and settings newer than
  `deployed_at`) never cleared. Fixed here, on top of NAN-4936's
  marker-correlated activation and under its deploy lock: `deployed_at` advances
  only after Vector ACTIVATED the deploy, and only if neither the row (rendered
  `updated_at`, compare-and-swap) nor its routing rules changed after the
  render; a first deploy sets `deployed = true` for the router without stamping.
  A refused or unconfirmed activation, or a failed router rewrite, leaves the
  change pending. `nanosiem-core/tests/source_config_deploy_stamp_integration.rs`
  covers each case; the UI scenario asserts that Pending clears.
- **Azure Event Hubs could not be created from the UI.** The add sheet creates
  every source with `connection_config: {}`, and the Event Hubs validation
  demanded `event_hub_name` at create time, so the request returned 422. Fixed
  here: an empty config is accepted at create only, where it means not
  configured yet. Update validates the merged config in full, so a deployed
  source cannot be blanked, and deploy still requires the hub.

## Real-tenant connector feeds (NAN-4961)

```bash
scripts/e2e.sh run connectors             # own OCSF stack, LIVE runner, web UI, real tenants
scripts/e2e.sh up --profile connector-live && scripts/e2e.sh run connectors -- -k entra
```

`--profile connector-live` runs `nano-connector-runner` exactly as shipped:
no `CONNECTOR_TEST_MODE`, no mock URL, so every vendor request goes to the
real tenant under the spec's host policy. It is exclusive with `mock-vendor`
and needs native app mode. `run connectors` on a stack it brings up picks it
(and the OCSF profile) by itself; a mixed run (`all`) keeps the mock and the
connectors scenarios SKIP naming the profile.

Collector lanes get the vendor's real OCSF parser, imported LINKED from the
nano-rs/parsers repository the install follows (`feeds_live.ensure_vendor_parser`),
not the harness lane parser. Every scenario compares nano with the tenant's own
answer, read with the same credential (`nano_e2e.vendors_live`).

| connector | tenant | per scenario | status |
|---|---|---|---|
| `entra_directory` | Azure e2e tenant, app `nano-e2e-entra-connector` (Graph application permissions User.Read.All, GroupMember.Read.All, RoleManagement.Read.Directory, admin-consented; two client secrets) | feed created in the UI with the secret inline; run 1 writes exactly Graph's users into the directory (UPN, name, enabled/status), every group and activated directory-role membership; run 2 (delta) advances the `users` checkpoint, no duplicates; rotate to a wrong secret fails the next run, rotate to the second real secret recovers it; a wrong-secret feed fails visibly (API + row) while the good feed runs and Vector HEC stays healthy; delete tombstones the users | runs |
| `okta_system_log` + `okta_users` | Okta developer org (`OKTA_ORG_URL`, `OKTA_API_TOKEN`, optional `OKTA_ROTATE_API_TOKEN`) | one throwaway user created and deleted for fresh System Log events, then the shared collector flow (`nano_e2e.connector_scenario`): UI create, events land in the vendor's OCSF classes, every System Log uuid of the committed span landed once, checkpoint advances, rotate live on the next run, refused token isolated, UI search == API; users feed == the org's users and group memberships | SKIPs until the org exists |
| `google_workspace` | nano's own Workspace, READ-ONLY (`NANO_E2E_GWS_SA_JSON`, `NANO_E2E_GWS_ADMIN_EMAIL`) | the shared collector flow; events need a sign-in during the run | SKIPs: no key on hand |
| `slack` | a Business+ / Grid workspace (`NANO_E2E_SLACK_USER_TOKEN`) | the shared collector flow | SKIPs: nano's workspace is Pro, which does not offer the `admin` scope team.accessLogs needs |

Findings (11-04):

- **NAN-4963** connector events parsed by the first-party OCSF parsers land with
  `source_type` / `metadata.log_source` = `unknown` (the HEC lane never sets
  `%source_type`; the parsers don't set `metadata.log_source`). Fixed: under
  OCSF every parser stamps the lane it was claimed on; every collector scenario
  now ends asserting `metadata.log_source` is the lane and a lane search finds
  every landed event. `tests/test_hec_ocsf_lane.py` covers it without vendor
  credentials.
- **NAN-4964** pull feeds have no preview step (the issue's "preview shows real
  events"); `test_pull_feed_preview.py` is the explicit placeholder.
- **NAN-4965** the user directory an identity feed writes has no UI
  (`IdentitySettings` is unmounted), and New pull feed shows the internal
  `identity_allow_shrink` knob as a free-text field.
- **NAN-4966** OAuth token failures read only `token endpoint failed: HTTP 401`
  (the vendor's `invalid_client` / AADSTS reason is dropped).

Scheduled lane: job `connectors` in `.github/workflows/e2e.yml` (04:30 cron,
commented out like the rest of the workflow, or dispatch with
`connectors: true`). Tenants are left intact by teardown.

## Cloud credentials (real clouds, no emulators)

Pull scenarios use **real** AWS, GCP and Azure test resources (Dan, 11-03).
Credentials are never in the repo, logs or artifacts. The runner places them
only in the pytest process environment, from the first source that works:

1. `doppler run -p nano-e2e -c dev` (override the project and config with
   `NANO_E2E_DOPPLER_PROJECT` / `NANO_E2E_DOPPLER_CONFIG`; disable with
   `NANO_E2E_NO_DOPPLER=1`)
2. `~/.nan2361-secrets/e2e.env`, which must be mode 0600 (override the path
   with `NANO_E2E_CREDS_FILE`)

`scripts/e2e.sh doctor` reports which groups are present, never their values.
A scenario whose credentials are missing **skips with the reason**. A selected
suite in which **every** scenario skipped (or that runs nothing) **fails**,
so lost secrets or a build that stops exposing a feature never read as green.
Pass `--allow-skips` for local exploration.

Every resource a test creates is named `nano-e2e-<runid>-...` and carries
ownership tags or labels: `nano-e2e=1`, `nano-e2e-run=<runid>` and
`nano-e2e-created=<epoch>`. Event Hub entities cannot be tagged, so the run's
consumer group carries them in `userMetadata` and the Blob container in
`x-ms-meta-*`. A fixture finalizer deletes each resource and verifies the
deletion (2xx/404 only; conflicts are retried) even when the scenario fails.

`scripts/e2e.sh gc --cloud --hours N` touches cloud resources ONLY (never a
local stack). Plain `scripts/e2e.sh gc --hours N` removes local `nanoe2e-*`
stacks older than N hours that THIS checkout started (container label
`nano.e2e.owner` = the checkout path; an unlabelled older stack only if its run
dir is under this checkout's `target/e2e`). Another worktree's stack is left
alone unless `--all-local` is passed. The cloud straggler is deleted only when
all of these hold:

- it carries all three ownership markers;
- the run named in its tags matches the run in its name;
- that run is not active locally (a live `target/e2e/<runid>/stack.env`);
- it was created more than N hours ago.

The name prefix alone never authorizes a deletion.

### AWS (S3 + SQS): `aws_s3`, `aws_sqs`

| Variable | |
|---|---|
| `NANO_E2E_AWS_ACCESS_KEY_ID`, `NANO_E2E_AWS_SECRET_ACCESS_KEY` | IAM user for the harness. The same key pair is given to nano as the source credential |
| `NANO_E2E_AWS_REGION` | e.g. `us-east-1` |
| `NANO_E2E_AWS_ROTATE_ACCESS_KEY_ID`, `NANO_E2E_AWS_ROTATE_SECRET_ACCESS_KEY` | optional second key pair for the rotate step. Without it, rotate re-submits the same pair, which still exercises rotate and redeploy |

Least-privilege policy for that user, limited to the prefix:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": [
       "s3:CreateBucket", "s3:DeleteBucket", "s3:PutBucketTagging", "s3:PutBucketNotification",
       "s3:GetBucketNotification", "s3:ListBucket", "s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
     "Resource": ["arn:aws:s3:::nano-e2e-*", "arn:aws:s3:::nano-e2e-*/*"]},
    {"Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*"},
    {"Effect": "Allow", "Action": [
       "sqs:CreateQueue", "sqs:DeleteQueue", "sqs:TagQueue", "sqs:GetQueueAttributes", "sqs:SetQueueAttributes",
       "sqs:GetQueueUrl", "sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage",
       "sqs:ChangeMessageVisibility"],
     "Resource": "arn:aws:sqs:*:*:nano-e2e-*"},
    {"Effect": "Allow", "Action": ["sqs:ListQueues"], "Resource": "*"}
  ]
}
```

- **Who uses what:** the harness creates the bucket and queue, sets the queue
  policy that lets `s3.amazonaws.com` send from that bucket, wires
  `s3:ObjectCreated:*` notifications, and writes the objects. nano's Vector
  source receives from the queue, reads the objects and deletes the messages.
- **Restart cost:** an S3 notification that is in flight when Vector stops
  comes back only after the SQS visibility timeout. Since NAN-4936 nano emits
  `visibility_timeout_secs` for `aws_s3` (default 60 s, settable per source;
  Vector's own default is 300 s, measured on real AWS 11-03 as about 300 s of
  delay). `aws_sqs` sets `visibility_timeout_secs: 30`.
- **Splitting the identity:** a stricter setup gives nano a second identity
  with only `sqs:ReceiveMessage`, `sqs:DeleteMessage`,
  `sqs:ChangeMessageVisibility`, `sqs:GetQueueAttributes` and `s3:GetObject`
  on the prefix. Pass it as the `ROTATE` pair to exercise both identities.

### GCP (Pub/Sub): `gcp_pubsub`

| Variable | |
|---|---|
| `NANO_E2E_GCP_PROJECT` | test project id |
| `NANO_E2E_GCP_SA_JSON` | service-account key: a path, raw JSON or base64 |
| `NANO_E2E_GCP_ADC` | alternative when org policy blocks SA keys: the path to `gcloud auth application-default login` credentials (`authorized_user`). The same file is given to nano as the source credential |
| `NANO_E2E_GCP_ROTATE_SA_JSON` | optional second key for the rotate step |

- **Roles on the project** (or a custom role scoped to it):
  `pubsub.topics.create/delete/publish/list` and
  `pubsub.subscriptions.create/delete/consume/list` (for example
  `roles/pubsub.editor` in a dedicated test project).
- **What nano needs:** only `roles/pubsub.subscriber` on the subscription.
- **ADC works (NAN-4935).** The nano-rs Vector fork (0.61.0-nano.3) accepts
  `authorized_user`, `external_account` and `impersonated_service_account`
  files, not only service-account keys, and takes the project from the source
  config. Earlier forks refused ADC with `Invalid GCP credentials: missing
  field project_id`.
  Workload-identity file sources must live under `/var/run/secrets/nano-gcp-wif`.
- **Rejected credential is quarantined (NAN-4936, was: wedged Vector).** A
  pull source Vector cannot build is kept out of the live topology: the deploy
  returns `success: false`, the config shows `last_deployment.status =
  "quarantined"` with Vector's reason, and other sources keep ingesting.
  `pull/test_pull_robustness.py` checks that, a parser publish after the bad
  source going live, and ingest resuming after a cold Vector restart. It needs
  no cloud credentials.
- **Disk-buffer stall after a restart (NAN-4936, fixed in 0.61.0-nano.4).** On
  0.61.0-nano.3 the `clickhouse_logs` disk-buffer reader could miss the final
  write after a cold restart: the event was accepted (200), sat in the buffer
  (`buffer_size_events=1`, sink received 0) and landed only when a later write
  arrived (vectordotdev/vector#26946; 2 stalls in 25 robustness runs). nano.4
  carries the port; the strict cold-restart step in `test_pull_robustness.py`
  fails if it regresses.
- **Deploy outcomes are correlated (NAN-4936).** Source deploys, undeploys and
  quarantines wait for a per-change activation marker (`nano_activation_<id>`)
  to run in Vector, under the shared deploy lock, so one change's reload can
  never acknowledge another. `test_concurrent_deploys_each_report_their_own_outcome`
  deploys a good and a bad source at once and checks each result.
- **Events accepted during a reload all land (NAN-4936, NAN-4937 finding).**
  `test_events_accepted_during_a_vector_reload_all_land` posts a burst over HTTP
  and HEC while Vector reloads (alternating an ingest-token issue and a parser
  publish), then stays silent until the burst is searchable (60 s bound per
  round). Events stranded in the disk buffer until a LATER write or reload are
  the disk-buffer visibility stall that 0.61.0-nano.4 fixes.

### Azure (Event Hubs): `azure_event_hubs` (NAN-4914-pull)

| Variable | |
|---|---|
| `NANO_E2E_AZURE_TENANT_ID`, `NANO_E2E_AZURE_CLIENT_ID`, `NANO_E2E_AZURE_CLIENT_SECRET` | Entra service principal (client secret) |
| `NANO_E2E_AZURE_EVENTHUBS_NAMESPACE` | bare name or `<ns>.servicebus.windows.net` |
| `NANO_E2E_AZURE_RESOURCE_GROUP` | resource group of the namespace. Needed to create a hub and consumer group per run through ARM |
| `NANO_E2E_AZURE_SUBSCRIPTION_ID` | optional. Discovered when the SP sees exactly one subscription |
| `NANO_E2E_AZURE_STORAGE_ACCOUNT` | **required** Blob checkpoint store (the product mandates `checkpoint_container`). The harness creates a container per run |
| `NANO_E2E_AZURE_EVENTHUB_NAME` | optional pre-provisioned hub. The run still gets its own consumer group and checkpoint container on it |

Measured against real Azure on 11-03 (stack built from NAN-4914-pull,
service principal and Blob checkpoints), the lifecycle passed:

- 0 events lost;
- the first warm-up probe was dropped, because the source starts at
  `latest`;
- after the pause and resume redeploy, a full batch (40) was re-read from the
  last committed checkpoint. That is at-least-once delivery, and the
  lifecycle judges duplicates per batch at the end.

Every run gets its own consumer group and checkpoint container, so
concurrent runs (for example the X64 and ARM64 CI legs) never share
checkpoints. Modes that cannot provide that isolation, such as a
connection string only or a shared checkpoint container, are refused with
the reason.

SP roles, scoped to the namespace and storage account only:

- **Event Hubs namespace:**
  - *Contributor*, or a custom role with
    `Microsoft.EventHub/namespaces/eventhubs/*` and
    `.../consumergroups/*`, to create and delete per-run hubs and consumer
    groups.
  - *Azure Event Hubs Data Sender* (for the harness) and *Data Receiver*
    (for nano). *Data Owner* covers both.
- **Storage account:** *Storage Blob Data Contributor*, for the checkpoint
  container (create and delete, plus nano's checkpoint writes).

## Sentry error tracking (NAN-5798, report only)

For nano's own runs: `NANO_E2E_SENTRY=1 scripts/e2e.sh run personas` runs the
stack with Sentry on (environment `e2e`, tagged with the run id and the
running test; see `scripts/lib/e2e-sentry.sh`). At `down` the run's issues
land in `artifacts/sentry/summary.txt` and `issues.json`; the run never fails
because of them. Without the flag nothing changes.

## Legacy lanes

`dev/e2e/legacy-lanes.toml` wraps the existing end-to-end scripts and the
env-gated `#[ignore]` suites, without rewriting them. Run them with:

```bash
scripts/e2e.sh legacy list
scripts/e2e.sh legacy ingest-tokens onboarding    # self-contained scripts (own containers)
scripts/e2e.sh legacy upgrade-180                 # migration 180 on an infra-only ocsf stack
scripts/e2e.sh legacy upgrade-from-v01            # oldest supported v0.1 source -> this checkout, both editions (v2.0.0 gate)
scripts/e2e.sh legacy all                         # stack lanes get a fresh stack's stack.env
```

Stack lanes run sequentially against their own fresh stack, because several
suites TRUNCATE shared tables. Never point `legacy` at a stack that is also
running scenarios.

## Harness selftests

`scripts/e2e.sh selftest` (no stack, no cloud credentials, about 15 s) proves
the harness's own safety properties:

- native pid files are bound to pid, start time and owner token, so a reused
  pid or a dev service built from the same target directory is never
  signalled;
- the ClickHouse admin password never appears in argv;
- `gc` refuses an unsafe cutoff; local gc selects only this checkout's
  stacks (`--all-local` overrides) and `--cloud` never touches docker; cloud GC
  requires ownership tags and skips active runs;
- deletes are verified;
- a suite that runs nothing, or a skipped explicit legacy lane, fails;
- Azure creates a consumer group and checkpoint container per run;
- a timed-out legacy lane's whole process group is killed;
- the stripped open-core tree defaults to `EDITION=open`;
- the C05 license env is validated, the identity seeding SQL is guarded and
  parameterized, a refused seed or an inactive license fails `up`, and the
  license file's contents never reach output or artifacts.

## Development

```bash
cd e2e && .venv/bin/pip install ruff pyright
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/pyright
.venv/bin/python -m pytest --collect-only -q
```

The pinned dependencies are in `requirements.lock`; the ranges are in
`pyproject.toml`. `scripts/e2e.sh` builds `e2e/.venv` from the lock, with
`uv` when it is installed and `python -m venv` otherwise.
