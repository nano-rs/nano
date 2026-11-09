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
or `all` / `fast`.
Anything after `--` goes to pytest.

### What `up` does

1. It creates the compose project `nanoe2e-<runid>` (`runid` = `<user>-<8 hex>`)
   from `docker-compose.opensource.yml` plus `dev/e2e/compose.e2e.yml`. The
   stack runs PostgreSQL 17, ClickHouse 26.10 (single node), Valkey and the
   Vector 0.61 fork. Every port is an ephemeral `127.0.0.1` port. Containers
   are named `nanoe2e-<runid>-*`. It never touches `nanoch-*` or any other
   project.
2. It starts the app:
   - **native** (the macOS default): `cargo build` with the repo's
     `rust-toolchain.toml` (1.95), then the migrator, `nanosiem-search`,
     `nanosiem-jobs` and `nanosiem-api` as host processes on free ports.
   - **docker** (the Linux default): `docker build --target api|search|jobs`
     from this tree.
   - **image:\<tag\>**: published `ghcr.io/nano-rs/nano-*` images.
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

## Scenarios (phase 1)

| Suite | Scenario | Status on clickhouse/dev |
|---|---|---|
| base | health (api, search, jobs, Vector HEC); setup is one-shot; capabilities edition; login (bad password 401); API key create, use on api and search, least privilege, delete leads to 401 | runs |
| ingest | per-source token: HEC + HTTP land as the token's source; a spoofed sourcetype is kept only as the claim; unknown token 401; rotate (old 401, new 200); revoke 401; two sources isolated | runs |
| onboarding | draft source ingests before its parser is published; connect status `receiving_unparsed`; publish leads to new events being parsed | runs |
| vector_render | a draft (`http` spelling) deploys live, then a normal source, then a parser publish; a deploy Vector refuses is reported failed, rolled back, the draft disabled again, and the next deploy goes live; `${...}`/`$NAME` in parser VRL refused at save; `$` anchors, `$1` captures and the literal form run as written (NAN-4952/4953) | runs |
| delete_race | a bound Kafka pull parser, then its source config, deleted back to back: no Vector reload refused, a later publish goes live (NAN-4956) | runs |
| hec_ocsf_lane | the connector delivery (platform token, `sourcetype=okta`) to the published `okta_ocsf` from nano-rs/parsers: parsed as User Management 3007, `metadata.log_source = okta`, found by `metadata.log_source="okta"` and `source_type="okta"`, not by `"unknown"` (NAN-4963; needs an ocsf stack) | runs |
| detection | Alerting rule: an alert carries the event. Live rule: a match is recorded, no alert | runs |
| search_jobs | durable job completes and its results page without loss or duplicates; `async_mode` returns a job handle; cancel | runs |
| pull | `aws_s3` (S3 to SQS notifications), `aws_sqs` payload, `gcp_pubsub` lifecycle: create, then events land, then a Vector restart (no loss, bounded duplicates), then pause/resume, then credential rotate, then delete | real cloud; skips without credentials |
| pull | `azure_event_hubs` lifecycle | real cloud (NAN-4914) |
| ui: search URLs (NAN-4927) | a legacy `?q=` link migrates the hunt into the fragment and a reload never sends it in a page URL; a relative range stays relative through run and reload; `view=rarity` opens rarity; hunt in API GET query strings is an xfail finding | runs (ocsf) |
| ui: Nano Pipe (NAN-4919) | Add step > Filter, Save draft (nano-pipe-v2 plan in the API), paste sample + Run preview == `/pipe-preview`, publish twice, History > Rollback == versions API | runs (`NANO_PIPE_PREVIEW_ENABLED`) |
| ui: audit (NAN-4930) | API-key actor label == audit API; Action filter round-trips the URL; Export CSV == rows on screen, every cell quoted, a formula-shaped name neutralized | runs |
| ui: SSO (v2 entitlements) | login shows no SSO without providers; open build says the deployment lacks SSO; enterprise: every licensed capacity mounts the provider page, including retired tier inputs normalized to `licensed` | runs |
| ui: lookups (NAN-4924) | delete of a table a rule uses is refused naming the rule; Replace data swaps schema and rows (rows API + table page); delete succeeds once the rule is gone | runs |
| ui: IPinfo bundle-only (NAN-4959) | catalog entry has no credential field and the configure API refuses a BYO `download_url` (422); retired IPinfo configure / sync / auto-sync endpoints 404; the IPinfo Lite inventory drawer and the connection drawer Config tab show the bundle status (revision == platform feed status, last update, next refresh) with no inputs and no Configure / Uninstall | runs |
| ui: edition affordances | open: every enterprise route shows the entitlement panel or redirects (5 answer "Access Denied": xfail finding), every rail link opens a page, no uncaught page errors; enterprise: none of those routes serves the open placeholder | runs |
| enterprise ui: SOAR (NAN-4911) | switched on in Settings > SOAR (the API refuses an API key); flow run from its row (No-op + Search): run detail == run/steps API; Approval step suspends, a second user approves from Approvals, run resumes; requester cannot approve; `soar:view` cannot run | runs (jobs executor) |
| enterprise `soar` closeout (NAN-4911) | signed catalog import and tamper refusal; real ClickHouse detection → Search → deterministic Judge → two-person Okta suspend → Mailpit STARTTLS email; case wall and secret-free run trace; `iam.suspend_user` playbook; RFC1918/analyst denial; disable cancellation fence | runs (native app + owned `soar-lab` and `ai-stub` profiles) |
| enterprise ui: risk watchlists (NAN-4926) | a risk rule fires on OCSF events for a user; New watchlist (weight 0.5): rail == API; Risk index ×1.50 badge, effective and base == `/api/risk/entities`; detail sheet; `risk:view` alone sees no weight | runs |
| content_acceptance (NAN-4955) | fresh OCSF enterprise install consumes signed parser, rule, playbook, marketplace, model, MITRE ATT&CK and SOAR channels from a loopback app publisher while a deny-all proxy sinkholes GitHub; real catalogs + browser surfaces populate; tamper retains last-good; raw air-gap import advances the channel | `scripts/e2e.sh run content_acceptance --fresh` (native only) |
| pull | connector feeds: Okta, Google Workspace, Slack, Netskope (`saas_api`) + a rejected credential | runs with the mock-vendor profile (phase 2, below) |
| enterprise | Nano Pipe pipelines (5 stubs) | skips: lands with NAN-4919 |

## Phase 2: UI scenarios and the mock-vendor profile (NAN-4937)

```bash
scripts/e2e.sh run ui                     # own stack: OCSF profile, mock-vendor, first-run in the browser
scripts/e2e.sh run ui --edition open      # open core: enterprise scenarios report as SKIPPED
scripts/e2e.sh run ui --run <id> -- -k search   # against a kept stack
E2E_UI_HEADED=1 scripts/e2e.sh run ui ... # watch the browser
scripts/e2e.sh run personas              # all five role-based journeys
scripts/e2e.sh run personas --edition open # core paths + explicit AI boundary
```

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

**Schema profile.** A stack that `run ui` brings up itself, with `ui` as the
only suite, uses `NANO_SCHEMA_PROFILE=ocsf`, the install default for new
installs, unless you set the profile yourself. Mixed runs (`run all`,
`run ui base`) keep udm, because the phase-1 parsers are not OCSF-shaped. The
OCSF sidebar scenario skips, with the reason, on a udm stack. Every other UI
scenario runs on both profiles.

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
- the stripped open-core tree defaults to `EDITION=open`.

## Development

```bash
cd e2e && .venv/bin/pip install ruff pyright
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/pyright
.venv/bin/python -m pytest --collect-only -q
```

The pinned dependencies are in `requirements.lock`; the ranges are in
`pyproject.toml`. `scripts/e2e.sh` builds `e2e/.venv` from the lock, with
`uv` when it is installed and `python -m venv` otherwise.
