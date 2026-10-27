# Writing a nano connector spec

A connector is one YAML file, validated by `connector.schema.json`. The engine
does the HTTP, auth, paging, retries, rate limits, time windows, dedupe,
checkpoints and caps. You describe the API. Add an optional VRL `program` only
when the API needs logic that the declarative fields can't express.

Check your work with `nano-connector validate spec.yaml`. Then dry-run it with
`nano-connector preview spec.yaml recording.json --config K=V --cred K=V`,
which runs offline against recorded responses.

## Where specs live

First-party specs ship in the content repos, as `connector.yaml` next to the
integration's `manifest.yaml` (and, until cutover, its `code.ts`):

- `nano-integrations/integrations/<name>/connector.yaml` (collectors)
- `nano-enrichments/enrichments/{agent,data}/<name>/connector.yaml` (enrichments)

The manifest names the spec and says which runtime runs the entry:

```yaml
runtime: connector          # or deno (the default) while code.ts still runs
connector_spec: connector.yaml
```

Marketplace sync copies the spec into the catalog row's `config` as
`runtime`, `connector_spec` and `connector_spec_sha256`. A feed pins the
sha256 it was configured against. The `execution_backend` column is unchanged.

Only first-party content is ported. Custom Deno scripts that operators wrote
themselves have no conversion path and stop running at cutover.

`nano-connector/tests/fixtures/specs` holds frozen copies for the engine's own
tests; they are not the shipped specs.

## Shadow runs: prove a port against the Deno script

Each content repo has `testing/shadow/`. It runs the Deno script and the
connector against the same vendor mock and diffs what each one ships:

```
nano-connector shadow connector.yaml --mock-url http://127.0.0.1:PORT \
    --cred K=V --cred-file K=PATH --config K=V \
    [--checkpoints state.json] [--all-batches]
```

`shadow` is `preview` with the recorded responses swapped for a live mock. It
sends every request to the loopback `--mock-url`, with the vendor host in the
`x-mock-host` header, and refuses any URL that is not `http://<loopback IP>`.
The output's `checkpoints` feed a restart run, which must ship nothing new.

`nano-connector check-uids parser.yaml batches.json` then runs the stream's
parser over the shipped events twice and fails when an event has no
`metadata.uid`, when the uid changes between the two parses (a random uid),
or when two different events share one.

## Shape

```yaml
version: 1
name: vendor_thing                 # snake_case
kind: collector                    # collector | agent_enrichment | data_enrichment | identity
allow:                             # egress allowlist; every request, Link URL and redirect is checked
  - host: api.vendor.com           # exact host, or "{{config.TENANT_HOST}}" with host_suffixes: [".vendor.com"] (dot-prefixed)
    path_prefixes: ["/v2/events"]  # segment-aligned; keep them narrow
auth: { type: bearer, credential: API_TOKEN }
schedule: "*/5 * * * *"
limits: { max_run_secs: 600, max_pages: 500 }        # optional; engine clamps them
rate_limit: { min_interval_ms: 250, max_retries_429: 5, reset_header: X-RateLimit-Reset }
streams:
  - id: events
    source_type: vendor_events     # tells ingest which parser to use; may template {{item}}
    request:
      url: "https://api.vendor.com/v2/events"
      query: { limit: "500", since: "{{window.start}}" }
      headers: { Accept: application/json }   # no auth headers here; use `auth`
    response: { events_path: data }           # dotted path to the array; "" = the body itself
    pagination: { type: cursor, from: meta.next_cursor, param: cursor }
    window: { time_field: created_at, uid_field: id, lag_secs: 60, lookback_secs: 300 }
```

## Auth (`auth.type`)

Auth parameters name credential fields; they never hold the secrets themselves.

- `none`
- `bearer {credential}`
- `okta_ssws {credential}`
- `api_key_header {header, credential, prefix?, optional?}`
- `api_key_query {param, credential}`
- `basic {username_credential, password_credential}`
- `oauth2_client_credentials {token_url, client_id_credential | client_id, client_secret_credential, scope?}`:
  `token_url` may template `config.*` (for example
  `https://login.microsoftonline.com/{{config.DIRECTORY_ID}}/oauth2/v2.0/token`;
  the rendered URL must be in `allow`). The client id comes from exactly one
  of `client_id_credential` (a credential field) or `client_id` (a
  `config.*` template such as `{{config.CLIENT_ID}}`; it is not a secret).
- `google_service_account {token_url, private_key_credential, client_email_credential, scope, subject?}`
- `google_dwd_broker {token_url, scope, subject}`: keyless Google
  domain-wide delegation for hosted collectors. No credential fields: the
  runner asks the platform pull broker for an assertion signed by the
  tenant's own Google service account, then exchanges it at `token_url`
  (which must be in `allow`). The tenant authorizes that service account's
  client ID for `scope` in the Google Admin console. A runner without a
  platform broker (open core, local preview) fails the run with
  `google_dwd_broker_unconfigured`. The broker host is never reachable from
  a spec, even if listed in `allow`. The runner authenticates to the broker
  with a per-tenant caller token (`npc<v>.<tenant>.<hmac>`) that has no
  expiry by design: it is a stateless HMAC, revocable per tenant at the
  broker (`NANO_PULL_BROKER_REVOKED_TENANTS`) and rotated by key version.
  `scope` may list several scopes separated by spaces (for example
  `admin.directory.user.readonly admin.directory.group.readonly`); each must
  be on the broker's allowlist.
- `entra_fic_broker {directory_id, client_id}`: keyless Microsoft Entra
  (Graph) for hosted collectors. No credential fields: the runner asks the
  platform pull broker (`/v1/azure/graph-token`) for a Graph access token
  for the tenant's app registration, which trusts nano's federated identity
  credential. Both parameters are templates that must render to GUIDs
  (usually `{{config.DIRECTORY_ID}}` and `{{config.CLIENT_ID}}`). The engine
  refuses a token whose `resource`, `tid`, `appid`/`azp` or `aud` do not
  match, caches it until 60 s before `expires_on`, and refreshes it once on
  a Graph 401. Allow `graph.microsoft.com` only; the broker host is never
  reachable from a spec. Without a broker the run fails with
  `google_dwd_broker_unconfigured`.
- `okta_broker_jwt {okta_domain, client_id, scope}`: keyless Okta for hosted
  collectors, for an Okta API Services app using `private_key_jwt` (no
  client secret). The runner asks the platform pull broker
  (`/v1/okta/client-assertion`, body `{feed_id, okta_domain, client_id}`)
  for a client assertion signed with the tenant's broker-held key, checks
  it (`iss` = `sub` = the client id, `aud` =
  `https://<okta_domain>/oauth2/v1/token`, expiry within 300 s), trades it
  there (client credentials, `scope` space-separated, for example
  `okta.users.read okta.groups.read okta.roles.read`) and sends
  `Authorization: Bearer <token>`. `okta_domain` and `client_id` are
  `config.*` templates; the token endpoint path `/oauth2/v1/token` must be in
  `allow`. DPoP must be off on the app: `invalid_dpop_proof`,
  `use_dpop_nonce` or a DPoP-bound token fail with `okta_dpop_required`.
- `session_login {login_url, credential_fields, fields?, encoding?, response, expires_in_secs?}`:
  POST named credential fields as JSON (default) or form data. `login_url` and
  optional non-secret `fields` may template only `config.*`; credential values
  are resolved by the plugin. The login endpoint must be in `allow`.
  `response` selects either `{type: json_token, pointer, header, prefix?}`
  (RFC 6901 JSON pointer to a string) or
  `{type: cookie, name, path_prefix}` (one named `Set-Cookie` value). Both
  variants send the session header only to the exact login origin. Cookie
  auth additionally restricts that pair to the configured,
  segment-aligned path prefix; it is not a browser cookie jar. Duplicate,
  missing, short or malformed selected tokens fail closed. Login redirects
  are never followed. Tokens are cached per plugin in the run/connection,
  refreshed at most once per request after a 401, and redacted like credentials.
  TTL defaults to 3,600 seconds (1–86,400 allowed, with early refresh). Every
  login and refresh consumes the existing HTTP/request/deadline budgets and
  collector request pacing. A login 429 reports rate limiting without sending
  the data request. A late 401 invalidates only the token it rejected, leaving
  a newer token available to other concurrent requests.
- `composite_token {header, first_credential, second_credential, separator, prefix?}`:
  forms one header from the two credential values in order. For example,
  `separator: /` produces `<first>/<second>`. Both fields must be present;
  values and the composed header are redacted. The spec stores field names,
  never the credential values.
- `json_body_credential {credential, field}`:
  inserts one named credential as a top-level JSON string field after rendering.
  Intended for APIs such as PagerDuty Events v2 that require authentication in
  the body. The body must be a JSON object on a POST, PUT or PATCH with one
  `application/json` content type. An existing field is refused, so templates
  and inputs cannot override authentication. Field names are literal and
  bounded to 64 ASCII letters/digits/underscores. The final body is capped at
  1 MiB and the credential at 16 KiB. Credentials stay in the credential store;
  config, templates and outputs never receive them. Strict catalog replay uses
  generated `fixture-only-<NAME>-not-a-secret` placeholders, not real keys.
- `hmac {credential, header, message, algorithm?, encoding?, prefix?, timestamp_header?, timestamp_format?, key_id_header?, key_id_credential?}`:
  signs the canonical `message` with HMAC-SHA256 (default), SHA384, SHA512 or
  explicitly selected legacy SHA1. Signature encoding is hex (default) or
  base64. The message accepts `{method}`, `{path}` (path plus query),
  `{uri_path}`, `{query}`, `{host}`, `{timestamp}`, `{body}`, `{body_sha256}`
  and `{body_sha512}`. Substitutions happen once; request bytes are literal,
  including placeholder-looking text, and binary bodies are signed exactly.
  `timestamp_format` is `unix_seconds` (default), `rfc3339` or `rfc2822`.
  Optional timestamp and key-ID headers must be valid, distinct auth headers;
  key-ID header/credential must be supplied together. Header names that affect
  routing/framing and unknown canonical placeholders are refused. The expanded
  canonical message is bounded at 8 MiB. Reflected signatures are redacted;
  retention is bounded by the compiled request cap and covers the entire run.
  Signing beyond that cap fails closed instead of forgetting early signatures.
- `aws_sigv4 {...}`
- `mtls {...}`

The engine caches tokens and refreshes them once on a 401. The schema lists
every parameter.

Without a `program`, a non-2xx status fails the run with the vendor's body
text once retries are spent. 429 and 5xx responses retry with backoff, and
`Retry-After` is honoured. A body that has no `events_path` yields zero
events, not an error. Use a `program` when the vendor signals errors inside a
200 response, such as Slack's `{"ok": false}`.

## Pagination (`pagination.type`)

- `none`: a single page.
- `link_header`: follows `Link: <url>; rel="next"`.
- `next_url {pointer}`: follows an absolute next-page URL from the body at a
  JSON pointer (RFC 6901), for keys with dots such as Graph's
  `/@odata.nextLink`. Missing, null or empty ends paging. The URL is checked
  against `allow` like every hop. Also works for fan-out
  `discover: {from: request, pagination: ...}`.
- `cursor` or `token` `{from, param}` (aliases): reads the next value from body path `from` and sends it as query parameter `param`. Paging stops when the value is empty or missing.
- `offset {param, page_size, limit_param?, max_offset?}`: stops on a short page. When `max_offset` is reached inside a window, the engine narrows the window instead of failing.

## Time windows (`window`), for APIs that filter by time

The engine walks `[window.start, window.end)` windows of up to
`max_span_secs`. It never goes past `now - lag_secs`, and each pass starts
`lookback_secs` before the last watermark so it re-reads late arrivals. Events
are deduped by `uid_field` across overlaps and restarts.

Put `{{window.start}}` and `{{window.end}}` in the query. Their format comes
from `format`: `rfc3339` (default), `epoch_secs` or `epoch_millis`.
`time_field` is the event's own timestamp; RFC 3339 or epoch values are both
accepted.

A window's watermark advances only after every page in it is walked and
acknowledged, so newest-first APIs are safe. Pagination restarts for each
window. If the vendor's upper bound is inclusive, as with Slack's `latest`,
leave it that way: dedupe by `uid_field` absorbs the shared boundary second.
`max_seen` (default 50,000) bounds the remembered uids. Raise it if one
lookback can hold more events than that.

## Retry rewrite (`retry_rewrite`)

Some APIs move a server-side cursor when they serve a page, so retrying the
same request after a lost response skips that page. `retry_rewrite` changes a
query parameter on a 5xx or connection-error retry:

```yaml
retry_rewrite: { param: operation, from: next, to: resend }   # Netskope iterators
```

Only a retry is rewritten; 429s and the first attempt are sent as written.

Every new stream starts point-forward: the first window starts at
the stream's initial cursor, activation time minus 5 minutes
(`INITIAL_CURSOR_OVERLAP_SECS = 300`), never earlier. There is no backfill
option, and `initial_lookback_secs` does not move the first window. The engine
records `point_forward: {activated_at, initial_cursor, overlap_secs}` in the
stream's checkpoint on that first run, and an existing cursor is always
resumed. If the vendor expires page tokens, add
`restart_window_on: {status: [400], body_contains: "expired"}`.

A tenant can reset a window stream's checkpoint (hosted feeds:
`POST /api/marketplace/collectors/{slug}/feeds/{feed_id}/reset-checkpoint`).
A reset never backfills: it re-anchors the stream at now − 5 minutes, exactly
where a new stream starts, and records a fresh `point_forward` entry
(`activated_at` = the reset time). The optional `since` must lie in
`[now − 300 s, now]` and does not move the anchor; an earlier `since` is
refused (400). `max_backfill_secs` and `initial_lookback_secs` are unused
(still parsed, so existing specs load) and widen nothing. Older runners refuse
specs that set `max_backfill_secs`, so do not add it.

## Event identity (`ingest_id`)

Every collector event leaves the engine with `_nano_ingest_id`, the vendor's
own event id. By default it is the window's `uid_field`. Set it explicitly
for streams without a window, or when the id spans several fields:

```yaml
ingest_id: { fields: [id.applicationName, id.uniqueQualifier] }   # joined with ":"
```

An event missing any listed field gets `h:<sha256 of the event JSON>`, which
is stable across re-reads of identical content. The field is ingest-side
identity only: today's Vector and lake do not read it, and lake dedupe keys
on the parser's `metadata.uid`. Make sure the source's parser maps the same
vendor id to `metadata.uid` (a hash of it is fine; `uuid_v4()` is not). The
shadow harness checks this with `check-uids`, and treats an `h:` fallback
id as a missing vendor id. `validate` rejects a collector stream with neither
`ingest_id` nor a `window`.

**Same uid, different content: the later row is dropped.** The lake keeps the
first row it saw for a `metadata.uid` and drops every later one, even when
the vendor has since changed the record. If the vendor re-sends an updated
record under the same id (a user profile, an alert whose status changes),
put the vendor's version field in the id, for example `[id, lastUpdated]`,
so each version is a new row. Leave it out when the vendor re-sends identical
records across overlapping windows, which is what dedupe exists for.

## Fan-out (`fanout`): one sub-pull per item, each with its own checkpoint

```yaml
fanout:
  discover: { from: config, key: STREAMS }        # or {from: static, items: [...]}
                                                  # or {from: request, request: {...}, response: {...}, pagination: {...}}
  item_key: ""            # dotted path to the item's id; "" when items are strings
  concurrency: 4
```

Use `{{item}}` or `{{item.field}}` in the url, query and `source_type`.

`{from: config, key: STREAMS}` is the convention for streams the operator
toggles in the marketplace: the connector service fills `STREAMS` with the ids
of the manifest streams the operator enabled.

## Enrichment-lane collectors (`source_type: nano_enrich`)

A collector that pulls reference data rather than logs (users, assets) ships
with `source_type: nano_enrich` and stamps each record with
`kind` (e.g. `identity`), `source` and `provider_id`. Vector routes these to
the enrichment normalizers instead of a log parser, so the stream names no
parser in its manifest. `okta_users` is the example.

## Identity directory sync (`kind: identity`)

An identity connector syncs a directory (users, group memberships) into the
tenant's identity directory through its enrichment coordinator. It has no
ingest, no `source_type`, no parser and no ingest token.

```yaml
kind: identity
identity: { full_every_secs: 86400 }     # force a full snapshot at least this often
streams:
  - id: users
    identity: { role: users, mode: delta }   # mode: full (default) | delta
    request: ...
    program: |                            # vendor user -> canonical row
  - id: groups_members
    identity: { role: memberships }       # always full
    fanout: { discover: { from: request, request: ..., response: { events_path: groups } }, item_key: id }
    request: { url: "https://.../groups/{{item.id}}/members" }
    program: |                            # emits {"member": <user id>, "group": "<name>", "privileged": bool?}
```

- Users rows use the directory's field names: `external_id` (required, the
  vendor's immutable id), `username`, `upn`, `email`, `display_name`,
  `first_name`, `last_name`, `department`, `title`, `manager_upn`,
  `manager_display_name`, `manager_external_id` (resolved to
  `manager_upn`: by the engine from the same run, else by the coordinator
  from the directory), `company`, `office_location`, `city`,
  `country`, `account_enabled`, `account_status`
  (`active|suspended|disabled|deprovisioned|locked|staged|unknown`; until
  the runner sets `CONNECTOR_IDENTITY_V2_FIELDS`, `deprovisioned`, `locked`
  and `staged` are sent as `disabled`, `suspended` and `unknown`),
  `mfa_enabled`, `last_sign_in_at`, `created_in_directory_at` (RFC 3339 or
  epoch), `phone`, `employee_id`, `employee_type`, `is_admin`, `deleted`
  (delta tombstone) and `version`. Other fields are dropped. The engine
  stamps the provenance (`feed_id` = `<feed>:<stream id>`, `source_kind`,
  `snapshot_id`, `observed_at`).
- A full run starts from `initial_state` (the saved cursor is ignored),
  stages every page with the coordinator and commits the snapshot at the
  end: users absent from it disappear. Its checkpoint (cursor and
  `identity_last_full_at`, `identity_last_full_rows`) is saved only after
  that commit. A full run that returns no users fails rather than empty the
  directory, and one that finds fewer than half the users of the previous
  full run fails before the commit (`identity_shrink_refused`; the counts
  are logged) unless the feed config sets `identity_allow_shrink: true`
  (with it, an empty run commits an empty snapshot; the coordinator also
  refuses zero rows without that explicit `allow_empty`).
- A delta run sends each page as a patch delta and saves the cursor after
  the coordinator acknowledged it. `deleted: true` rows are tombstones.
  Delta runs need the runner's `CONNECTOR_IDENTITY_V2_FIELDS` (the v2
  coordinator contract); without it every users stream runs full.
- The engine runs full when there is no checkpoint, the last full run is
  older than `identity.full_every_secs`, or the program returns
  `{"restart_full": true}` (Graph 410 Gone / `syncStateNotFound`). The VRL
  input carries `.identity.mode` (`"full"` or `"delta"`) so the program can
  pick its first request.
- Memberships streams run after the users streams on every run. The engine
  aggregates their pairs into one row per member on the `<feed>:groups`
  sub-feed (`groups` sorted, `is_admin` = any `privileged`, sent only with
  `CONNECTOR_IDENTITY_V2_FIELDS`), bounded by
  `limits.max_identity_memberships`.
- Memberships streams never checkpoint (no per-group `state.items`): they
  are always full. Their fan-out may discover up to 100,000 items (an unset
  `max_items` means that); discovering more fails the run instead of
  committing a partial groups snapshot. If a memberships walk finds no
  memberships at all, the previous groups snapshot is kept (the coordinator
  cannot commit an empty snapshot and the writer token cannot delete).
- Users streams may omit `request`: the program is then called first with
  `.response == null` (and `.identity.mode` set) and returns the first
  `next_request`.
- Limits: identity runs get higher defaults (3,600 s, 20,000 pages, 100,000
  requests, 10M events, 8 GiB) when the spec leaves a limit at the
  collector default, and higher ceilings (10x pages and requests, 2x events,
  8x event bytes of the platform ceilings). The runner's run-time cap still
  applies.
- A full run replaces the sub-feed (highest `version` wins). A delta row is
  a patch: a field it omits (or sends empty) keeps the directory's value,
  so a vendor delta that resends only changed properties (Graph) is safe.
  A patch cannot clear a field; the next full run does. A delta row whose
  manager is not in the same run is sent with `manager_external_id` as a
  reference the coordinator resolves against the directory, so unchanged
  managers are kept.
- A feed has one users stream and its id is `users`: the feed's directory
  rows are exactly `<feed>:users` and `<feed>:groups`, which is what an
  uninstall removes (the runner deletes both at the tenant coordinator,
  retrying with backoff, before the feed row goes).
- Users streams cannot fan out; no identity stream may use `window`,
  `write_ahead_state` or `restart_window_on`.

## Templates

`{{config.X}}`, `{{state.X}}`, `{{item.X}}`, `{{input.artifact}}`,
`{{input.artifact_type}}`, `{{window.start}}`, `{{window.end}}`, `{{now}}` and
`{{initial_cursor}}` (the stream's first cursor, RFC 3339; `{{backfill_from}}`
is a deprecated alias with the same value) are available. There is no `credentials` namespace; the
engine refuses a request that contains a secret. Values are percent-encoded
in paths. A query value that renders empty is dropped.

## The VRL loop (`program`)

The program runs once per response, and once before the first request when
`request` is absent. Its input is:

```
.state .response{status, headers, body, links.next} .request{url, method}
.config .input .item .window{start,end} .now .initial_cursor
```

`.initial_cursor` is the stream's first cursor (activation − 5 min), fixed at
activation. A program with no saved position starts there; never fall back to
"all history". `.backfill_from` is a deprecated alias with the same value.

`.response` is null on the pre-first call.

The program must return an object with these optional keys:

```
{ "events": [...],             # shipped to ingest (after dedupe/caps)
  "next_request": {url?, method?, query?, form?, json?} | null,   # null/absent = done
  "state": {...},              # replaces .state; committed after ingest acks
  "wait_ms": 1000,             # polite pause before the next request
  "error": "message" }         # fail the run with this message
```

How `next_request` works:

- A `next_request` without `url` reuses the stream's `request` url and query.
- A `query` value of `null` removes that parameter.
- It cannot set headers.

Rules for the program:

- Comparisons on unknown types are fallible in VRL. Coerce first, for example
  `status = to_int(.response.status) ?? 0`.
- Use `!` only on fallible calls.
- Closures in `for_each` and `map_values` can update outer variables.
- Network, env, random, decompression, file and keyed-crypto functions are not
  available.
- The program runs in a sandboxed worker process with no network and no
  filesystem. The engine fetches and parses for it.
- Each call has a time budget (`limits.vrl_timeout_ms`), and the reply is
  capped at twice `limits.max_response_bytes`. The whole checkpoint, which
  holds `state`, is capped by `limits.max_checkpoint_bytes` (default 4 MiB,
  ceiling 16 MiB). Keep cursors in `state`, not page contents.
- Very deep nesting (hundreds of levels) fails validation.

With a `program`, the events come from the program, not from `events_path`.
For enrichments, `agent_enrichment` returns one event: `{key, key_type,
risk_score?, tags?, data}`. `data_enrichment` returns records the same way.

## Checklist

- Prefer declarative fields. Use VRL for vendor-specific stop conditions,
  shaping, or multi-step lookups.
- Keep `allow` to the hosts and path prefixes you call. If OAuth is used,
  allow the token endpoint too. Requests go to port 443 over https only, and
  a tenant's egress deny list always overrides `allow`.
- Give a stable `uid_field` whenever you use `window`. Without one, dedupe
  cannot work. Without a window, set `ingest_id.fields` to the vendor's id.
- Set `ingest_id` to the vendor's stable id (plus a version field when the
  vendor updates records in place), and make the parser's `metadata.uid` use
  the same fields.
- Add a shadow test in the content repo, including a restart from the run's
  checkpoints that ships nothing.
- Respect the vendor's documented page size, rate tier and error shapes. Put
  the vendor's error text in `error`.

## Native request sequences and value helpers

Hosts can use `sequence::compile` / `sequence::run` for bounded chained HTTP
requests without a script or VRL program. Requests use the existing auth
registry, broker, HTTPS host/path policy, public-address guards and platform
deny rules. The caller supplies request usage accounting. Sequences do not retry transport errors or follow redirects. Session login
may refresh once and resend after an explicit 401 refusal; other statuses
and ambiguous writes do not enable this exception. Polling is read-only and
bounded by time, request count and aggregate bytes. Once a write is accepted,
an unverified completion returns an ambiguous outcome.

Sequence scope adds `steps.<id>`, `poll`, `run`, `alert` and `case` to the existing
template namespaces. A host controls which namespaces its format admits.
Credentials, auth, secret and environment namespaces remain forbidden.

The closed helpers are `coalesce a b`, `first array`, `join array delimiter`,
`lower string`, `json_quote value`, `base64url string`,
`notification_body format event target`, and `with_field object key value`. JSON double-quoted literals and parenthesized
nested calls are supported. Examples: `{{coalesce input.id steps.resolve.ids.0}}`
and `{{join input.ids ","}}`. `coalesce` evaluates lazily. There is no general
expression evaluation, scripting, filtering or access to host functions.
Evaluation and aggregate rendering have byte budgets. `base64url` returns RFC
4648 URL-safe Base64 without padding, for read-only URL identifier lookups. It
accepts only strings and checks the encoded size before allocation. Empty JSON
array/object literals (`[]`, `{}`) can supply typed `coalesce` defaults.

Request execution checks every evaluated expression value against registered
connection/caller credentials and derived tokens before an outer helper runs.
Nested encoding, JSON quoting, case conversion, and reconstruction with `join`
cannot conceal credential material. A refusal occurs before vendor dispatch;
dry runs also refuse credential-bearing helper operands while preserving
redaction of raw preview values. Diagnostics never include the refused value.
Unselected lazy `coalesce` branches remain unevaluated.

Sequence response expectations can require multiple exact JSON values with
`expect.fields`, a map of at most 16 dotted paths (256 bytes each) to literal
values. Every field must exist and match its value and type. For example,
`fields: {attempted: 1, succeeded: 1, "results.0.error": null}` combined with
`path: results, items: 1` rejects zero, partial and multi-result receipts.
An explicit null requires a present JSON null; missing fields fail. Paths use
alphanumeric/underscore segments and array indexes. Values are not templates.
Empty `fields` is omitted from serialization, preserving existing sequence bytes.
An explicitly empty `expect.path` selects the complete JSON body. Combine
`path: ""`, `items: 1` and exact `fields` checks for root-array batch receipts;
for example, HTTP 207 alone does not prove that its individual items were accepted.
Form fields whose entire value is a missing `input.*` reference are omitted,
matching optional query parameters. Literal empty strings and explicit helpers
remain present. This supports bounded optional AWS Query group parameters
without sending empty group IDs or discarding supplied restoration state.

A URL may start with a single `{{config.base_url}}` containing an HTTPS origin,
or retain the existing `https://{{config.host}}/path` form with a bare host.
Origins cannot contain userinfo, query, fragment, a path prefix or a non-443
port. Dynamic origins still need constrained allow rules. Path substitutions
are encoded as single segments, and dot-segment substitutions are refused.

SOAR action packs may explicitly type a non-secret connection field as
`format: https_endpoint`. A request URL consisting of exactly
`{{config.<field>}}` then selects that complete configured HTTPS URL, including
its non-secret path. It requires a DNS hostname on port 443 and refuses
userinfo, query, fragment, reserved names, IP literals and embedded templates.
It is resolved before native request compilation into one exact host; private
or mixed DNS answers and platform denials remain blocked by the broker. The
existing tenant/connection/revision-bound egress helper and inventory publish
that same exact host. Optional vendor suffixes, enumerated values and path
constraints still apply. A flow input cannot select or append to the endpoint.
This opt-in belongs to the signed pack definition, not to an environment flag
or to ordinary untyped config. Token/login endpoints do not use this format.

`preview::ReplayTransport::strict` consumes expected exchanges in order and
checks the exact method, URL, query and JSON/form body. Unexpected duplicate
query parameters, incorrect bodies and extra/missing exchanges are refused.
Use `assert_complete()` after execution. Independent recordings have distinct
identities so a host can isolate authentication caches from live execution.


## Session auth example (synthetic protocol only)

```yaml
auth:
  type: session_login
  login_url: "https://{{config.HOST}}/login"
  credential_fields: { username: USER, password: PASSWORD }
  encoding: json
  response: { type: json_token, pointer: /session/token, header: X-Session }
```

Allow the login route and the API routes explicitly. Construct a new auth
plugin/plan for each connection or collector run; never share a cached plugin
between tenants or credential sets. The native action host does this through
its connection context. A context retains at most 1,024 session tokens for
redaction; after that, re-create the context. Dry runs show authentication
placeholders and make no login request or usage charge. This example is not a
vendor action pack and contains no credential values.

### Duo v5 authentication

`duo_hmac {integration_key_credential, secret_key_credential}` implements the
vendor's [current signing protocol](https://duo.com/docs/adminapi#authentication)
for Admin/Auth/Device APIs. It uses the engine clock for Date, RFC 3986 sorted
query parameters, SHA-512 hashes of the exact JSON body and canonical X-Duo
headers, then HMAC-SHA512 in an HTTP Basic envelope. GET/DELETE bodies, form
mutations, malformed query encodings, duplicate query/header names and unknown
plugin fields are refused before sending. POST/PUT/PATCH require a JSON object.
The plugin owns Date/Authorization and retains derived signatures for redaction
within the compiled request cap. No v2/SHA-1 fallback or shared credential cache
is used. Declare the exact vendor API host and path scope in `allow`.

OAuth client credentials additionally accepts `client_auth: basic` (default:
`body`). Basic authenticates only the token POST; it does not duplicate secrets
in the grant form. `scope` may reference connection `config.*`, never flow inputs;
the rendered scope is bounded to 4096 characters and cannot contain controls.

A response expectation can use `path: findingIds, json_type: array` to accept
an empty documented result while refusing missing/wrong-type fields. Supported
`json_type` values are `array`, `object`, `string`, `number`, `boolean` and `null`;
`null` requires an explicitly present field. `path: ""` selects the JSON root.

Independent replay request contracts may declare non-secret `headers` alongside
method, URL, query and body. Header names match case-insensitively; values match
exactly, and a missing or duplicate matching header fails replay. Auth-bearing
headers can stay omitted so fixtures never need credentials. Use this for
vendor API-version, media-type and required client-identification headers.

SOAR input `type: text` accepts multiline ticket/alert content with a hard 16 KiB
UTF-8 byte ceiling. Optional `max_bytes` can lower it (1–16384); tabs, CR and LF
are allowed as JSON payload data, while other control characters are refused.
`max_bytes` is valid only on text inputs. Identifier `string` keeps its existing
2 KiB/no-control grammar. Regex patterns stay identifier-only; use the text byte
ceiling for long descriptions. URL/header policy and encoded-secret outbound
checks still run before any transport call. No text value becomes a template or
host program.

SOAR `deployment_scope: self_hosted_sovereign` is a signed publisher restriction. Only the trusted `SelfHosted` startup profile (including sovereign customer installations) may install, connect or execute it; hosted/shared/demo profiles refuse it. Customer config, action inputs and run metadata cannot select deployment authority. `config.format: https_origin` is available only with that scope and accepts one certificate-valid HTTPS FQDN origin on port 443; action paths append to it, while the exact configured host and reviewed API path prefixes remain mandatory. `https_endpoint` keeps its complete-URL/public-only behavior.

For scoped packs the native broker permits RFC1918/ULA corporate DNS answers, pins and checks every answer, and keeps explicit platform/tenant denies. Loopback, link-local, CGNAT, cloud metadata (including `fd00:ec2::/32`), reserved addresses, Kubernetes service/cluster DNS and IP literals stay refused. A trusted self-managed startup saves its original dialer for scoped packs inside the existing authority-guarded transports; public packs retain the proxy route and public-only IP policy. Private pack hosts never become hosted proxy grants. There is no direct fallback from a failed public proxy request, or customer/network environment knob enabling this authority.

SigV4 retains each issued Authorization value and isolated signature as derived secrets, so reflected response bodies, summaries and downstream action outputs are scrubbed like raw credentials. Retention is bounded by the compiled request cap; signing refuses before send at the cap rather than evicting an early signature that a later response could reflect. The closed auth registry reflection suite must cover every registered plugin.

## SOAR action output contracts

Native action packs may declare `output_types` alongside `outputs`. The keys
must cover exactly the extracted output names. Supported JSON types are
`string`, `integer`, `number`, `boolean`, `array`, and `object`. Values are
validated after native execution and secret redaction, without coercion:

```yaml
outputs:
  score: steps.lookup.score
  matches: steps.lookup.matches
output_types:
  score: integer
  matches: array
```

Missing or null output paths already fail native extraction. A Read action with
a wrong output type fails with `invalid_outputs`; after an accepted mutation,
the result is ambiguous so a flow cannot retry it as a known failure. Dry runs
render requests without requiring vendor response values. Declared scalar
outputs may be used as compile-time-validated Judge entity references. Object
and array outputs remain usable as evidence but cannot serve as scalar entities.
Omitting the map preserves existing pack behavior and canonical bytes. These
fields belong to the native ActionPack schema, rather than the collector
ConnectorSpec schema linked above.

A native action output may reference an entire preceding response with `steps.<step_id>` (including a top-level JSON array). It has the same prior-step visibility and secret-redaction rules as field extraction; declare `array` or `object` in `output_types` to enforce the required shape.

## SOAR deployment eligibility

Action packs restricted to self-hosted/sovereign installations declare the
signed top-level field `deployment_scope: self_hosted_sovereign`. Omitting it
preserves the unrestricted legacy default and canonical bytes. A `self_hosted` category
requires this field; a category alone grants no deployment permission.

The trusted startup deployment policy used by private SMTP also gates pack
installation/upgrades, connection creation/update/use, and action execution.
Managed, shared-enterprise, and demo deployments cannot admit these packs;
tenant configuration cannot override the gate. Offline converter replay
selects the self-hosted profile only for scoped artifacts. This field
does not relax artifact validation or hosted egress. Private-network admission
requires the trusted self-hosted scope and native DNS/deny rules documented above.

## Scoped JSON credentials with existing OAuth

`oauth2_json_credential` wraps the existing `oauth2_client_credentials` plugin;
its `oauth2` object uses the same parameters, token allowlist, cache, 401 handling
and secret retention. It does not introduce another OAuth implementation.
`credential`, `field_pointer`, `selector_pointer` and `selector_value` select a
native credential and a single bounded JSON mutation discriminator. Pointers
are literal object identifier paths (1–8 segments); JSON Pointer escapes and
array traversal are refused. The selected field must be absent from the initial
request. Other discriminator values and reads use OAuth without injection.
All plugin credential fields remain required by sequence admission.

For example, Jamf `DEVICE_LOCK` uses `/commandData/commandType` as discriminator,
`/commandData/pin` as destination and `six_digit_pin` as `format`. The PIN stays
in the connection credential store, never in flow inputs/config/templates.
`opaque` is the default format, with the engine minimum secret length and a
16 KiB ceiling. Mutation bodies require application/json, an object and a
1 MiB limit. Fields cannot alias OAuth credentials. Retained summaries and
response echoes use existing secret redaction. Exact already-decorated request
fingerprints allow auth reapplication without allowing initial field overrides;
retention is bounded by the native request limit (max 4096), never evicted.

`{{with_field steps.current.properties "status" input.status}}` creates a copy
of a JSON object with one field replaced. The key must be a 1–64 byte ASCII
alphanumeric/underscore identifier; this is a field name, not a path or program.
Existing expression depth/size, deferred-response and secret-namespace guards
apply. Sentinel uses it to preserve every fetched incident property during its
etag-protected status PUT, avoiding silent resets of owner/labels/description.

### Bind mutation targets to an identity Read

Sequence `expect.input_equals` maps at most 16 response JSON paths to literal
required string input names, for example `input_equals: {id: device_id}`. Paths
use the same bounded dotted grammar as `expect.fields`; input names cannot be
templates, namespaces or helpers. Both values must exist as nonempty strings and
match exactly, without coercion. Missing/null/wrong-type/mismatched identities
refuse before the next step. SOAR admission requires each named input to be a
required string. Empty maps are omitted from serialized definitions.

Device mutations perform the Read inside the same approved native sequence and
connection/auth context, then derive their command target from `steps.identity`.
For Jamf, bind both the inventory `id` and `general.managementId` to the selected
`computer_id` and `management_id`; dispatch only the returned management UUID.
This avoids trusting an independent flow input as the command target. No external
identity receipt, cross-tenant cache or credential/egress change is introduced.
