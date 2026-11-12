# Writing a nano connector spec

A connector is one YAML file, validated by `connector.schema.json`. The engine
does the HTTP, auth, paging, retries, rate limits, time windows, dedupe,
checkpoints and caps. You describe the API. Add an optional VRL `program` only
when the API needs logic that the declarative fields can't express.

Check your work with `nano-connector validate spec.yaml`. Then dry-run it with
`nano-connector preview spec.yaml recording.json --config K=V --creds-stdin`
(credentials as `K=V` lines on stdin, or `--cred-file K=PATH` for a mode-0600
file; values are never accepted on the command line), which runs offline
against recorded responses.

## Where specs live

First-party specs ship in the content repos, as `connector.yaml` next to the
integration's `manifest.yaml` (and, until cutover, its `code.ts`):

- `nano-integrations/integrations/<name>/connector.yaml` (collectors)
- `nano-enrichments/enrichments/{agent,data}/<name>/connector.yaml` (enrichments)

The manifest names the spec and says which runtime runs the entry:

```yaml
runtime: connector          # or deno (the default): code.ts, run on the wasm sandbox since 2.0.14
connector_spec: connector.yaml
```

Marketplace sync copies the spec into the catalog row's `config` as
`runtime`, `connector_spec` and `connector_spec_sha256`. A feed pins the
sha256 it was configured against. The `execution_backend` column is unchanged.

Only first-party content is ported. `runtime: deno` is a historical value:
since 2.0.14 the `code.ts` script runs on the embedded wasm sandbox, not Deno.
Operator-written scripts keep running there; one that cannot (plain http, a
credential outside a header) is marked needs attention until it is fixed.

`nano-connector/tests/fixtures/specs` holds frozen copies for the engine's own
tests; they are not the shipped specs.

## Shadow runs: prove a port against the original script (dev tooling; needs a local Deno)

Each content repo has `testing/shadow/`. It runs the Deno script and the
connector against the same vendor mock and diffs what each one ships:

```
nano-connector shadow connector.yaml --mock-url http://127.0.0.1:PORT \
    --creds-stdin --cred-file K=PATH --config K=V \
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
kind: collector                    # collector | agent_enrichment | data_enrichment
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
- The hosted platform's keyless broker plugins (`google_dwd_broker`,
  `entra_fic_broker`, `okta_broker_jwt`) are not part of this engine
  (NAN-4914). Single-tenant equivalents: Google Workspace domain-wide
  delegation with `google_service_account` + `subject` (the customer's own
  service-account key), Entra with `oauth2_client_credentials`, Okta with
  `okta_ssws`. A spec naming a broker plugin fails to compile.
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

## Identity directory sync

Do not author an ordinary collector with `source_type: nano_enrich`: generic
ingest rejects that contract with 409. Directory connectors use `kind:
identity` plus per-stream `identity.role` and bypass Vector entirely. The
runner writes through its fenced ClickHouse directory target; bundled
`okta_users` and `entra_directory` are the examples. Log collectors such as
`okta_system_log` continue to deliver through HEC and a parser.

The separate native provider scheduler in `nanosiem-core/src/identity/sync`
uses Vector's dedicated `/enrichment`/`:8090` lane. That internal transport is
not a connector-authoring surface.

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

## Template value helpers

The closed helpers are `coalesce a b`, `first array`, `join array delimiter`,
`lower string`, `json_quote value`, `base64url string` and
`with_field object key value`. JSON double-quoted literals and parenthesized
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

A URL may start with a single `{{config.base_url}}` containing an HTTPS origin,
or retain the existing `https://{{config.host}}/path` form with a bare host.
Origins cannot contain userinfo, query, fragment, a path prefix or a non-443
port. Dynamic origins still need constrained allow rules. Path substitutions
are encoded as single segments, and dot-segment substitutions are refused.

## Replay transport

`preview::ReplayTransport::strict` consumes expected exchanges in order and
checks the exact method, URL, query and JSON/form body. Unexpected duplicate
query parameters, incorrect bodies and extra/missing exchanges are refused.
Use `assert_complete()` after execution. Independent recordings have distinct
identities so a host can isolate authentication caches from live execution.

Independent replay request contracts may declare non-secret `headers` alongside
method, URL, query and body. Header names match case-insensitively; values match
exactly, and a missing or duplicate matching header fails replay. Auth-bearing
headers can stay omitted so fixtures never need credentials. Use this for
vendor API-version, media-type and required client-identification headers.

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

SigV4 retains each issued Authorization value and isolated signature as derived secrets, so reflected response bodies, summaries and downstream action outputs are scrubbed like raw credentials. Retention is bounded by the compiled request cap; signing refuses before send at the cap rather than evicting an early signature that a later response could reflect. The closed auth registry reflection suite must cover every registered plugin.

## Scoped JSON credentials with existing OAuth

`oauth2_json_credential` wraps the existing `oauth2_client_credentials` plugin;
its `oauth2` object uses the same parameters, token allowlist, cache, 401 handling
and secret retention. It does not introduce another OAuth implementation.
`credential`, `field_pointer`, `selector_pointer` and `selector_value` select a
native credential and a single bounded JSON mutation discriminator. Pointers
are literal object identifier paths (1–8 segments); JSON Pointer escapes and
array traversal are refused. The selected field must be absent from the initial
request. Other discriminator values and reads use OAuth without injection.
Every secret credential field a plugin reads must be present and at least six bytes (see the engine credential check).
