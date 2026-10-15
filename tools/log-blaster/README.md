# log-blaster

Generate profile-driven security logs. Build with `cargo build --release -p log-blaster`.
Run `target/release/log-blaster --help` for normal, blast, spike, HEC, Tenzir,
dev, and OTLP options.

## Hosted source-mode tenants

Hosted source credentials are HEC-only: use `--hec`. The Vector HTTP lane
(without `--hec`, Bearer auth) is for self-hosted Vector only.

Enroll each source on the tenant's Log sources page and store its credential in
the corresponding shell variable below. This runs at **2,000 aggregate EPS for
5 minutes**; it then drains outstanding requests and retries before exiting.

```bash
target/release/log-blaster \
  --hec --vector https://tenant1.ingest.nano.rs \
  --blast --eps 2000 --duration 5 --threads 8 --batch-size 250 \
  --chain-interval-secs 0 --idempotency-key-prefix blast-demo \
  --source-token "windows_sysmon=${SYSMON_TOKEN:?set SYSMON_TOKEN}" \
  --source-token "windows_event=${WINDOWS_TOKEN:?set WINDOWS_TOKEN}" \
  --source-token "conduit_proxy=${PROXY_TOKEN:?set PROXY_TOKEN}" \
  --source-token "aws_cloudtrail=${CLOUDTRAIL_TOKEN:?set CLOUDTRAIL_TOKEN}" \
  --source-token "apache_access=${APACHE_TOKEN:?set APACHE_TOKEN}"
```

- `--source-token SOURCE_TYPE=TOKEN` is repeatable. Alternatively set
  `SOURCE_TOKENS=windows_sysmon=token1,windows_event=token2`. CLI entries override
  environment entries for the same source; the last duplicate wins. Tokens may
  contain `=`. Commas delimit environment entries; use CLI flags for tokens with commas.
- Specific tokens take precedence over `--token`, then `VECTOR_AUTH_TOKEN`.
  When source tokens are supplied, the built-in development token is **not** a
  fallback. Sources lacking credentials are skipped with a startup warning.
  The run fails before sending if no selected source has a credential.
- `--sources windows_sysmon,windows_event` explicitly restricts the mix.
  Supported names are `windows_sysmon`, `windows_event`, `conduit_proxy`,
  `aws_cloudtrail`, and `apache_access` (`apache_http_server` is an alias).
- Source tokens produce source-homogeneous batches in both transports. The historical mix
  (60% Sysmon, 10% Windows Event, 12% proxy, 8% CloudTrail, 10% Apache) is
  renormalized over enabled sources, preserving the aggregate EPS target.
- These options require Vector or HEC blast mode and disable the lateral-chain
  emitter so it cannot bypass source selection or credentials. HEC sends to
  `/services/collector/event` with `Authorization: Splunk <source-token>`,
  `source` and `sourcetype` set to the credential slug (`apache_access` for
  Apache), and the raw log string in `event`. It sends no `X-Source-Type` header.
- HEC source batches each have a UUID `X-Splunk-Request-Channel`. With
  `--idempotency-key-prefix`, the `Idempotency-Key` is `<prefix>-<batch UUID>`.
  Retries reuse the channel, key, and body; new batches receive fresh UUIDs.
  Without the explicit prefix, neither Vector nor HEC adds an idempotency key;
  retries may duplicate events.
- Vector source mode retains Bearer auth and `--dev` support (appends `/ingest`).
  With source tokens, Apache is sent as the enrolled slug `apache_access` on
  both lanes (the hosted Worker rejects any other name for that credential);
  `apache_http_server` remains accepted as a token alias.

Vector and HEC source-mode blast periodic EPS output and the final summary include cumulative
per-source counters: `sent` counts logical events dispatched once; `accepted`
counts events whose request succeeded; `refused` counts events ending in an HTTP
error after retries; `failed` counts events ending without an HTTP response.
`http={202: 4, 401: 2}` counts individual HTTP responses, including retries;
`network_errors` counts attempts without a response. In-flight events are not
accepted or refused until their request finishes. EPS reflects accepted events,
including successful sources in a partially failed mixed batch. Acceptance is
an HTTP acknowledgment (including HEC `200` responses with `ackId`), not a
downstream query verification. Background lateral
chains in legacy runs are outside blast accounting.

## Local examples

```bash
target/release/log-blaster --vector http://localhost:8080 --dev --rate 30
target/release/log-blaster --hec --blast --eps 5000 --duration 1
target/release/log-blaster --tenzir --rate 30
target/release/log-blaster --otlp --blast --eps 2000 --duration 1
```

## Tests

```bash
cargo test -p log-blaster -p event-core -p injector
```

Tests cover credential precedence, environment parsing, source restriction,
homogeneous implication, validation, and a loopback HTTP receiver that verifies
Vector headers and Bearer tokens, HEC paths/envelopes and Splunk tokens,
Apache aliases, partial success, 401 retry counts, UUID channels, and stable
idempotency keys. Tests do not access a live tenant.

Blast batches accumulate paced events up to `--batch-size` or
`--max-batch-latency-ms` (default 2000), whichever comes first. The latency
bound applies to accumulation before dispatch; in-flight backpressure and
HTTP retries can delay delivery. Fractional per-thread rates preserve the
aggregate `--eps`, even when it is not divisible by `--threads`. Source-mode
requests retain a single source and its credential. At 300 EPS with two
threads, batch size 500 and the default latency produce up to 300 events per
request; use a longer latency if full 500-event batches are required.
