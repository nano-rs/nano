# Verify

An install is verified only when every row below has real output. Health and
login alone are not a verified install. Paste the result table into the work
log and show it to the operator.

## Single node

```bash
ssh $H 'cd ~/nano && docker compose -f docker-compose.opensource.yml ps --format "table {{.Name}}\t{{.Status}}"'
ssh $H 'python3 -I - --app-url http://localhost' < scripts/smoke-test.py
```

`smoke-test.py` checks health, admin login, the license state, ingest of a
uniquely marked JSON event through `/ingest/` with a short-lived source-bound
token (revoked afterwards), and search for that marker. It reports the write
latency and FAILS when the event takes longer than `--write-sla` (default
60 s) to become searchable. It deploys its log source only the first time
(`--redeploy` forces it; never during a failover drill). Then check from
outside the host, through the real public path:

```bash
curl -fsS https://APP_FQDN/api/health          # through the LB / TLS overlay
curl -sS -o /dev/null -w '%{http_code}\n' http://APP_FQDN/   # expect 301 to https with the overlay
```

## Kubernetes (Helm)

```bash
python3 -I scripts/k8s-health.py --namespace nano          # read-only; exit 0 = healthy
python3 scripts/smoke-test.py --app-url https://APP_FQDN --ingest-url https://INGEST_FQDN --creds ./admin-creds.env
```

`ingest-hz` (`GET https://INGEST_FQDN/healthz`) is a 404 on chart 2.0.9 and
earlier, where the ingest Gateway did not route it: a WARN there, not a
failure, when every ingest check passes. From 2.0.10 it must be 200.

## Limits and delays that look like failures

Tell the operator about these before a test or a drill, so a 401 or a 429 is not
read as a broken install:

- **Sign-in is rate limited**: 100 attempts per client IP per 5 minutes and
  10 per account per 10 minutes, successful ones included. Over the limit the
  API answers 429 with `Retry-After`. A probe that signs in every few seconds
  as one user hits the per-account limit; reuse the session token instead.
- **A new ingest token** is accepted by each ingest host within a few seconds
  (each host polls the token list every 2 s, then reloads Vector). The first
  requests with a brand-new token can get 401 from a host that has not picked
  it up yet; retry, or wait about 10 s before sending. Revocation takes effect
  the same way.
- **HEC admission** (multi-node ingest edge): per token 100 requests/s with a
  burst of 200, per client IP 50 requests/s with a burst of 100, per ingest
  host 1000 requests/s with a burst of 2000, at most 16 concurrent
  connections per client IP, and 8 MiB per request. Over the limit: 429; the
  sender should back off and retry. Batch events into fewer, larger requests
  rather than raising the request rate. `/ingest` and `/enrichment` allow
  1000 requests/s per client IP with a burst of 500 (100 MiB per request).
  OTLP/HTTP has no request-rate limit at the edge (100 MiB per request; every
  request is authenticated against its token).

## 3-node HA

```bash
# Containers on every host
for h in $H1 $H2 $H3; do ssh $h 'docker ps --format "{{.Names}}\t{{.Status}}" | sort'; done

# Keeper quorum and ClickHouse replicas, on every host
for h in $H1 $H2 $H3; do ssh $h 'python3 -I - --install-dir ~/nano' < scripts/cluster-health.py; done

# End to end from the app host, ingest through each ingest host in turn
for ing in http://<ip2> http://<ip3>; do
  ssh $H1 "python3 -I - --app-url http://localhost --ingest-url $ing" < scripts/smoke-test.py
done
```

Expect one Keeper `leader` with 2 synced followers and two `follower`s, both
replicas in `system.clusters` (seen from `nano-2` and `nano-3`), no read-only replicated tables, and a
replica delay of 30 seconds or less, and a `PASS` on every `gw:` row: each is
one of the host's own HAProxy gateways read from its runtime socket. A
`gw:clickhouse-proxy` FAIL naming the local replica means the host's
containers cannot reach the host's own address (host firewall blocking
Docker bridges); fix it before go-live. `cluster-health.py` exits 3 with
`INCONCLUSIVE` when `system.replicas` does not answer in time (it can block
behind table locks on a busy, small host). That is not a pass: wait a few
minutes and re-run it. If it persists, report it with `system.processes`
output. The script reads the system tables as `nanosiem_admin` with
SELECT-only queries, as the product's upgrade preflight does, because the
runtime `nanosiem` user cannot. Check the edge contract too:

```bash
ssh $H1 'curl -s -o /dev/null -w "%{http_code}\n" http://localhost/ingest'        # 404: app edge refuses ingest
ssh $H1 'curl -s -o /dev/null -w "%{http_code}\n" http://localhost/api/internal/' # 404
ssh $H2 'curl -fsS http://localhost/healthz'                                       # 200: ingest on nano-2 ready
ssh $H3 'curl -fsS http://localhost/healthz'                                       # 200: ingest on nano-3 ready
```

From the workstation, outside the cluster, nothing but the load balancer may
answer:

```bash
bash scripts/preflight.sh --exposure-probe <ip1>,<ip2>,<ip3>   # every row PASS
```

Use the public addresses when the hosts have them. A `WARN` on PostgreSQL,
Valkey, etcd, Patroni, Sentinel, ClickHouse or Keeper is a go-live blocker.

Optional failover drill, with operator approval: stop ClickHouse on `nano-3`
(`docker stop` its clickhouse container), re-run the smoke test, then start it
again. Show that `cluster-health.py` returns to `PASS` and the replica delay
recovers.

## License

`smoke-test.py` prints `state`, `valid`, `expires` and the entitlement
(offering, capacity). Report them as they are:

- `valid=True`, `mode=hosted` (online license) **and** an entitlement or
  expiry: done.
- `valid=True` with no entitlement, expiry or license ID (the smoke test says
  `NO LICENSE BOUND`): there is no license. The API may say "active" because
  no license URL is configured. Report it as unlicensed, never as licensed.
- Not valid with enrollment applied: check outbound HTTPS to `LICENSE_URL`,
  `docker logs` of `nano-api` and `nano-jobs` for license lines, and
  [known-issues.md](known-issues.md). Never edit license tables or fabricate
  license state.
- No enrollment yet: report "running unlicensed; apply the enrollment values
  before production use". Do not promise that the enterprise features are
  locked or unlocked. That depends on the release (see
  [known-issues.md](known-issues.md)).

The app.nano.rs deployment page should also show the install's license
check-in within a few minutes.

## Report format

| Check | Host | Result | Evidence |
|---|---|---|---|
| containers healthy | node-1 | PASS | 14/14 running (healthy) |
| health | app | PASS | GET /api/health 200 |
| login | app | PASS | admin@... 200 |
| license | app | WARN | state=... valid=False (no enrollment yet) |
| ingest → search | app via node-2 | PASS | marker found after 12 s |
| keeper quorum | all | PASS | leader + 2 followers |
| ch replicas | all | PASS | 3/3 active, max delay 0 s |

Then hand over: the login URL, where the admin password is
(`~/.nano-admin-credentials` on the app host, which they should move into a
password manager and then delete), the ingest endpoint for senders, and the
next steps: issue per-source tokens in **Ingestion → Log Sources →
Credentials**, set up backups ([operate.md](operate.md)), and configure the
firewall.
