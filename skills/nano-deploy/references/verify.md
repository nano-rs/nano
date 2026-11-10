# Verify

An install is verified only when every row below has real output. Health and
login alone are not a verified install. Paste the result table into the work
log and show it to the operator.

## Single node

```bash
ssh $H 'cd ~/nano && docker compose -f docker-compose.opensource.yml ps --format "table {{.Name}}\t{{.Status}}"'
ssh $H 'python3 -I - --app-url http://localhost' < scripts/smoke-test.py
```

`smoke-test.py` checks health, admin login, the licence state, ingest of a
uniquely marked JSON event through `/ingest/` with a short-lived source-bound
token (revoked afterwards), and search for that marker. Then check from
outside the host, through the real public path:

```bash
curl -fsS https://APP_FQDN/api/health          # through the LB / TLS overlay
curl -sS -o /dev/null -w '%{http_code}\n' http://APP_FQDN/   # expect 301 to https with the overlay
```

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
replica delay of 30 seconds or less. `cluster-health.py` exits 3 with
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

Optional failover drill, with operator approval: stop ClickHouse on `nano-3`
(`docker stop` its clickhouse container), re-run the smoke test, then start it
again. Show that `cluster-health.py` returns to `PASS` and the replica delay
recovers.

## Licence

`smoke-test.py` prints `state`, `valid`, `expires` and the entitlement
(offering, capacity). Report them as they are:

- `valid=True`, `mode=hosted` (online licence) **and** an entitlement or
  expiry: done.
- `valid=True` with no entitlement, expiry or licence ID (the smoke test says
  `NO LICENCE BOUND`): there is no licence. The API may say "active" because
  no licence URL is configured. Report it as unlicensed, never as licensed.
- Not valid with enrollment applied: check outbound HTTPS to `LICENSE_URL`,
  `docker logs` of `nano-api` and `nano-jobs` for licence lines, and
  [known-issues.md](known-issues.md). Never edit licence tables or fabricate
  licence state.
- No enrollment yet: report "running unlicensed; apply the enrollment values
  before production use". Do not promise that the enterprise features are
  locked or unlocked. That depends on the release (see
  [known-issues.md](known-issues.md)).

The app.nano.rs deployment page should also show the install's licence
check-in within a few minutes.

## Report format

| Check | Host | Result | Evidence |
|---|---|---|---|
| containers healthy | node-1 | PASS | 14/14 running (healthy) |
| health | app | PASS | GET /api/health 200 |
| login | app | PASS | admin@... 200 |
| licence | app | WARN | state=... valid=False (no enrollment yet) |
| ingest → search | app via node-2 | PASS | marker found after 12 s |
| keeper quorum | all | PASS | leader + 2 followers |
| ch replicas | all | PASS | 3/3 active, max delay 0 s |

Then hand over: the login URL, where the admin password is
(`~/.nano-admin-credentials` on the app host, which they should move into a
password manager and then delete), the ingest endpoint for senders, and the
next steps: issue per-source tokens in **Ingestion → Log Sources →
Credentials**, set up backups ([operate.md](operate.md)), and configure the
firewall.
