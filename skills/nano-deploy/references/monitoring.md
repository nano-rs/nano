# Monitor your Self-run install

Optional and off by default. Offer it once the install is verified. It adds
Prometheus, Grafana with five dashboards, and alert rules. It is metrics only:
if it stops, dashboards stop; ingest and search do not.

The full operator guide ships in the bundle at
`docs/administration/monitor-self-run.md` and on nano.rs
(https://nano.rs/docs/getting-started/monitor-self-run). Follow it; this page is
the agent's checklist.

## Decide

Ask the operator:

1. Do they already run Prometheus and Grafana? Then use "Your own Prometheus"
   in the guide: scrape table, job names, the `host` label, dashboards and
   rules from the bundle.
2. Otherwise, which shape:
   - **Single node:** add `monitoring` to `COMPOSE_PROFILES` in `.env`, rerun
     `./install.sh`.
   - **Role split:** one host gets the `monitoring` role. A small dedicated VM
     (2 vCPU, 4 GB, 50 GB), or an existing PostgreSQL/Keeper host. Only one,
     even on full HA. `plan.py --monitoring dedicated|colocate` places it.
   - **Helm:** `monitoring.serviceMonitor.enabled`, `monitoring.prometheusRule.enabled`
     and `monitoring.dashboards.enabled` with a stock kube-prometheus-stack.
3. Do they want nano's own health alerts as events in nano (self-ingest)? It
   needs a log source and an ingest token made in the UI first.

## Role split: steps and gates

1. **Gate:** the cluster is healthy (`cluster-health.py` PASS on every host).
2. Add the role to `inventory.yaml` (a new host entry, or `monitoring` in an
   existing host's `roles`). Do not change any other field. The durable
   identity does not change.
3. Rerun the first app host's role. It adds `NANO_SERVICE_TOKEN` and
   `NANO_GRAFANA_ADMIN_PASSWORD` to `.env` when missing. Copy `.env` and the
   inventory to every host.
4. Rerun every host's role (data roles first, as for any rerun). Each host
   starts node-exporter and publishes its exporters.
5. Regenerate the firewall with `plan.py --firewall-script` (the plan must
   include the monitoring host) and apply it on every host. Exporter ports are
   opened to the monitoring host only.
6. Install the monitoring host last: `--role monitoring` (or its full role
   list when co-located).
7. **Verify:** on the monitoring host,
   `curl -s localhost:9090/api/v1/targets | python3 -c 'import json,sys; t=json.load(sys.stdin)["data"]["activeTargets"]; print([x["scrapeUrl"] for x in t if x["health"]!="up"])'`
   prints `[]`. Then, from the management network (the firewall script opens
   3030 to `MGMT_CIDR` only), open Grafana (port 3030 on the monitoring host's
   address), sign in as `admin` with `NANO_GRAFANA_ADMIN_PASSWORD`, and check
   "nano Overview" shows every service up.

Report the targets and the dashboard check as a table, like any other verify
step. Never print the Grafana password or the service token in the report.

## Self-ingest

1. In the UI: create a log source, issue an ingest token for it.
2. Put `NANO_SELF_INGEST_TOKEN=<token>` in the shared `.env`, copy it to the
   monitoring host, rerun its role (single node: rerun `./install.sh`). The
   bundled Alertmanager then posts alert notifications to nano's ingest.
3. **Verify:** within six minutes, a search for `"NanoHeartbeat"` on that
   source returns events (the heartbeat is re-sent every 5 minutes).

## Common faults

| Symptom | Cause | Fix |
|---|---|---|
| Targets on one host DOWN, "connection refused" or timeout | Host firewall | Regenerate and apply the firewall script with the monitoring host in the plan |
| api/search/jobs targets DOWN with 401 | `.env` copies differ | Copy the first app host's `.env` again; rerun the app hosts and the monitoring host |
| Grafana does not start | `NANO_GRAFANA_ADMIN_PASSWORD` missing | Rerun the first app host's role, copy `.env` again |
| Single node: nano-jobs DOWN | jobs on loopback | The installer sets `NANO_JOBS_BIND_ADDR=0.0.0.0`; rerun it |
