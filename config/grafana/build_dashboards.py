#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build the shipped Grafana dashboards (NAN-5250).

    python3 -I config/grafana/build_dashboards.py          rewrite dashboards/*.json
    python3 -I config/grafana/build_dashboards.py --check  exit 1 if they drifted

The dashboards are generated so every panel follows the same rules: one
`datasource` variable (any Prometheus works: the provisioned one on Compose,
kube-prometheus-stack's on Helm), a multi-select `host` variable on every
dashboard, and the job names every install shape shares (nano-api,
nano-search, nano-jobs, nano-vector, clickhouse, keeper, node, haproxy,
patroni, etcd, valkey, valkey-sentinel). Grafana 11 or later.

Edit this file, not the JSON. To keep a dashboard you changed in Grafana,
save it under a new name there: provisioned dashboards are read-only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "dashboards"
DS = {"type": "prometheus", "uid": "${datasource}"}
H = 'host=~"$host"'
# Vector sources that carry real ingest: not Vector's own internal_* sources,
# and not demo_logs, which on every install is only nano's synthetic reload
# markers (nano_activation_<id>, __nano_ack_*/__nano_failed_*), 1 event/s each
# into a blackhole (NAN-5407). Same filter as the NanoIngestStalled rule.
REAL_SOURCES = 'component_kind="source", component_type!~"internal_.*|demo_logs"'


class Board:
    def __init__(self, uid: str, title: str, description: str, tags: list[str]):
        self.uid, self.title, self.description, self.tags = uid, title, description, tags
        self.panels: list[dict] = []
        self.x = self.y = 0
        self.row_h = 0

    def _place(self, w: int, h: int) -> dict:
        if self.x + w > 24:
            self.x, self.y = 0, self.y + self.row_h
            self.row_h = 0
        pos = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.x += w
        self.row_h = max(self.row_h, h)
        return pos

    def row(self, title: str) -> None:
        if self.x:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0
        self.panels.append({"type": "row", "title": title, "collapsed": False, "panels": [],
                            "gridPos": {"x": 0, "y": self.y, "w": 24, "h": 1}})
        self.y += 1

    def _panel(self, kind: str, title: str, targets: list[tuple[str, str]], w: int, h: int,
               unit: str, description: str, extra: dict | None = None) -> None:
        panel = {
            "type": kind,
            "title": title,
            "description": description,
            "datasource": DS,
            "gridPos": self._place(w, h),
            "targets": [
                {"refId": chr(65 + i), "datasource": DS, "expr": expr, "legendFormat": legend,
                 **({"instant": True, "format": "table"} if kind == "table" else {})}
                for i, (expr, legend) in enumerate(targets)
            ],
            "fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
            "options": {},
        }
        panel.update(extra or {})
        self.panels.append(panel)

    def ts(self, title, targets, unit="short", w=12, h=8, description="", stack=False):
        extra = {"options": {"legend": {"displayMode": "table", "placement": "bottom", "calcs": ["lastNotNull", "max"]},
                             "tooltip": {"mode": "multi", "sort": "desc"}}}
        if stack:
            extra["fieldConfig"] = {"defaults": {"unit": unit, "custom": {"stacking": {"mode": "normal"}, "fillOpacity": 20}},
                                    "overrides": []}
        self._panel("timeseries", title, targets, w, h, unit, description, extra)

    def stat(self, title, expr, unit="short", w=4, h=4, description="", thresholds=None, mappings=None, legend=""):
        steps = thresholds or [{"color": "green", "value": None}]
        extra = {
            "fieldConfig": {"defaults": {"unit": unit, "thresholds": {"mode": "absolute", "steps": steps},
                                         "mappings": mappings or []}, "overrides": []},
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                        "colorMode": "background", "graphMode": "none", "textMode": "auto"},
        }
        self._panel("stat", title, [(expr, legend)], w, h, unit, description, extra)

    def table(self, title, targets, w=12, h=8, description="", unit="short"):
        extra = {"transformations": [{"id": "merge", "options": {}},
                                     {"id": "organize", "options": {"excludeByName": {"Time": True}}}]}
        self._panel("table", title, targets, w, h, unit, description, extra)

    def json(self) -> dict:
        return {
            "uid": self.uid,
            "title": self.title,
            "description": self.description,
            "tags": ["nano", *self.tags],
            "editable": False,
            "graphTooltip": 1,
            "refresh": "30s",
            "schemaVersion": 39,
            "time": {"from": "now-6h", "to": "now"},
            "timezone": "",
            "version": 1,
            "links": [{"type": "dashboards", "tags": ["nano"], "asDropdown": True, "title": "nano dashboards"}],
            "templating": {"list": [
                {"name": "datasource", "label": "Prometheus", "type": "datasource", "query": "prometheus",
                 "current": {}, "hide": 0, "refresh": 1},
                {"name": "host", "label": "Host", "type": "query", "datasource": DS,
                 "query": {"query": "label_values(up, host)", "refId": "host"},
                 "definition": "label_values(up, host)", "refresh": 2, "multi": True, "includeAll": True,
                 "allValue": ".*", "current": {"text": "All", "value": "$__all"}, "sort": 1, "hide": 0},
            ]},
            "annotations": {"list": []},
            "panels": self.panels,
        }


UP_MAP = [{"type": "value", "options": {"0": {"text": "DOWN", "color": "red"}, "1": {"text": "UP", "color": "green"}}}]
RED_BELOW = lambda n: [{"color": "red", "value": None}, {"color": "green", "value": n}]  # noqa: E731
RED_ABOVE = lambda n: [{"color": "green", "value": None}, {"color": "red", "value": n}]  # noqa: E731


def up_count(job: str) -> str:
    return f'count(up{{job="{job}", {H}}} == 1) or vector(0)'


def overview() -> Board:
    b = Board("nanosiem-overview", "nano Overview",
              "Is nano up, ingesting and searching? Start here.", ["overview"])
    b.row("Services")
    for title, job in (("API up", "nano-api"), ("Search up", "nano-search"), ("Jobs up", "nano-jobs"),
                       ("Vector up", "nano-vector"), ("ClickHouse up", "clickhouse")):
        b.stat(title, up_count(job), thresholds=RED_BELOW(1),
               description=f"{job} targets answering scrapes.")
    b.stat("Alerts firing", 'count(ALERTS{alertstate="firing", alertname=~"Nano.*", alertname!="NanoHeartbeat"}) or vector(0)',
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
           description="nano alert rules firing now (Prometheus ALERTS).")
    b.row("Ingest")
    b.ts("Events written to ClickHouse", [
        (f'sum by (host) (rate(nanosiem_vector_component_sent_events_total{{job="nano-vector", component_type="clickhouse", {H}}}[$__rate_interval]))', "{{host}}")],
        unit="eps", description="Events per second Vector's ClickHouse sinks sent, per ingest host.")
    b.ts("Events received by Vector", [
        (f'sum by (host) (rate(nanosiem_vector_component_received_events_total{{job="nano-vector", {REAL_SOURCES}, {H}}}[$__rate_interval]))', "{{host}}")],
        unit="eps", description="Events per second arriving at Vector's sources (internal sources and nano's demo_logs reload markers excluded).")
    b.row("API")
    b.ts("API requests", [
        (f'sum by (status) (rate(axum_http_requests_total{{job="nano-api", {H}}}[$__rate_interval]))', "{{status}}")],
        unit="reqps", stack=True)
    b.ts("API latency", [
        (f'histogram_quantile(0.5, sum by (le) (rate(axum_http_requests_duration_seconds_bucket{{job="nano-api", {H}}}[$__rate_interval])))', "p50"),
        (f'histogram_quantile(0.95, sum by (le) (rate(axum_http_requests_duration_seconds_bucket{{job="nano-api", {H}}}[$__rate_interval])))', "p95"),
        (f'histogram_quantile(0.99, sum by (le) (rate(axum_http_requests_duration_seconds_bucket{{job="nano-api", {H}}}[$__rate_interval])))', "p99")],
        unit="s")
    b.row("Health")
    b.table("Firing alerts", [('ALERTS{alertstate="firing", alertname!="NanoHeartbeat"}', "")], w=12,
            description="Every alert firing now, with its labels.")
    b.table("Scrape targets down", [(f'up{{{H}}} == 0', "")], w=12,
            description="Targets Prometheus cannot scrape. Empty is good.")
    return b


def api() -> Board:
    b = Board("nanosiem-api", "nano API, Search and Jobs",
              "Request rates and latency of api and search, search admission, the jobs leader and detection schedule lag.",
              ["api", "search", "jobs"])
    b.row("API")
    b.ts("Requests per host", [
        (f'sum by (host) (rate(axum_http_requests_total{{job="nano-api", {H}}}[$__rate_interval]))', "{{host}}")], unit="reqps")
    b.ts("5xx ratio", [
        (f'sum by (host) (rate(axum_http_requests_total{{job="nano-api", status=~"5..", {H}}}[$__rate_interval])) '
         f'/ sum by (host) (rate(axum_http_requests_total{{job="nano-api", {H}}}[$__rate_interval]))', "{{host}}")],
        unit="percentunit")
    b.ts("p95 latency by endpoint (top 10)", [
        (f'topk(10, histogram_quantile(0.95, sum by (le, endpoint) (rate(axum_http_requests_duration_seconds_bucket{{job="nano-api", {H}}}[$__rate_interval]))))', "{{endpoint}}")],
        unit="s")
    b.ts("Requests by endpoint (top 10)", [
        (f'topk(10, sum by (endpoint) (rate(axum_http_requests_total{{job="nano-api", {H}}}[$__rate_interval])))', "{{endpoint}}")],
        unit="reqps")
    b.ts("Requests in flight", [
        (f'sum by (host, job) (axum_http_requests_pending{{job=~"nano-api|nano-search", {H}}})', "{{job}} {{host}}")])
    b.ts("Audit outbox", [
        (f'sum(rate(nanosiem_audit_outbox_deferred_total{{{H}}}[$__rate_interval]))', "deferred"),
        (f'sum(rate(nanosiem_audit_outbox_delivered_total{{{H}}}[$__rate_interval]))', "delivered"),
        (f'sum(rate(nanosiem_audit_emit_failures_total{{{H}}}[$__rate_interval]))', "emit failures")],
        unit="ops", description="Security audit events queued, delivered and failed. Failures should stay at zero.")
    b.row("Search")
    b.ts("Search query time", [
        (f'max by (type, quantile) (nanosiem_search_query_duration_seconds{{job="nano-search", success="true", {H}}})', "{{type}} p{{quantile}}")],
        unit="s")
    b.ts("Search admission", [
        (f'sum(nanosiem_search_active_queries{{job="nano-search", {H}}})', "running"),
        (f'sum(nanosiem_search_queue_depth{{job="nano-search", {H}}})', "queued")])
    b.ts("Admitted searches by priority", [
        (f'sum by (priority) (rate(nanosiem_search_jobs_admitted_total{{job="nano-search", {H}}}[$__rate_interval]))', "{{priority}}")],
        unit="ops", stack=True)
    b.ts("Rejected searches by reason", [
        (f'sum by (reason) (rate(nanosiem_search_jobs_rejected_total{{job="nano-search", {H}}}[$__rate_interval]))', "{{reason}}")],
        unit="ops", stack=True)
    b.ts("Search queue wait", [
        (f'histogram_quantile(0.95, sum by (le) (rate(nanosiem_search_queue_wait_seconds_bucket{{job="nano-search", {H}}}[$__rate_interval])))', "p95"),
        (f'histogram_quantile(0.5, sum by (le) (rate(nanosiem_search_queue_wait_seconds_bucket{{job="nano-search", {H}}}[$__rate_interval])))', "p50")],
        unit="s")
    b.ts("Search requests per host", [
        (f'sum by (host) (rate(axum_http_requests_total{{job="nano-search", {H}}}[$__rate_interval]))', "{{host}}")], unit="reqps")
    b.row("Jobs and detections")
    b.stat("Jobs leaders", 'sum(nano_jobs_leader{job="nano-jobs"}) or vector(0)', w=4,
           thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}, {"color": "red", "value": 2}],
           description="Exactly one jobs instance holds the scheduler lease. 0 or 2 is an incident.")
    b.table("Jobs leader", [('nano_jobs_leader{job="nano-jobs"} == 1', "")], w=8,
            description="The host whose nano-jobs holds the lease now.")
    b.stat("Rules behind schedule", f'max(nanosiem_detection_rules_behind_schedule{{{H}}}) or vector(0)', w=4,
           thresholds=RED_ABOVE(1))
    b.stat("Schedule degraded", f'max(nanosiem_detection_schedule_degraded{{{H}}}) or vector(0)', w=4,
           thresholds=RED_ABOVE(1), mappings=[{"type": "value", "options": {"0": {"text": "OK"}, "1": {"text": "DEGRADED"}}}])
    b.stat("Panics (1h)", f'sum(increase(nano_panics_total{{{H}}}[1h])) or vector(0)', w=4, thresholds=RED_ABOVE(1))
    b.ts("Detection schedule lag", [
        (f'max(nanosiem_detection_schedule_lag_p95_seconds{{{H}}})', "p95"),
        (f'max(nanosiem_detection_schedule_lag_max_seconds{{{H}}})', "max")], unit="s")
    b.ts("Jobs leader over time", [('nano_jobs_leader{job="nano-jobs"}', "{{host}}")], stack=True,
         description="A handover shows as the 1 moving from one host to another.")
    return b


def clickhouse_ingest() -> Board:
    b = Board("nanosiem-databases", "nano ClickHouse and Ingest",
              "ClickHouse inserts, queries, parts, merges and replication; Vector throughput, buffers, errors and drops.",
              ["clickhouse", "ingest"])
    j = f'job="clickhouse", {H}'
    b.row("ClickHouse")
    b.stat("Replicas up", up_count("clickhouse"), thresholds=RED_BELOW(1))
    b.stat("Read-only tables", f'sum(ClickHouseMetrics_ReadonlyReplica{{{j}}}) or vector(0)', thresholds=RED_ABOVE(1))
    b.stat("Max replication delay", f'max(ClickHouseAsyncMetrics_ReplicasMaxAbsoluteDelay{{{j}}}) or vector(0)', unit="s",
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 10}, {"color": "red", "value": 30}])
    b.stat("Max parts per partition", f'max(ClickHouseAsyncMetrics_MaxPartCountForPartition{{{j}}})',
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 300}, {"color": "red", "value": 1000}])
    b.stat("Keeper sessions", f'sum(ClickHouseMetrics_ZooKeeperSession{{{j}}}) or vector(0)',
           description="ClickHouse servers connected to Keeper.")
    b.stat("Distributed files waiting", f'sum(ClickHouseMetrics_DistributedFilesToInsert{{{j}}}) or vector(0)',
           thresholds=RED_ABOVE(1000))
    b.ts("Rows inserted", [(f'sum by (host) (rate(ClickHouseProfileEvents_InsertedRows{{{j}}}[$__rate_interval]))', "{{host}}")],
         unit="rowsps")
    b.ts("Queries", [(f'sum by (host) (rate(ClickHouseProfileEvents_SelectQuery{{{j}}}[$__rate_interval]))', "select {{host}}"),
                     (f'sum by (host) (rate(ClickHouseProfileEvents_InsertQuery{{{j}}}[$__rate_interval]))', "insert {{host}}"),
                     (f'sum by (host) (rate(ClickHouseProfileEvents_FailedQuery{{{j}}}[$__rate_interval]))', "failed {{host}}")],
         unit="qps")
    b.ts("Merges running and parts", [(f'sum by (host) (ClickHouseMetrics_Merge{{{j}}})', "merges {{host}}"),
                                      (f'max by (host) (ClickHouseAsyncMetrics_MaxPartCountForPartition{{{j}}})', "max parts {{host}}")])
    b.ts("Replication queue and delay", [(f'max by (host) (ClickHouseAsyncMetrics_ReplicasMaxQueueSize{{{j}}})', "queue {{host}}"),
                                         (f'max by (host) (ClickHouseAsyncMetrics_ReplicasMaxAbsoluteDelay{{{j}}})', "delay s {{host}}")])
    b.ts("Memory", [(f'max by (host) (ClickHouseMetrics_MemoryTracking{{{j}}})', "{{host}}")], unit="bytes")
    b.ts("Data disk free", [(f'max by (host) (ClickHouseAsyncMetrics_FilesystemMainPathAvailableBytes{{{j}}})', "{{host}}")],
         unit="bytes")
    v = f'job="nano-vector", {H}'
    b.row("Vector")
    b.ts("Received by source", [(f'sum by (component_id) (rate(nanosiem_vector_component_received_events_total{{{v}, {REAL_SOURCES}}}[$__rate_interval]))', "{{component_id}}")],
         unit="eps")
    b.ts("Sent by sink", [(f'sum by (component_id) (rate(nanosiem_vector_component_sent_events_total{{{v}, component_kind="sink", component_type!="blackhole"}}[$__rate_interval]))', "{{component_id}}")],
         unit="eps", description="Blackhole sinks (discarded data and nano's reload markers) are excluded.")
    b.ts("Buffer fill", [(f'max by (host, component_id) (nanosiem_vector_buffer_size_bytes{{{v}}}) / max by (host, component_id) (nanosiem_vector_buffer_max_size_bytes{{{v}}} > 0)', "{{host}} {{component_id}}")],
         unit="percentunit", description="Disk buffers fill when ClickHouse cannot keep up.")
    b.ts("Buffered events", [(f'sum by (host, component_id) (nanosiem_vector_buffer_size_events{{{v}}})', "{{host}} {{component_id}}")])
    b.ts("Errors", [(f'sum by (host, component_id) (rate(nanosiem_vector_component_errors_total{{{v}}}[$__rate_interval]))', "{{host}} {{component_id}}")],
         unit="ops")
    b.ts("Dropped events", [(f'sum by (host, component_id, intentional) (rate(nanosiem_vector_component_discarded_events_total{{{v}}}[$__rate_interval]))', "{{host}} {{component_id}} intentional={{intentional}}")],
         unit="eps", description="intentional=false means events were lost.")
    return b


def hosts() -> Board:
    b = Board("nanosiem-host", "nano Hosts", "CPU, memory, disk and network of every nano host (node-exporter).", ["hosts"])
    n = f'job="node", {H}'
    fs = 'fstype!~"tmpfs|overlay|squashfs|ramfs|nsfs"'
    b.row("Now")
    b.table("Hosts", [
        (f'max by (host, nano_role) (up{{{n}}})', "up"),
        (f'1 - avg by (host, nano_role) (rate(node_cpu_seconds_total{{{n}, mode="idle"}}[5m]))', "cpu"),
        (f'max by (host, nano_role) (1 - node_memory_MemAvailable_bytes{{{n}}} / node_memory_MemTotal_bytes{{{n}}})', "memory"),
        (f'min by (host, nano_role) (node_filesystem_avail_bytes{{{n}, {fs}}} / node_filesystem_size_bytes{{{n}, {fs}}})', "lowest disk free"),
    ], w=24, h=8, description="One row per host. Roles come from the inventory.")
    b.row("Over time")
    b.ts("CPU busy", [(f'1 - avg by (host) (rate(node_cpu_seconds_total{{{n}, mode="idle"}}[$__rate_interval]))', "{{host}}")],
         unit="percentunit")
    b.ts("Memory used", [(f'1 - node_memory_MemAvailable_bytes{{{n}}} / node_memory_MemTotal_bytes{{{n}}}', "{{host}}")],
         unit="percentunit")
    b.ts("Disk free", [(f'node_filesystem_avail_bytes{{{n}, {fs}}} / node_filesystem_size_bytes{{{n}, {fs}}}', "{{host}} {{mountpoint}}")],
         unit="percentunit", description="The NanoDiskPressure alert fires below 15%, NanoDiskCritical below 8%.")
    b.ts("Disk I/O", [(f'sum by (host) (rate(node_disk_read_bytes_total{{{n}}}[$__rate_interval]))', "read {{host}}"),
                      (f'sum by (host) (rate(node_disk_written_bytes_total{{{n}}}[$__rate_interval]))', "write {{host}}")],
         unit="Bps")
    b.ts("Network", [(f'sum by (host) (rate(node_network_receive_bytes_total{{{n}, device!~"lo|veth.*|docker.*|br-.*"}}[$__rate_interval]))', "in {{host}}"),
                     (f'sum by (host) (rate(node_network_transmit_bytes_total{{{n}, device!~"lo|veth.*|docker.*|br-.*"}}[$__rate_interval]))', "out {{host}}")],
         unit="Bps")
    b.ts("Load (1m) per CPU", [(f'node_load1{{{n}}} / on(host) group_left count by (host) (node_cpu_seconds_total{{{n}, mode="idle"}})', "{{host}}")])
    return b


def ha() -> Board:
    b = Board("nanosiem-ha", "nano HA",
              "The highly available pieces: PostgreSQL (Patroni) and etcd, Valkey and Sentinel, ClickHouse replicas "
              "and Keeper, the host-local routers, and the jobs leader. Panels stay empty on a shape without that piece.",
              ["ha"])
    b.row("PostgreSQL")
    b.stat("Primaries", 'sum(patroni_primary{job="patroni"})',
           thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}, {"color": "red", "value": 2}],
           description="Exactly one. 0 = writes refused; 2 = split brain.")
    b.stat("Members running", 'sum(patroni_postgres_running{job="patroni"})', thresholds=RED_BELOW(2))
    b.stat("Sync standbys", 'sum(patroni_sync_standby{job="patroni"}) or vector(0)',
           description="With synchronous_mode on (the default), one replica confirms every commit.")
    b.stat("etcd members with a leader", 'sum(etcd_server_has_leader{job="etcd"})', thresholds=RED_BELOW(2))
    b.stat("etcd leader changes (1h)", 'sum(increase(etcd_server_leader_changes_seen_total{job="etcd"}[1h])) or vector(0)',
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 3}])
    b.stat("Failsafe active", 'max(patroni_failsafe_mode_is_active{job="patroni"}) or vector(0)',
           thresholds=RED_ABOVE(1), description="The primary kept writing through an etcd outage.")
    b.ts("Role per member", [('patroni_primary{job="patroni"}', "{{host}}")], stack=True,
         description="1 = this member is the primary. A move is a failover or switchover.")
    b.ts("Replication lag", [('scalar(max(patroni_xlog_location{job="patroni"})) - (patroni_xlog_replayed_location{job="patroni"} and on(instance) patroni_replica{job="patroni"} == 1)', "{{host}}")],
         unit="bytes", description="WAL bytes each replica is behind the primary. Alert: 16 MiB.")
    b.ts("etcd leader", [('etcd_server_is_leader{job="etcd"}', "{{host}}")], stack=True)
    b.ts("etcd WAL fsync p99", [('histogram_quantile(0.99, sum by (le, host) (rate(etcd_disk_wal_fsync_duration_seconds_bucket{job="etcd"}[$__rate_interval])))', "{{host}}")],
         unit="s", description="Above 10 ms means a slow disk under etcd.")
    b.row("Valkey")
    b.stat("Masters", 'count(redis_instance_info{job="valkey", role="master"}) or vector(0)',
           thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}, {"color": "red", "value": 2}])
    b.stat("Members up", 'sum(redis_up{job="valkey"}) or vector(0)', thresholds=RED_BELOW(2))
    b.stat("Healthy Sentinels (min)", 'min(redis_sentinel_master_ok_sentinels{job="valkey-sentinel"})', thresholds=RED_BELOW(2),
           description="Each Sentinel's count of healthy Sentinels; failover needs 2.")
    b.stat("Replicas of the master", 'max(redis_connected_slaves{job="valkey"} and on(instance) redis_instance_info{job="valkey", role="master"})',
           thresholds=RED_BELOW(1))
    b.ts("Role per member", [('redis_instance_info{job="valkey", role="master"}', "{{host}}")], stack=True)
    b.ts("Memory used", [('redis_memory_used_bytes{job="valkey"}', "{{host}}")], unit="bytes")
    b.row("ClickHouse and Keeper")
    b.ts("Read-only replicated tables", [('ClickHouseMetrics_ReadonlyReplica{job="clickhouse"}', "{{host}} s{{shard}} r{{replica}}")])
    b.ts("Replication delay", [('ClickHouseAsyncMetrics_ReplicasMaxAbsoluteDelay{job="clickhouse"}', "{{host}}")], unit="s")
    b.ts("Replication queue", [('ClickHouseAsyncMetrics_ReplicasMaxQueueSize{job="clickhouse"}', "{{host}}")])
    b.ts("Keeper leader", [('ClickHouseAsyncMetrics_KeeperIsLeader{job="keeper"}', "{{host}}")], stack=True,
         description="Exactly one Keeper leads.")
    b.row("Routers (HAProxy on app and ingest hosts)")
    b.table("Healthy backends per router", [
        ('haproxy_backend_active_servers{job="haproxy", proxy=~"postgres_primary|clickhouse_all|ingest_http|ingest_hec|app_api"}', "")],
        w=12, description="postgres_primary must be 1 on every app host; the others count every healthy peer.")
    b.table("Servers DOWN", [('haproxy_server_status{job="haproxy", state="DOWN"} == 1', "")], w=12,
            description="Every peer a router has marked down. Empty is good.")
    b.row("Jobs leader and ingest")
    b.ts("Jobs leader", [('nano_jobs_leader{job="nano-jobs"}', "{{host}}")], stack=True)
    b.ts("Events written to ClickHouse", [
        ('sum by (host) (rate(nanosiem_vector_component_sent_events_total{job="nano-vector", component_type="clickhouse"}[$__rate_interval]))', "{{host}}")],
        unit="eps")
    return b


BOARDS = {
    "nanosiem-overview.json": overview,
    "nanosiem-api.json": api,
    "nanosiem-databases.json": clickhouse_ingest,
    "nanosiem-host.json": hosts,
    "nanosiem-ha.json": ha,
}


def render() -> dict[str, str]:
    out = {}
    for name, build in BOARDS.items():
        board = build().json()
        for index, panel in enumerate(board["panels"], 1):
            panel["id"] = index
        out[name] = json.dumps(board, indent=2) + "\n"
    return out


def main() -> int:
    check = "--check" in sys.argv[1:]
    rendered = render()
    drift = []
    for name, text in rendered.items():
        path = OUT / name
        if check:
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                drift.append(name)
        else:
            path.write_text(text, encoding="utf-8")
    stale = sorted(p.name for p in OUT.glob("*.json") if p.name not in rendered)
    if check and (drift or stale):
        print(f"dashboards drifted: {drift + stale}; run python3 -I config/grafana/build_dashboards.py", file=sys.stderr)
        return 1
    if stale and not check:
        for name in stale:
            (OUT / name).unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
