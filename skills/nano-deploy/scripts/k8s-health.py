#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only health for a nano Helm install (the Kubernetes counterpart of
cluster-health.py, which reads Docker hosts over SSH).

Runs on the operator's workstation with their kubectl context (standard library
only, no secrets printed):

  python3 -I scripts/k8s-health.py --namespace nano [--release nano] [--context CTX]

Checks:
  pods      every pod Running and Ready (completed Jobs excluded); names the
            reason for CrashLoopBackOff, ImagePullBackOff / ErrImagePull (an
            expired registry credential shows up here), Init:Error and Pending
            (with the scheduler's message: e.g. a volume bound to another zone).
  workloads every Deployment / StatefulSet has all replicas available.
  vector    every Vector pod Ready on an installed config generation
            (helm test does not catch a Vector that never starts).
  ch        through `kubectl exec` into a ClickHouse pod, as nanosiem_admin with
            the password from the pod's own environment (never read out):
            every configured replica of cluster 'default' answers (remote_servers
            rows only: the operator's Replicated `default` database lists the
            hosts a second time), no read-only replicated tables, replication
            delay <= 30 s, Keeper session alive, no distributed DDL older than
            10 min still pending (an entry older than one its host already
            finished is stale, not stuck: it only warns). NAN-5390: no
            refused logins for nano's users (codes 192-195, 516; latest within
            10 min), which catches a wrong clickhouse.allowedNetworks because
            pods log in from the pod network; and a zero-row INSERT as
            nanosiem_vector succeeds. That probe runs over loopback inside the
            ClickHouse pod (always allowed), so it checks Vector's password and
            INSERT grant, NOT its networks; `helm test` writes from the pod
            network.
  registry  the registry credential refresh CronJob (when present) succeeded
            within the last hour.
Exit 0 = healthy, 1 = a check failed, 2 = usage error / kubectl unavailable.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys

FAILS: list[str] = []


def row(check: str, ok: bool | None, detail: str) -> None:
    status = "PASS" if ok else ("WARN" if ok is None else "FAIL")
    if ok is False:
        FAILS.append(check)
    print(f"{status:<4} {check:<10} {detail}", flush=True)


class Kube:
    def __init__(self, namespace: str, context: str | None):
        self.base = ["kubectl"] + (["--context", context] if context else []) + ["-n", namespace]

    def json(self, *args: str) -> dict:
        out = subprocess.run(self.base + list(args) + ["-o", "json"], capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            raise RuntimeError(out.stderr.strip()[:300])
        return json.loads(out.stdout)

    def exec_sh(self, pod: str, container: str | None, script: str) -> tuple[int, str]:
        cmd = self.base + ["exec", pod] + (["-c", container] if container else []) + ["--", "sh", "-c", script]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        return out.returncode, (out.stdout if out.returncode == 0 else out.stderr).strip()


def pod_problem(pod: dict) -> str | None:
    """None when the pod is healthy (or a finished Job pod); otherwise a reason."""
    status = pod.get("status", {})
    phase = status.get("phase")
    if phase == "Succeeded":
        return None
    for cs in status.get("initContainerStatuses", []) + status.get("containerStatuses", []):
        waiting = (cs.get("state") or {}).get("waiting") or {}
        reason = waiting.get("reason")
        if reason in {"CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError", "InvalidImageName"}:
            hint = " (registry credential expired? see registryCredentialRefresh)" if "Image" in reason else ""
            return f"{cs['name']}: {reason}{hint}"
        terminated = (cs.get("state") or {}).get("terminated") or {}
        if cs in status.get("initContainerStatuses", []) and terminated.get("exitCode", 0) != 0:
            return f"init {cs['name']}: exit {terminated.get('exitCode')}"
    if phase == "Pending":
        for cond in status.get("conditions", []):
            if cond.get("type") == "PodScheduled" and cond.get("status") == "False":
                return f"Pending: {cond.get('message', cond.get('reason', ''))[:200]}"
        running_init = [cs["name"] for cs in status.get("initContainerStatuses", [])
                        if not ((cs.get("state") or {}).get("terminated") or {}).get("exitCode") == 0]
        return f"initializing ({running_init[0]})" if running_init else "Pending"
    if phase == "Failed":
        return f"Failed: {status.get('reason', '')}"
    ready = next((c for c in status.get("conditions", []) if c.get("type") == "Ready"), {})
    if ready.get("status") != "True":
        return "not Ready"
    return None


def check_pods(kube: Kube, release: str) -> list[dict]:
    pods = kube.json("get", "pods", "-l", f"app.kubernetes.io/instance={release}").get("items", [])
    ch = kube.json("get", "pods", "-l", "app.kubernetes.io/name=clickhouse-server").get("items", [])
    names = {p["metadata"]["name"] for p in pods}
    pods += [p for p in ch if p["metadata"]["name"] not in names]
    def job_pod(p: dict) -> bool:
        return any(o.get("kind") == "Job" for o in p["metadata"].get("ownerReferences", []))
    bad = [(p["metadata"]["name"], pod_problem(p)) for p in pods if not job_pod(p)]
    bad = [(n, r) for n, r in bad if r]
    row("pods", not bad and bool(pods), f"{len(pods)} pods" + ("" if not bad else "; " + "; ".join(f"{n}: {r}" for n, r in bad)))
    # Job pods (migrations, hooks, CronJob runs) linger after a failed attempt
    # even when a later revision succeeded: report, don't fail. A failed
    # first-install migration still fails the app pods above (Init:Error).
    jobs = [(p["metadata"]["name"], pod_problem(p)) for p in pods if job_pod(p)]
    jobs = [(n, r) for n, r in jobs if r]
    if jobs:
        row("jobs", None, "; ".join(f"{n}: {r}" for n, r in jobs) + " (kubectl -n <ns> logs <pod> --all-containers)")
    return pods


def check_workloads(kube: Kube, release: str) -> None:
    short = []
    for kind in ("deployments", "statefulsets"):
        for w in kube.json("get", kind).get("items", []):
            want = w.get("spec", {}).get("replicas", 1)
            have = w.get("status", {}).get("availableReplicas" if kind == "deployments" else "readyReplicas", 0) or 0
            if have < want:
                short.append(f"{w['metadata']['name']} {have}/{want}")
    row("workloads", not short, "all replicas available" if not short else ", ".join(short))


def check_vector(pods: list[dict]) -> None:
    vec = [p for p in pods if p["metadata"].get("labels", {}).get("app.kubernetes.io/component") == "vector"]
    if not vec:
        row("vector", None, "no Vector pods found")
        return
    unready = [p["metadata"]["name"] for p in vec if pod_problem(p)]
    row("vector", not unready, f"{len(vec) - len(unready)}/{len(vec)} on an installed config generation"
        + ("" if not unready else f"; not ready: {', '.join(unready)} (kubectl logs <pod> -c config-consumer)"))


# Distributed DDL older than 10 min that a host has not finished. A host runs its
# queue in order, so an entry older than one that host already Finished can't be
# blocking it: it is a stale leftover (seen on AKS: a replica restarted while an
# ON CLUSTER statement was issued and left it `Inactive` for good, with nothing
# diverged). Stuck entries fail; stale ones only warn. Two TSV columns.
DDL_SQL = ("SELECT countIf(f.last_finished = '' OR q.entry > f.last_finished), "
           "countIf(f.last_finished != '' AND q.entry < f.last_finished) "
           "FROM system.distributed_ddl_queue AS q LEFT JOIN "
           "(SELECT host, port, max(entry) AS last_finished FROM system.distributed_ddl_queue "
           "WHERE status = 'Finished' GROUP BY host, port) AS f ON q.host = f.host AND q.port = f.port "
           "WHERE q.status NOT IN ('Finished', 'Removing') AND q.query_create_time < now() - 600")


CH_SQL = {
    "replicas": "SELECT (SELECT count() FROM system.clusters WHERE cluster='default' AND database_replica_name='') AS configured, "
                "(SELECT count() FROM clusterAllReplicas('default', system.one) SETTINGS skip_unavailable_shards=1) AS answering",
    "readonly": "SELECT count() FROM clusterAllReplicas('default', system.replicas) WHERE is_readonly OR is_session_expired "
                "SETTINGS skip_unavailable_shards=1",
    "delay": "SELECT max(absolute_delay) FROM clusterAllReplicas('default', system.replicas) SETTINGS skip_unavailable_shards=1",
    "keeper": "SELECT count() FROM system.zookeeper_connection WHERE NOT is_expired",
    "ddl": DDL_SQL,
    # NAN-5390: refused logins (UNKNOWN_USER, WRONG_PASSWORD, REQUIRED_PASSWORD,
    # IP_ADDRESS_NOT_ALLOWED, AUTHENTICATION_FAILED) whose latest message, within
    # the last 10 minutes on this replica, names a nano user. system.errors
    # counts are cumulative since server start; the sum is reported as such.
    # Two TSV columns: refusals, last message.
    "refusals": "SELECT sum(value), any(last_error_message) FROM system.errors "
                "WHERE code IN (192, 193, 194, 195, 516) AND remote = 0 "
                "AND last_error_time > now() - 600 "
                "AND match(last_error_message, '^nanosiem[a-z_]*: ')",
}

# NAN-5390: Vector's write identity, checked with a zero-row INSERT over HTTP
# from inside the ClickHouse pod (clickhouse-client refuses an empty INSERT
# client-side, before any grant check). Stores nothing; logs in, checks the
# INSERT grant. ocsf_logs_raw on OCSF installs, logs_ingest on UDM. ClickHouse's
# answer goes to stderr, which exec_sh returns on failure.
WRITE_PROBE = (
    'for t in ocsf_logs_raw logs_ingest; do '
    'wget -qO- --content-on-error --post-data= '
    '--header "X-ClickHouse-User: nanosiem_vector" --header "X-ClickHouse-Key: $CLICKHOUSE_VECTOR_PASSWORD" '
    '"http://127.0.0.1:8123/?query=INSERT%20INTO%20nanosiem.$t%20FORMAT%20JSONEachRow" 1>&2 '
    '&& { echo "ok $t"; exit 0; }; done; exit 1'
)


def check_clickhouse(kube: Kube, pods: list[dict]) -> None:
    ch = [p for p in pods if p["metadata"].get("labels", {}).get("app.kubernetes.io/name") == "clickhouse-server"
          and not pod_problem(p)]
    if not ch:
        row("ch", False, "no Ready ClickHouse pod to query")
        return
    pod = ch[0]["metadata"]["name"]
    results = {}
    for key, sql in CH_SQL.items():
        # The password is expanded inside the pod; it never reaches this process.
        rc, out = kube.exec_sh(pod, None, f'clickhouse-client --user nanosiem_admin --password "$CLICKHOUSE_ADMIN_PASSWORD" '
                                          f'--format TSV -q "{sql}"')
        if rc != 0:
            row("ch", False, f"{key} query failed on {pod}: {out[:200]}")
            return
        results[key] = out.split() if key != "refusals" else out.split("\t", 1)
    configured, answering = (int(x) for x in results["replicas"][:2])
    row("ch", configured > 0 and answering == configured, f"replicas answering {answering}/{configured} (cluster 'default')")
    row("ch", int(results["readonly"][0]) == 0, f"{results['readonly'][0]} read-only / expired-session replicated tables")
    delay = int(float(results["delay"][0] or 0)) if results["delay"] else 0
    row("ch", delay <= 30, f"max replication delay {delay}s")
    row("ch", int(results["keeper"][0]) > 0, "Keeper session alive" if int(results["keeper"][0]) else "no live Keeper session")
    stuck, stale = (int(x) for x in (results["ddl"] + ["0", "0"])[:2])
    row("ch", stuck == 0, f"{stuck} distributed DDL entries pending > 10 min"
        + ("" if not stuck else " (SELECT entry, host, status, exception_text, query FROM system.distributed_ddl_queue "
                                "WHERE status != 'Finished'; see known-issues.md)"))
    if stale:
        row("ch", None, f"{stale} stale distributed DDL entries: never run on a host that has finished later ones; "
            "harmless, ClickHouse drops them after distributed_ddl.task_max_lifetime (7 days)")
    refused = int((results["refusals"] + ["0"])[0] or 0)
    last = (results["refusals"] + ["", ""])[1].strip()[:200]
    row("ch", refused == 0, "no refused logins for nano's ClickHouse users in the last 10 min" if not refused
        else f"refused logins for nano's ClickHouse users: {refused} since ClickHouse started, latest within "
             f"10 min (last: {last}); check clickhouse.allowedNetworks and the ClickHouse passwords")
    # The password is expanded inside the pod; it never reaches this process.
    rc, out = kube.exec_sh(pod, None, WRITE_PROBE)
    if rc == 127 or "not found" in out:
        row("ch", None, f"write probe skipped: no wget in {pod}")
    else:
        row("ch", rc == 0, f"nanosiem_vector can write ({out.split()[-1]}; password + grant, over loopback)" if rc == 0
            else f"nanosiem_vector cannot write: {out[:200]}")


def check_registry(kube: Kube, release_prefix: str) -> None:
    try:
        cj = kube.json("get", "cronjob", f"{release_prefix}-registry-cred-refresh")
    except RuntimeError:
        row("registry", None, "no registry credential refresh CronJob (mirror install, or chart < 2.0.10)")
        return
    last = cj.get("status", {}).get("lastSuccessfulTime")
    if not last:
        row("registry", None, "refresh CronJob has not succeeded yet "
            f"(kubectl -n <ns> create job --from=cronjob/{release_prefix}-registry-cred-refresh refresh-now)")
        return
    age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(last.replace("Z", "+00:00"))
    row("registry", age < dt.timedelta(hours=1), f"last credential refresh {int(age.total_seconds() // 60)} min ago")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--namespace", "-n", default="nano")
    ap.add_argument("--release", default="nano")
    ap.add_argument("--context")
    a = ap.parse_args()
    kube = Kube(a.namespace, a.context)
    prefix = a.release if "nano" in a.release else f"{a.release}-nano"
    try:
        pods = check_pods(kube, a.release)
    except (RuntimeError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"kubectl failed: {exc}", file=sys.stderr)
        return 2
    check_workloads(kube, a.release)
    check_vector(pods)
    check_clickhouse(kube, pods)
    check_registry(kube, prefix)
    print("HEALTHY" if not FAILS else f"UNHEALTHY: {', '.join(sorted(set(FAILS)))}")
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
