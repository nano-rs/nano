"""An in-memory nano API for the realistic seed's selftests (NAN-5764).

Just enough of the endpoints `nano_e2e.realistic_seed` calls, with the
product's observable rules that matter for idempotency and resume:

- a log source is a draft until published; DELETE removes it and writes an
  audit row; rules are archived by DELETE; a case delete's audit row has no
  resource name (NAN-5790);
- HEC accepts only live (unrevoked) ingest tokens; search finds what HEC
  accepted;
- hunts: one sweep in flight per hunt (409 otherwise); a claim pops the
  OLDEST queued desktop sweep of ANY hunt; a report needs the claiming
  runner and its fence; GET /api/hunts serves at most 50 rows a page;
- SOAR: GET /api/soar/flows ignores paging (every call is counted); a run
  waits on its approval.

`fail(method, path_regex, skip=n)` makes the (n+1)th matching request answer
500 once: the seed's interruption point.
"""

from __future__ import annotations

import itertools
import json
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, ClassVar
from urllib.parse import parse_qs

import httpx

FIELDS = {
    "device.hostname": lambda e: (e.get("device") or {}).get("hostname"),
    "device.ip": lambda e: (e.get("device") or {}).get("ip"),
    "actor.user.name": lambda e: ((e.get("actor") or {}).get("user") or {}).get("name"),
    "metadata.uid": lambda e: (e.get("metadata") or {}).get("uid"),
}


@dataclass
class Fault:
    method: str
    path: re.Pattern[str]
    skip: int


@dataclass
class FakeNano:
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)
    tokens: dict[str, dict[str, Any]] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)
    dashboards: list[dict[str, Any]] = field(default_factory=list)
    cases: dict[str, dict[str, Any]] = field(default_factory=dict)
    hunts: dict[str, dict[str, Any]] = field(default_factory=dict)
    sweeps: dict[str, dict[str, Any]] = field(default_factory=dict)
    leads: list[dict[str, Any]] = field(default_factory=list)
    runners: list[dict[str, Any]] = field(default_factory=list)
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    soar: dict[str, Any] = field(default_factory=lambda: {"soar_enabled": False, "revision": 1})
    packs: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {"name": n, "version": "1.0.0", "availability": "available", "installed": False}
            for n in ("okta", "crowdstrike", "slack")
        ]
    )
    flows: dict[str, dict[str, Any]] = field(default_factory=dict)
    runs: dict[str, dict[str, Any]] = field(default_factory=dict)
    approvals: list[dict[str, Any]] = field(default_factory=list)
    calls: Counter[str] = field(default_factory=Counter)
    faults: list[Fault] = field(default_factory=list)
    secrets_seen: list[str] = field(default_factory=list)
    # Ingest latency: an accepted event becomes searchable only after this
    # many further searches (a probe checked right after it is sent misses).
    latency: int = 2
    searches: int = 0
    _seq: itertools.count = field(default_factory=lambda: itertools.count(1))

    # ------------------------------------------------------------ plumbing
    def fail(self, method: str, path: str, skip: int = 0) -> None:
        self.faults.append(Fault(method, re.compile(path), skip))

    def _faulted(self, method: str, path: str) -> bool:
        for f in self.faults:
            if f.method == method and f.path.search(path):
                if f.skip == 0:
                    self.faults.remove(f)
                    return True
                f.skip -= 1
        return False

    def tick(self) -> int:
        return next(self._seq)

    def _audit(self, action: str, rid: str, name: str | None) -> None:
        self.audit.append({"action": action, "resource_id": rid, "resource_name": name})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        q = {k: v[-1] for k, v in parse_qs(request.url.query.decode()).items()}
        body: Any = json.loads(request.content) if request.content else None
        key = re.sub(r"/(lsrc|cred|rule|case|pb|swp|run|flow|sess|runner)_[0-9a-z]+", r"/{id}", path)
        self.calls[f"{method} {key}"] += 1
        if self._faulted(method, path):
            return httpx.Response(500, json={"error": {"code": "FAULT", "message": "injected"}})
        for pattern, fn in self.ROUTES:
            m = re.fullmatch(pattern, f"{method} {path}")
            if m:
                out = fn(self, q, body, *m.groups())
                status, payload = out if isinstance(out, tuple) else (200, out)
                return httpx.Response(status, json=payload)
        return httpx.Response(404, json={"error": {"message": f"fake: no route {method} {path}"}})

    def new_id(self, prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex[:26]}"

    # ------------------------------------------------------------ HEC (realistic_seed._hec_post)
    def hec(self, url: str, body: bytes, token: str) -> int:
        live = {t["token"] for t in self.tokens.values() if not t["revoked"]}
        if token not in live:
            return 401
        text, dec, i = body.decode(), json.JSONDecoder(), 0
        while i < len(text):
            obj, i = dec.raw_decode(text, i)
            self.events.append(
                {**obj["event"], "id": str(uuid.uuid4()), "_visible": self.searches + self.latency}
            )
        return 200

    # ------------------------------------------------------------ routes
    def login(self, q, body):
        sid = self.new_id("sess")
        access, refresh = f"jwt-access-{uuid.uuid4().hex}", f"jwt-refresh-{uuid.uuid4().hex}"
        self.secrets_seen += [access, refresh]
        self.sessions[sid] = {"id": sid, "created_at": "2099-01-01T00:00:00Z", "is_current": False}
        return {"tokens": {"access_token": access, "refresh_token": refresh}}

    def sessions_me(self, q, body):
        return {"sessions": list(self.sessions.values())}

    def session_delete(self, q, body, sid):
        self.sessions.pop(sid, None)
        return 204, None

    def sources_list(self, q, body):
        return list(self.sources.values())

    def source_create(self, q, body):
        sid = self.new_id("lsrc")
        self.sources[sid] = {"id": sid, **body}
        return 201, self.sources[sid]

    def source_publish(self, q, body, sid):
        self.sources[sid]["lifecycle_status"] = "active"
        return {"success": True}

    def source_delete(self, q, body, sid):
        src = self.sources.pop(sid)
        self._audit("log_source_deleted", sid, src["name"])
        return {"deleted": True}

    def token_create(self, q, body):
        cid = self.new_id("cred")
        tok = f"nano-ingest-{uuid.uuid4().hex}"
        self.secrets_seen.append(tok)
        self.tokens[cid] = {"token": tok, "revoked": False, "source_id": body["source_id"]}
        return 201, {"credential": {"credential_id": cid}, "token": tok}

    def tokens_list(self, q, body):
        rows = []
        for cid, t in self.tokens.items():
            src = self.sources.get(t["source_id"]) or {}
            rows.append(
                {
                    "credential_id": cid,
                    "route_key": (src.get("match_values") or [""])[0],
                    "state": "revoked" if t["revoked"] else "active",
                }
            )
        return {"tokens": rows}

    def token_revoke(self, q, body, cid):
        self.tokens[cid]["revoked"] = True
        return {"revoked": True}

    def search(self, q, body):
        self.searches += 1
        query = body["query"]
        events = [e for e in self.events if e["_visible"] <= self.searches]
        if "stats count by metadata.uid" in query:
            uids = Counter(FIELDS["metadata.uid"](e) for e in events)
            return {
                "results": [{"metadata.uid": u, "count": n} for u, n in uids.items()],
                "total_count": len(uids),
            }
        word = re.search(r'\s"([A-Za-z0-9-]+)"\s*$', query)
        if word:  # a keyword: whole word in the message
            rows = [e for e in events if word.group(1) in str(e.get("message", "")).split()]
            return {"results": rows[: body.get("limit", 100)], "total_count": len(rows)}
        m = re.search(r'([a-z_.]+)="([^"]*)"\s*$', query)
        rows = [e for e in events if m and FIELDS.get(m.group(1), lambda e: None)(e) == m.group(2)]
        return {"results": rows[: body.get("limit", 100)], "total_count": len(rows)}

    def mitre(self, q, body):
        techs = ["T1110", "T1558", "T1021", "T1059", "T1053", "T1070", "T1041", "T1071", "T1087", "T1078"]
        return {"techniques": [{"id": t, "tactic_ids": ["TA0006"]} for t in techs]}

    def rules_list(self, q, body):
        return list(self.rules.values())

    def rule_create(self, q, body):
        rid = self.new_id("rule")
        self.rules[rid] = {"id": rid, **body, "archived": False}
        return 201, self.rules[rid]

    def rules_import(self, q, body):
        for r in body["rules"]:
            self.rule_create(q, r)
        return {"imported": len(body["rules"])}

    def rule_put(self, q, body, rid):
        self.rules[rid].update(body)
        return self.rules[rid]

    def rule_delete(self, q, body, rid):
        self.rules[rid]["archived"] = True
        self._audit("rule_deleted", rid, self.rules[rid]["name"])
        return {"deleted": True}

    def rule_trigger(self, q, body, rid):
        self.alerts.append({"rule_id": rid})
        return {"ok": True}

    def alerts_list(self, q, body):
        return {"alerts": [a for a in self.alerts if a["rule_id"] == q.get("rule_id")]}

    def audit_list(self, q, body):
        needle = q.get("q", "")
        return {"logs": [r for r in self.audit if needle in json.dumps(r, ensure_ascii=False)]}

    def dashboards_list(self, q, body):
        return self.dashboards

    def dashboard_create(self, q, body):
        self.dashboards.append({"id": self.new_id("dash"), **body})
        return 201, self.dashboards[-1]

    def cases_list(self, q, body):
        rows = list(self.cases.values())
        off, lim = int(q.get("offset", 0)), int(q.get("limit", 50))
        return {"cases": rows[off : off + lim]}

    def case_create(self, q, body):
        cid = self.new_id("case")
        self.cases[cid] = {"id": cid, "status": "open", "tags": [], **body}
        self._audit("case_created", cid, body["title"])
        return 201, self.cases[cid]

    def case_delete(self, q, body, cid):
        self.cases.pop(cid)
        self._audit("case_deleted", cid, None)  # NAN-5790: no name on the delete row
        return 204, None

    def case_tags(self, q, body, cid):
        return [{"tag": t} for t in self.cases[cid]["tags"]]

    def case_tag_add(self, q, body, cid):
        tags = self.cases[cid]["tags"]
        if body["tag"] not in tags:
            if len(tags) >= 32:
                return 400, {"error": "at most 32 tags"}
            tags.append(body["tag"])
        return {"tags": tags}

    def case_status(self, q, body, cid):
        self.cases[cid]["status"] = body["status"]
        return self.cases[cid]

    def hunts_list(self, q, body):
        rows = [h for h in self.hunts.values() if h["status"] != "archived"]
        off, lim = int(q.get("offset", 0)), min(int(q.get("limit", 50)), 50)
        return {"hunts": rows[off : off + lim]}

    def hunt_create(self, q, body):
        hid = self.new_id("pb")
        self.hunts[hid] = {"id": hid, "name": body["title"], "status": "draft", **body}
        self._audit("hunt_created", hid, body["title"])
        return 201, self.hunts[hid]

    def hunt_delete(self, q, body, hid):
        self.hunts[hid]["status"] = "archived"
        self._audit("hunt_archived", hid, self.hunts[hid]["name"])
        return 204, None

    def leads_list(self, q, body):
        return {"leads": [ld for ld in self.leads if ld["playbook_id"] == q.get("playbook_id")]}

    def runners_list(self, q, body):
        return {"runners": self.runners}

    def runner_create(self, q, body):
        self.runners.append({"id": self.new_id("runner"), "kind": "desktop", **body})
        return 201, self.runners[-1]

    def sweeps_list(self, q, body, hid):
        return {"sweeps": [s for s in self.sweeps.values() if s["playbook_id"] == hid]}

    def sweep_create(self, q, body, hid):
        if any(
            s["playbook_id"] == hid and s["status"] in ("queued", "leased", "running")
            for s in self.sweeps.values()
        ):
            return 409, {"error": "A sweep is already in flight for this hunt"}
        sid = self.new_id("swp")
        self.sweeps[sid] = {
            "id": sid,
            "playbook_id": hid,
            "status": "queued",
            "runner_id": None,
            "runner_fence": None,
            "seq": self.tick(),
            "reported": [],
        }
        return 202, self.sweeps[sid]

    def claim(self, q, body, rid):
        queued = sorted((s for s in self.sweeps.values() if s["status"] == "queued"), key=lambda s: s["seq"])
        if not queued:
            return {"sweep": None}
        s = queued[0]
        s.update(status="leased", runner_id=rid, runner_fence=self.tick())
        task = f"task_{s['id']}"
        return {
            "sweep": {
                "sweep": dict(s),
                "runner_fence": s["runner_fence"],
                "task_id": task,
                "tasks": [{"id": task, "kind": "investigator"}],
            }
        }

    def sweep_tasks(self, q, body, sid):
        return {"tasks": [{"id": f"task_{sid}", "kind": "investigator"}]}

    def report(self, q, body, sid):
        s = self.sweeps[sid]
        if (
            s["status"] not in ("leased", "running")
            or s["runner_id"] != body["runner_id"]
            or (s["runner_fence"] != body["runner_fence"])
        ):
            return 409, {"error": "lease gone"}
        s["status"] = "finished"
        for c in body["report"]["candidates"]:
            self.leads.append(
                {"playbook_id": s["playbook_id"], "sweep_id": sid, "entity_value": c["entity_value"]}
            )
        s["reported"].append(len(body["report"]["candidates"]))
        return {"leads_created": len(body["report"]["candidates"])}

    def drafts(self, q, body):
        out = []
        for d in body["drafts"]:
            if d["title"] in {h["name"] for h in self.hunts.values()}:
                out.append({"status": "dismissed"})
            else:
                self.hunt_create(q, d)
                out.append({"status": "created"})
        return {"drafts": out}

    def soar_settings(self, q, body):
        return self.soar

    def soar_settings_put(self, q, body):
        self.soar.update(soar_enabled=body["soar_enabled"], revision=self.soar["revision"] + 1)
        return self.soar

    def packs_list(self, q, body):
        return {"packs": self.packs}

    def pack_install(self, q, body, name):
        next(p for p in self.packs if p["name"] == name)["installed"] = True
        return {"packs": self.packs}

    def flows_list(self, q, body):  # no paging: every flow, every call
        return {"flows": list(self.flows.values())}

    def flow_create(self, q, body):
        fid = self.new_id("flow")
        self.flows[fid] = {"id": fid, **body}
        return 201, self.flows[fid]

    def flow_run(self, q, body, fid):
        rid = self.new_id("run")
        self.runs[rid] = {"id": rid, "flow_id": fid, "status": "suspended"}
        self.approvals.append(
            {
                "id": self.new_id("apr"),
                "run_id": rid,
                "status": "pending",
                "flow_name": self.flows[fid]["name"],
            }
        )
        return 202, self.runs[rid]

    def runs_list(self, q, body):
        rows = list(self.runs.values())
        off, lim = int(q.get("offset", 0)), int(q.get("limit", 50))
        return {"runs": rows[off : off + lim]}

    def approvals_list(self, q, body):
        rows = [a for a in self.approvals if a["status"] == q.get("status", a["status"])]
        if q.get("run_id"):
            rows = [a for a in rows if a["run_id"] == q["run_id"]]
        off, lim = int(q.get("offset", 0)), int(q.get("limit", 50))
        return {"approvals": rows[off : off + lim]}

    ID = r"([A-Za-z0-9_-]+)"
    ROUTES: ClassVar[list[tuple[str, Any]]] = [
        ("POST /api/auth/login", login),
        ("GET /api/sessions/me", sessions_me),
        (f"DELETE /api/sessions/{ID}", session_delete),
        ("GET /api/log-sources", sources_list),
        ("POST /api/log-sources", source_create),
        (f"POST /api/log-sources/{ID}/publish", source_publish),
        (f"DELETE /api/log-sources/{ID}", source_delete),
        ("POST /api/ingest-tokens", token_create),
        ("GET /api/ingest-tokens", tokens_list),
        (f"POST /api/ingest-tokens/{ID}/revoke", token_revoke),
        ("POST /api/search", search),
        ("GET /api/mitre", mitre),
        ("GET /api/rules", rules_list),
        ("POST /api/rules", rule_create),
        ("POST /api/rules/import", rules_import),
        (f"POST /api/rules/{ID}/trigger", rule_trigger),
        (f"PUT /api/rules/{ID}", rule_put),
        (f"DELETE /api/rules/{ID}", rule_delete),
        ("GET /api/alerts", alerts_list),
        ("GET /api/audit", audit_list),
        ("GET /api/dashboards", dashboards_list),
        ("POST /api/dashboards", dashboard_create),
        ("GET /api/cases", cases_list),
        ("POST /api/cases", case_create),
        (f"DELETE /api/cases/{ID}", case_delete),
        (f"GET /api/cases/{ID}/tags", case_tags),
        (f"POST /api/cases/{ID}/tags", case_tag_add),
        (f"POST /api/cases/{ID}/status", case_status),
        ("GET /api/hunts/leads", leads_list),
        ("GET /api/hunts/runners", runners_list),
        ("POST /api/hunts/runners", runner_create),
        (f"POST /api/hunts/runners/{ID}/claim", claim),
        (f"GET /api/hunts/sweeps/{ID}/tasks", sweep_tasks),
        (f"POST /api/hunts/sweeps/{ID}/report", report),
        ("POST /api/hunts/drafts", drafts),
        ("GET /api/hunts", hunts_list),
        ("POST /api/hunts", hunt_create),
        (f"GET /api/hunts/{ID}/sweeps", sweeps_list),
        (f"POST /api/hunts/{ID}/sweeps", sweep_create),
        (f"DELETE /api/hunts/{ID}", hunt_delete),
        ("GET /api/soar/settings", soar_settings),
        ("PUT /api/soar/settings", soar_settings_put),
        ("GET /api/soar/packs", packs_list),
        (f"POST /api/soar/packs/{ID}/install", pack_install),
        ("GET /api/soar/flows", flows_list),
        ("POST /api/soar/flows", flow_create),
        (f"POST /api/soar/flows/{ID}/run", flow_run),
        ("GET /api/soar/runs", runs_list),
        ("GET /api/soar/approvals", approvals_list),
    ]
