"""Deterministic OpenAI-compatible provider for persona scenarios.

The server deliberately records only request metadata and a body digest.  AI
prompts contain customer log samples, so neither prompts nor authorization
headers belong in e2e artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

MODEL = "e2e-stub"
_MARKER = re.compile(r"nano-e2e-[a-z0-9-]+", re.IGNORECASE)


def _messages(body: dict[str, Any]) -> str:
    values: list[str] = []
    for message in body.get("messages", []):
        content = message.get("content", "") if isinstance(message, dict) else ""
        if isinstance(content, str):
            values.append(content)
        elif isinstance(content, list):
            values.extend(str(part.get("text", "")) for part in content if isinstance(part, dict))
    return "\n".join(values)


def _last_user_message(body: dict[str, Any]) -> str:
    for message in reversed(body.get("messages", [])):
        if isinstance(message, dict) and message.get("role") == "user":
            content = message.get("content", "")
            if isinstance(content, list):
                return "\n".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
            return str(content)
    return ""


def concierge_intent(message: str) -> dict[str, Any]:
    """The pivt concierge's intent for a persona message (NAN-5574).

    Only explicit verbs map to an action intent, like the real classifier's
    "default to chat" rule; the concierge then answers with a proposal card,
    never a change.
    """
    lower = message.lower()
    if lower.startswith("create log source with transport:"):
        return {"intent": "create_log_source"}
    if re.search(r"\b(publish|deploy|go live)\b", lower):
        return {"intent": "deploy_log_source"}
    # Like real models (NAN-5597): rule requests classify as `detection` and
    # panel requests as `dashboard`; the concierge must still route them to
    # the page's own action when the page offers one.
    if re.search(r"\bcreate an? \w+ rule\b|\b(promote|demote|pause|resume) (this|it|this rule)\b", lower):
        return {"intent": "detection", "description": message.strip()[:200]}
    if re.search(r"\badd an? \w+ panel\b", lower):
        return {"intent": "dashboard", "description": message.strip()[:200]}
    return {"intent": "chat"}


_PAGE_QUERY = re.compile(r'"query":\s*"((?:[^"\\]|\\.)*)"')
_PAGE_TOTAL = re.compile(r'"total":\s*(\d+)')
_SAVE = re.compile(r"save this search as (.+)$", re.IGNORECASE)
_RULE = re.compile(r"create a (critical|high|medium|low|informational) rule named (.+)$", re.IGNORECASE)
_PIVOT = re.compile(r"pivot to search for (.+)$", re.IGNORECASE)
_CLOSE = re.compile(r"close (?:this|it|this alert) as (false positive|true positive|benign)", re.IGNORECASE)
_PAGE_ALERT = re.compile(r'"alert":\s*(\{[^{}]*\})', re.S)
_LIFECYCLE = re.compile(r"\b(promote|demote|pause|resume) (?:this|it|this rule)\b", re.IGNORECASE)
_PAGE_RULE = re.compile(r'"rule":\s*(\{[^{}]*\})', re.S)
_ADD_PANEL = re.compile(r"add an? (table|bar|line|area|pie|single_value|ranked_bar|timeline) panel named (.+?) for (.+)$", re.IGNORECASE)
_PAGE_DASHBOARD = re.compile(r'"dashboard":\s*(\{[^{}]*\})', re.S)


def page_chat_reply(prompt: str, message: str) -> str:
    """pivt on a page (NAN-5571): ground the answer in the fenced page context
    and propose only actions the catalog lists."""
    msg = message.strip()
    # The analyst's message is the last "**Analyst message:**" line.
    if "**analyst message:**" in msg.lower():
        msg = msg.split("**Analyst message:**")[-1].strip().splitlines()[0].strip()
    m = _SAVE.search(msg)
    if m and "`search.save`" in prompt:
        action = {"action": "search.save", "params": {"name": m.group(1).strip()}, "why": "The analyst asked to save it."}
        return "I can save this search.\n\n```page_action\n" + json.dumps(action) + "\n```\n"
    m = _RULE.search(msg)
    if m and "`search.create_rule`" in prompt:
        action = {
            "action": "search.create_rule",
            "params": {"name": m.group(2).strip(), "severity": m.group(1).lower()},
            "why": "The analyst asked for a rule from this search.",
        }
        return "Here is the rule to create.\n\n```page_action\n" + json.dumps(action) + "\n```\n"
    m = _PIVOT.search(msg)
    if m and "`search.pivot`" in prompt:
        action = {"action": "search.pivot", "params": {"query": m.group(1).strip()}, "why": "The analyst asked to pivot."}
        return "Here is the pivot.\n\n```page_action\n" + json.dumps(action) + "\n```\n"
    m = _CLOSE.search(msg)
    if m and "`alerts.close`" in prompt:
        disposition = m.group(1).lower().replace(" ", "_")
        action = {"action": "alerts.close", "params": {"disposition": disposition}, "why": "The analyst asked to close it."}
        return "I can close this alert.\n\n```page_action\n" + json.dumps(action) + "\n```\n"
    lc = _LIFECYCLE.search(msg)
    if lc and f"`rules.{lc.group(1).lower()}`" in prompt:
        verb = lc.group(1).lower()
        action = {"action": f"rules.{verb}", "params": {}, "why": f"The analyst asked to {verb} it."}
        return f"I can {verb} this rule.\n\n```page_action\n" + json.dumps(action) + "\n```\n"
    ap = _ADD_PANEL.search(msg)
    if ap and "`dashboards.add_panel`" in prompt:
        action = {
            "action": "dashboards.add_panel",
            "params": {"title": ap.group(2).strip(), "query": ap.group(3).strip(), "visualization": ap.group(1).lower()},
            "why": "The analyst asked for this panel.",
        }
        return "Here is the panel to add.\n\n```page_action\n" + json.dumps(action) + "\n```\n"
    if m or lc or ap or _SAVE.search(msg) or _RULE.search(msg):
        return "That action isn't available to you on this page."
    opening = '<untrusted_case_data source="page_context">'
    start = prompt.rfind(opening)
    scope = ""
    if start >= 0:
        rest = prompt[start + len(opening):]
        scope = rest.split("</untrusted_case_data>", 1)[0]
    a = _PAGE_ALERT.search(scope)
    if a:
        try:
            alert = json.loads(a.group(1))
        except ValueError:
            alert = {}
        if alert.get("id"):
            return (
                f"This is alert `{alert['id']}` from rule {alert.get('rule')}, "
                f"severity {alert.get('severity')}, status {alert.get('status')}."
            )
    dsh = _PAGE_DASHBOARD.search(scope)
    if dsh:
        try:
            board = json.loads(dsh.group(1))
        except ValueError:
            board = {}
        if board.get("id"):
            return f"This is dashboard {board['id']} named {board.get('name')}, with {board.get('panel_count')} panels."
    r = _PAGE_RULE.search(scope)
    if r:
        try:
            rule = json.loads(r.group(1))
        except ValueError:
            rule = {}
        if rule.get("id"):
            return f"This is rule {rule['id']} named {rule.get('name')}, in {rule.get('mode')} mode."
    q = _PAGE_QUERY.search(scope)
    t = _PAGE_TOTAL.search(scope)
    query = json.loads(f'"{q.group(1)}"') if q else "(none)"
    total = t.group(1) if t else "unknown"
    return f"You are looking at the query `{query}`, which matched {total} events on this page."


def deterministic_content(body: dict[str, Any]) -> tuple[str, str]:
    """Return ``(response kind, content)`` for an OpenAI request."""
    prompt = _messages(body)
    lower = prompt.lower()

    if "## the analyst's current page" in lower:
        return "page_chat", page_chat_reply(prompt, _last_user_message(body))

    if "intent classifier for a siem system" in lower:
        return "concierge_intent", json.dumps(concierge_intent(_last_user_message(body)))
    marker_match = _MARKER.search(prompt)
    marker = marker_match.group(0) if marker_match else "nano-e2e-persona"

    if "security operations triage judge" in lower:
        return "soar_judge", json.dumps(
            {
                "verdict": "compromised",
                "confidence": 0.99,
                "why": "Deterministic SOAR acceptance evidence matched.",
            }
        )

    if "create multiple detection rules using yaml frontmatter" in lower:
        return "detection", "\n\n".join(
            [
                "\n".join(
                    [
                        "---",
                        f"title: persona_ai_{index}_{marker.replace('-', '_')}",
                        f'description: "Detects deterministic persona marker {marker}"',
                        "severity: high",
                        "mode: staging",
                        "detection_mode: scheduled",
                        'mitre_tactics: "TA0001"',
                        'mitre_techniques: "T1078"',
                        "risk_score: auto",
                        "risk_entity: auto-detect",
                        "tags: persona, e2e",
                        "---",
                        f'"{marker}"',
                    ]
                )
                for index in (1, 2)
            ]
        )

    if '"queries"' in lower and "autonomous" in lower and "hunting" in lower:
        return "shadow_hunting", json.dumps({"queries": []})

    if "senior soc analyst" in lower and "threat assessment" in lower:
        return "shadow_narrative", json.dumps(
            {
                "disposition": "needs_investigation",
                "confidence": 0.65,
                "rationale": f"Deterministic investigation retained evidence for {marker}.",
                "recommended_action": "Have the assigned responder validate the affected identity.",
                "recommended_severity": "medium",
                "key_evidence": [marker],
                "is_follow_up_revision": False,
            }
        )

    if "log source classifier" in lower or '"source_type"' in lower and "alternatives" in lower:
        return "classifier", json.dumps(
            {
                "source_type": "",
                "reason": "No classifier needed for deterministic persona data",
                "alternatives": [],
            }
        )

    if "json object in this exact format" in lower and "risk_assessment" in lower:
        return "summary", json.dumps(
            {
                "narrative": f"Deterministic persona analysis verified the ground-truth marker {marker}.",
                "key_findings": [
                    {
                        "category": "pattern",
                        "title": "Ground truth verified",
                        "description": "The expected persona events are present in the displayed result set.",
                        "importance": "medium",
                        "related_fields": ["actor.user.name", "src_endpoint.ip"],
                    }
                ],
                "suggested_queries": [],
                "risk_assessment": {
                    "level": "low",
                    "explanation": "This is deterministic test data.",
                    "indicators": [],
                },
            }
        )

    if "vector remap language" in lower or "vrl parser" in lower or "generate_vrl" in lower:
        vrl = "\n".join(
            [
                "parsed = parse_json!(string!(.message))",
                ".class_uid = 3002",
                ".category_uid = 3",
                ".activity_id = 1",
                ".type_uid = 300201",
                ".severity_id = 1",
                # A complete OCSF 1.9.0 Authentication event: the parser editor
                # validates generated drafts against the contract (NAN-5333).
                '.time = to_unix_timestamp(now(), unit: "milliseconds")',
                '.metadata.version = "1.9.0"',
                '.metadata.product.name = "nano-e2e"',
                '.metadata.product.vendor_name = "nano"',
                ".user.name = string!(parsed.user)",
                ".actor.user.name = .user.name",
                ".src_endpoint.ip = string!(parsed.src_ip)",
                ".src_endpoint.hostname = string!(parsed.host)",
                '.service.name = "persona-auth"',
                ".message = string!(parsed.message)",
            ]
        )
        return "parser", (
            "Deterministic persona JSON authentication parser.\n"
            f"```vrl\n{vrl}\n```\n"
            "Output fields: user.name, actor.user.name, src_endpoint.ip, src_endpoint.hostname, service.name, message"
        )

    if "provider" in lower and ("connection" in lower or "respond" in lower):
        return "validation", "ok"

    return "query", (f'The query selects the deterministic persona ground truth.\n```spl\n"{marker}"\n```')


# ---------------------------------------------------------------------------
# Hunts v2 (NAN-5561): scripted tool calls for the hunt agents.
#
# The hunt investigator, reviewer, recheck and eval agents talk in TOOL CALLS,
# so the stub answers them with OpenAI `tool_calls`, chosen from the request
# alone (stateless): which tools are offered says which agent is asking, and
# the tool calls already in the history say which step it is on. The script
# follows the threat-hunter persona's seeded ground truth (`fin-ws-<tag>` is
# the malicious chain, `sccm-<tag>` the benign lookalike).
# ---------------------------------------------------------------------------

_EVENT_ID = re.compile(r'"id"\s*:\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"')
_ANY_UUID = re.compile(r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b")
_LEAD_ID = re.compile(r"\blead_[0-9a-z]{26}\b")
_HUNT_HOST = re.compile(r"\b(fin-ws|fin-srv|eng-ws|sccm|dc01)-[a-z0-9-]+\b")
# In the investigator's prompt (a hunt charter's analyst notes): file the
# `fin-ws-*` lead at critical instead of high.
HUNT_FILE_CRITICAL_MARKER = "e2e-file-severity-critical"


def _tool_names(body: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for tool in body.get("tools") or []:
        if isinstance(tool, dict):
            fn = tool.get("function") if isinstance(tool.get("function"), dict) else tool
            if isinstance(fn, dict) and fn.get("name"):
                names.add(str(fn["name"]))
    return names


def _calls_made(body: dict[str, Any]) -> list[str]:
    made: list[str] = []
    for message in body.get("messages", []):
        if isinstance(message, dict) and message.get("role") == "assistant":
            for call in message.get("tool_calls") or []:
                fn = call.get("function") if isinstance(call, dict) else None
                if isinstance(fn, dict) and fn.get("name"):
                    made.append(str(fn["name"]))
    return made


def _last_tool_result(body: dict[str, Any]) -> str:
    for message in reversed(body.get("messages", [])):
        if isinstance(message, dict) and message.get("role") == "tool":
            content = message.get("content")
            return content if isinstance(content, str) else json.dumps(content)
    return ""


def _rows_with(prompt: str, needle: str) -> list[str]:
    ids: list[str] = []
    for line in prompt.splitlines():
        if needle in line:
            for match in _EVENT_ID.findall(line):
                if match not in ids:
                    ids.append(match)
    return ids


def _call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    digest = hashlib.sha256(f"{name}{json.dumps(arguments, sort_keys=True)}".encode()).hexdigest()[:12]
    return {"id": f"call_{digest}", "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}


def hunt_tool_calls(body: dict[str, Any]) -> tuple[str, list[dict[str, Any]] | str] | None:
    """`(kind, tool_calls | final text)` for a hunt agent's request, else None."""
    tools = _tool_names(body)
    prompt = _messages(body)
    made = _calls_made(body)
    if "record_eval_verdict" in tools:
        benign = "sccm-" in prompt or "ccmexec" in prompt.lower()
        return "hunt_eval", [_call("record_eval_verdict", {
            "verdict": "benign" if benign else "escalated", "confidence": 0.9 if benign else 0.85})]
    if "record_recheck" in tools:
        return "hunt_recheck", [_call("record_recheck", {"verdict": "quiet", "event_ids": []})]
    if "record_verdict" in tools:
        # The finding under review is named after "FINDING"; other lead ids in
        # the context are memory (recent findings, rulings).
        named = re.search(r"FINDING (lead_[0-9a-z]{26})", prompt)
        lead = named if named else _LEAD_ID.search(prompt)
        entity = re.search(r"entity_value: (\S+)", prompt)
        host = entity.group(1) if entity else ""
        # The finding's own evidence pointers (`<id> source_type=... at ...`
        # lines in the claim fence): fetched first and cited first, so the
        # verdict's citations verify (other UUIDs in the context are memory).
        pointers = list(dict.fromkeys(
            m.group(1) for m in re.finditer(
                r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) source_type=", prompt, re.MULTILINE)))
        if "get_events" not in made:
            ids = (pointers + [i for i in _ANY_UUID.findall(prompt) if i not in pointers])[:10]
            return "hunt_reviewer", [_call("get_events", {"ids": ids})]
        last = _last_tool_result(body)
        retry = "record_verdict" in made and last.startswith("ERROR")
        if ("record_verdict" not in made or retry) and lead:
            # Cite what get_events returned (any id it rendered), else the
            # finding's own evidence pointers.
            fetched = list(dict.fromkeys(_ANY_UUID.findall(last)))[:10] if not retry else []
            own = [i for i in pointers if i in fetched]
            if own:
                fetched = own
            if not fetched:
                fetched = pointers[:10] or list(dict.fromkeys(_ANY_UUID.findall(prompt)))[:10]
            benign = host.startswith("sccm-")
            return "hunt_reviewer", [_call("record_verdict", {
                "lead_id": lead.group(1) if named else lead.group(0),
                "verdict": "benign" if benign else "escalated",
                "confidence": 0.9,
                "severity": "medium" if benign else "high",
                "internet_facing": False,
                "attack_succeeded": None if benign else True,
                "rationale": "Deterministic e2e review: " + (
                    "patch-management baseline with 14 days of history." if benign else
                    "Office spawned encoded PowerShell that reached a Tor exit and dropped a binary."),
                "benign_hypotheses": [{"hypothesis": "SCCM patch management", "status": "fits" if benign else "ruled_out",
                                       "basis": "parent process and history"}],
                "checks": [{"tool": "get_events", "summary": "re-read the finding's evidence", "event_ids": fetched[:5]}],
                "cited_event_ids": fetched,
            })]
        return "hunt_reviewer", "Review complete."
    if "file_finding" in tools:
        filed = made.count("file_finding")
        tag_hosts = {m.group(0) for m in _HUNT_HOST.finditer(prompt)}
        fin = next((h for h in sorted(tag_hosts) if h.startswith("fin-ws-")), None)
        sccm = next((h for h in sorted(tag_hosts) if h.startswith("sccm-")), None)
        if filed == 0 and fin and _rows_with(prompt, fin):
            # NAN-5663: a hunt charter carrying this marker files the same
            # chain at critical (the duplicate gate's "worse" variant).
            severity = "critical" if HUNT_FILE_CRITICAL_MARKER in prompt else "high"
            return "hunt_investigator", [_call("file_finding", {
                "class": "lead", "entity_type": "host", "entity_value": fin, "technique": "T1059.001",
                "severity": severity, "confidence": 0.8, "evidence_event_ids": _rows_with(prompt, fin)[:8],
                "benign_analysis": "Not patch management: the parent is WINWORD and the host reached a Tor exit.",
                "narrative": "Office macro to encoded PowerShell to Tor egress to a dropper.",
            })]
        if filed <= 1 and sccm and _rows_with(prompt, sccm) and "sccm" not in _last_tool_result(body):
            return "hunt_investigator", [_call("file_finding", {
                "class": "benign", "entity_type": "host", "entity_value": sccm, "severity": "low", "confidence": 0.9,
                "evidence_event_ids": _rows_with(prompt, sccm)[:5],
                "benign_analysis": "SCCM ccmexec runs this encoded inventory script daily; 14 days of history.",
            })]
        return "hunt_investigator", [_call("finish", {"note": "Deterministic e2e investigation complete."})]
    return None


class AiStubServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], journal: Path | None = None):
        super().__init__(address, AiStubHandler)
        self.journal = journal
        self._journal_lock = threading.Lock()
        self._ordinal = 0

    def record(self, path: str, kind: str, model: str, raw: bytes) -> None:
        if self.journal is None:
            return
        with self._journal_lock:
            self._ordinal += 1
            record = {
                "ordinal": self._ordinal,
                "path": path,
                "kind": kind,
                "model": model,
                "body_sha256": hashlib.sha256(raw).hexdigest(),
                # NAN-5642: whether a hunt charter block reached the prompt (a
                # boolean marker, never prompt content).
                "charter": b"CHARTER (this hunt's charter" in raw or b"CHARTER (the install's default charter" in raw,
            }
            self.journal.parent.mkdir(parents=True, exist_ok=True)
            with self.journal.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")


class AiStubHandler(BaseHTTPRequestHandler):
    server: AiStubServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        return

    def _json(self, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/health":
            self._json(200, {"status": "ok"})
        elif self.path.rstrip("/") == "/v1/models":
            self._json(200, {"object": "list", "data": [{"id": MODEL, "object": "model"}]})
        else:
            self._json(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.rstrip("/") not in {"/v1/chat/completions", "/chat/completions"}:
            self._json(404, {"error": {"message": "not found"}})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": {"message": "invalid content length"}})
            return
        if size <= 0 or size > 2_000_000:
            self._json(413, {"error": {"message": "request body must be 1-2000000 bytes"}})
            return
        raw = self.rfile.read(size)
        try:
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError("JSON body must be an object")
            scripted = hunt_tool_calls(body)
            kind, content = scripted if scripted is not None else deterministic_content(body)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": {"message": f"invalid request: {exc}"}})
            return
        model = str(body.get("model") or MODEL)
        self.server.record(self.path, kind, model, raw)
        self._json(
            200,
            {
                "id": f"persona-{int(time.time())}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": (
                            {"role": "assistant", "content": None, "tool_calls": content}
                            if isinstance(content, list)
                            else {"role": "assistant", "content": content}
                        ),
                        "finish_reason": "tool_calls" if isinstance(content, list) else "stop",
                    }
                ],
                "usage": {"prompt_tokens": 64, "completion_tokens": 64, "total_tokens": 128},
            },
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--journal", type=Path)
    args = parser.parse_args()
    AiStubServer((args.host, args.port), args.journal).serve_forever()


if __name__ == "__main__":
    main()
