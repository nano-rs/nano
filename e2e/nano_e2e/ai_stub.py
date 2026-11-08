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


def deterministic_content(body: dict[str, Any]) -> tuple[str, str]:
    """Return ``(response kind, content)`` for an OpenAI request."""
    prompt = _messages(body)
    lower = prompt.lower()
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
                ".actor.user.name = string!(parsed.user)",
                ".src_endpoint.ip = string!(parsed.src_ip)",
                ".device.hostname = string!(parsed.host)",
                ".message = string!(parsed.message)",
            ]
        )
        return "parser", (
            "Deterministic persona JSON authentication parser.\n"
            f"```vrl\n{vrl}\n```\n"
            "Output fields: actor.user.name, src_endpoint.ip, device.hostname, message"
        )

    if "provider" in lower and ("connection" in lower or "respond" in lower):
        return "validation", "ok"

    return "query", (f'The query selects the deterministic persona ground truth.\n```spl\n"{marker}"\n```')


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
            kind, content = deterministic_content(body)
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
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
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
