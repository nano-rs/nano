"""Persona suite provider and runner plumbing, without Docker or a stack."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import httpx

from nano_e2e.ai_stub import AiStubServer, deterministic_content
from nano_e2e.personas import AI_MODEL, persona_ai_target_model_id

ROOT = Path(__file__).resolve().parents[2]


def test_persona_ai_resolves_the_model_row_before_snapshot(monkeypatch) -> None:
    monkeypatch.delenv("E2E_PERSONA_AI_MODE", raising=False)
    monkeypatch.delenv("NANO_E2E_AI_MODEL", raising=False)
    assert persona_ai_target_model_id() == AI_MODEL

    monkeypatch.setenv("E2E_PERSONA_AI_MODE", "real")
    monkeypatch.setenv("NANO_E2E_AI_MODEL", "gpt-4.1")
    assert persona_ai_target_model_id() == "openai/gpt-4.1"

    monkeypatch.setenv("NANO_E2E_AI_MODEL", "openai/gpt-4.1-mini")
    assert persona_ai_target_model_id() == "openai/gpt-4.1-mini"


def _request(system: str, user: str) -> dict:
    return {
        "model": "e2e-stub",
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }


def test_stub_dispatches_deterministic_query_summary_parser_and_detection() -> None:
    kind, query = deterministic_content(_request("build a query", "find nano-e2e-abc-123"))
    assert kind == "query" and '"nano-e2e-abc-123"' in query

    kind, summary = deterministic_content(
        _request("Respond with a JSON object in this exact format: risk_assessment", "nano-e2e-sum-123")
    )
    assert kind == "summary"
    assert json.loads(summary)["narrative"].startswith("Deterministic persona analysis")

    kind, parser = deterministic_content(_request("You write Vector Remap Language VRL parsers", "JSON auth"))
    assert kind == "parser"
    assert ".actor.user.name" in parser and ".src_endpoint.ip" in parser

    kind, detection = deterministic_content(
        _request("Create MULTIPLE detection rules using YAML frontmatter", "catch nano-e2e-detect-123")
    )
    assert kind == "detection"
    assert detection.count("title: persona_ai_") == 2
    assert detection.count('"nano-e2e-detect-123"') == 2


def test_stub_dispatches_structured_shadow_agents() -> None:
    kind, hunting = deterministic_content(
        _request('Autonomous hunting planner. Return {"queries": []}', "nano-e2e-shadow-123")
    )
    assert kind == "shadow_hunting"
    assert json.loads(hunting) == {"queries": []}

    kind, narrative = deterministic_content(
        _request("You are a senior SOC analyst", "Provide a threat assessment for nano-e2e-shadow-123")
    )
    assert kind == "shadow_narrative"
    verdict = json.loads(narrative)
    assert verdict["disposition"] == "needs_investigation"
    assert verdict["key_evidence"] == ["nano-e2e-shadow-123"]


def test_stub_http_journal_contains_digest_not_prompt_or_auth(tmp_path: Path) -> None:
    journal = tmp_path / "stub.jsonl"
    server = AiStubServer(("127.0.0.1", 0), journal)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        assert httpx.get(base + "/health").json() == {"status": "ok"}
        response = httpx.post(
            base + "/v1/chat/completions",
            headers={"Authorization": "Bearer secret-persona-key"},
            json=_request("build a query", "private nano-e2e-http-123 prompt"),
        )
        assert response.status_code == 200
        assert response.json()["choices"][0]["message"]["content"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    text = journal.read_text()
    assert "body_sha256" in text
    assert "private" not in text and "secret-persona-key" not in text


def test_runner_and_compose_expose_owned_persona_entry() -> None:
    runner = (ROOT / "scripts/e2e.sh").read_text()
    compose = (ROOT / "dev/e2e/compose.e2e.yml").read_text()
    assert 'personas) out+=("$PY_DIR/tests/personas")' in runner
    assert "selects_suite ui connectors otlp personas" in runner
    assert "PROFILES+=(ai-stub)" in runner
    assert '${E2E_PERSONA_AI_MODE:-stub}" != real' in runner
    assert 'profiles: ["ai-stub"]' in compose
    assert "${E2E_PROJECT}-ai-stub" in compose
    assert "127.0.0.1:${E2E_AI_STUB_PORT:?}:8080" in compose
    assert "${E2E_ALLOW_PRIVATE_AI_ENDPOINTS:-false}" in compose
