"""Shared real-browser framework for role-based persona journeys.

Lane B adds journeys under ``tests/personas`` and consumes these helpers; it
does not need to change the lane-A scenarios or own another browser harness.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from collections import Counter
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlparse

import httpx

from nano_e2e import ui as uilib
from nano_e2e.cleanup import CleanupStack
from nano_e2e.client import Journal, Nano, expect, row_text
from nano_e2e.rbac import limited_user
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

AI_MODEL = "openai/e2e-stub"
PERSONA_AI_AGENTS = (
    "query",
    "detection",
    "parser",
    "parser_edit",
    "summarize",
    "shadow_hunting",
    "shadow_narrative",
)


def persona_ai_target_model_id() -> str:
    """Return the exact model row this persona run will mutate."""
    if os.environ.get("E2E_PERSONA_AI_MODE", "stub").strip().lower() != "real":
        return AI_MODEL
    provider_model = os.environ.get("NANO_E2E_AI_MODEL", "").strip()
    assert provider_model, "real persona AI requires NANO_E2E_AI_MODEL"
    return provider_model if provider_model.startswith("openai/") else f"openai/{provider_model}"


DETECTION_ENGINEER_PERMISSIONS = (
    "search:view",
    "search:execute",
    "search:sql",
    "detections:view",
    "detections:create",
    "detections:edit",
    "detections:promote",
    "alerts:view",
    "cases:view",
    "settings:ai",
    "melod:chat",
    "melod:detection",
)

INCIDENT_RESPONDER_PERMISSIONS = (
    "alerts:view",
    "alerts:acknowledge",
    "alerts:assign",
    "cases:view",
    "cases:edit",
    "cases:assign",
    "cases:close",
    "cases:comment",
    "notebooks:view",
    "notebooks:create",
    "notebooks:edit",
    "users:view",
    "playbooks:view",
    "playbooks:run",
    "soar:view",
    "soar:run",
)

INCIDENT_APPROVER_PERMISSIONS = (
    "cases:view",
    "cases:edit",
    "cases:assign",
    "cases:comment",
    "notebooks:view",
    "notebooks:edit",
    "playbooks:view",
    "soar:view",
    "soar:approve",
)

PLATFORM_ADMIN_PERMISSIONS = (
    "settings:view",
    "settings:system",
    "groups:view",
    "roles:view",
    "apikeys:view",
    "apikeys:create",
    "apikeys:edit",
    "apikeys:delete",
    "audit:view",
    "search:view",
    "search:execute",
)

PLATFORM_VIEWER_PERMISSIONS = ("settings:view", "apikeys:view")

SOC_ANALYST_PERMISSIONS = (
    "search:view",
    "search:execute",
    "search:save",
    "dashboards:view",
    "dashboards:create",
    "dashboards:edit",
    "settings:ai",
    "melod:summarize",
)

SIEM_ENGINEER_PERMISSIONS = (
    "search:view",
    "search:execute",
    "prevalence:view",
    "prevalence:configure",
    "users:view",
    "roles:view",
    "roles:create",
    "log_sources:view",
    "log_sources:create",
    "log_sources:edit",
    "log_sources:deploy",
    "source_configs:view",
    "parser_repositories:view",
    "settings:system",
    "melod:parser",
)


@dataclass(frozen=True)
class GroundTruth:
    marker: str
    source: str
    users: dict[str, int]
    ips: tuple[str, ...]
    total: int

    @property
    def query(self) -> str:
        return f'"{self.marker}"'


@dataclass
class PersonaBrowser:
    name: str
    page: uilib.UiPage
    permissions: list[str]
    client: Nano
    cleanup: CleanupStack

    def checkpoint(self, slug: str) -> Path:
        return self.page.screenshot(f"{self.name}-{slug}.png")


@contextmanager
def login_persona(
    stack: Stack,
    nano: Nano,
    driver: uilib.Driver,
    artifact_dir: Path,
    name: str,
    permissions: Sequence[str],
) -> Iterator[PersonaBrowser]:
    """Create role/group/user, perform a real UI login, and remove all three."""
    granted = list(permissions)
    assert granted, "a persona must declare an explicit non-empty permission set"
    with limited_user(stack, name, granted, Journal(artifact_dir / f"{name}-rbac.jsonl")) as user:
        page = uilib.UiPage.open(driver, artifact_dir / f"ui-{name}", name=f"persona:{name}")
        cleanup = CleanupStack()
        failed = True
        cleanup_failure: Exception | None = None
        try:
            driver.register_secret(user.password)
            uilib.login(page, user.email, user.password)
            jwt = nano.login(user.email, user.password)
            client = Nano(
                stack.api_url,
                stack.search_url,
                {"Authorization": f"Bearer {jwt}"},
                Journal(artifact_dir / f"{name}-api.jsonl"),
            )
            failed = False
            yield PersonaBrowser(name=name, page=page, permissions=granted, client=client, cleanup=cleanup)
        except Exception:
            failed = True
            raise
        finally:
            if "client" in locals():
                try:
                    cleanup.close()
                except Exception as exc:  # noqa: BLE001 - close browser/client before surfacing cleanup
                    cleanup_failure = exc
                finally:
                    client.close()
            page.finish(failed or cleanup_failure is not None)
            if cleanup_failure is not None:
                raise cleanup_failure


def seed_ground_truth(stack: Stack, nano: Nano, lane: Any, marker: str) -> GroundTruth:
    users = {f"alice-{marker[-6:]}": 2, f"bob-{marker[-6:]}": 3, f"carol-{marker[-6:]}": 5}
    ips: list[str] = []
    seq = 0
    for user, count in users.items():
        for _ in range(count):
            ip = f"203.0.113.{seq + 10}"
            lane.send(stack, marker, user, ip, f"persona-host-{seq % 3}", note=f"persona-seq={seq}")
            ips.append(ip)
            seq += 1
    truth = GroundTruth(marker=marker, source=lane.lane, users=users, ips=tuple(ips), total=seq)
    eventually(
        lambda: nano.search(truth.query)["total_count"],
        timeout=INGEST_VISIBLE,
        desc="all persona ground-truth events searchable",
        ok=lambda value: value == truth.total,
    )
    return truth


def assert_ground_truth_api(nano: Nano, truth: GroundTruth) -> None:
    rows = nano.rows(truth.query, limit=100)
    users = Counter(str(row.get("actor", {}).get("user", {}).get("name", "")) for row in rows)
    if not any(users):
        # Search rows may be flattened depending on the response projection.
        users = Counter(str(row.get("actor.user.name", "")) for row in rows)
    assert len(rows) == truth.total, f"expected {truth.total} rows, got {len(rows)}"
    assert {key: users[key] for key in truth.users} == truth.users, users
    assert all(truth.marker in row_text(row) for row in rows)


def assert_ground_truth_ui(page: uilib.UiPage, nano: Nano, truth: GroundTruth) -> None:
    uilib.run_search(page, truth.query)
    assert uilib.results_count(page) == nano.search(truth.query)["total_count"] == truth.total
    rows = uilib.result_rows_text(page)
    rendered = "\n".join(rows)
    assert len(rows) == truth.total, f"rendered {len(rows)} of {truth.total} ground-truth rows"
    assert all(truth.marker in row for row in rows), rendered[:2000]
    assert all(ip in rendered for ip in truth.ips), rendered[:2000]


def configure_persona_ai(nano: Nano) -> str | None:
    """Configure the default stub or the explicitly requested real provider.

    The real-provider mode is opt-in because it sends the synthetic persona
    samples to an external OpenAI-compatible endpoint and can incur cost.
    """
    edition = os.environ.get("E2E_EDITION", "enterprise")
    if edition == "open":
        capabilities = expect(nano.api.get("/api/capabilities"), 200)
        assert capabilities.get("capabilities", {}).get("melod") is False, capabilities
        return None

    mode = os.environ.get("E2E_PERSONA_AI_MODE", "stub").strip().lower()
    assert mode in {"stub", "real"}, "E2E_PERSONA_AI_MODE must be stub or real"

    if mode == "stub":
        profiles = os.environ.get("E2E_PROFILES", "").split()
        assert "ai-stub" in profiles, "stub personas require the owned ai-stub profile"
        health_url = os.environ["E2E_AI_STUB_URL"] + "/health"
        assert httpx.get(health_url, timeout=5).json() == {"status": "ok"}
        provider_url = os.environ["E2E_AI_PROVIDER_BASE_URL"]
        api_key = "sk-e2e-persona-provider"
        model_id = persona_ai_target_model_id()
        provider_model = "e2e-stub"
        context_window = 262144
        display_name = "e2e deterministic stub"
    else:
        required = ("NANO_E2E_AI_API_KEY", "NANO_E2E_AI_BASE_URL", "NANO_E2E_AI_MODEL")
        missing = [name for name in required if not os.environ.get(name, "").strip()]
        assert not missing, f"real persona AI requires {', '.join(missing)}"
        api_key = os.environ["NANO_E2E_AI_API_KEY"].strip()
        provider_url = os.environ["NANO_E2E_AI_BASE_URL"].strip().rstrip("/")
        provider_model = os.environ["NANO_E2E_AI_MODEL"].strip()
        model_id = persona_ai_target_model_id()
        provider_model = provider_model.removeprefix("openai/")
        context_window = int(os.environ.get("NANO_E2E_AI_CONTEXT_WINDOW", "128000"))
        assert context_window >= 128000, "NANO_E2E_AI_CONTEXT_WINDOW must be at least 128000"
        display_name = "optional real persona provider"

    expect(
        nano.api.put(
            "/api/settings/ai-providers/openai",
            json={
                "api_key": api_key,
                "config": {"base_url": provider_url, "test_model": provider_model},
                "enabled": True,
            },
        ),
        200,
    )
    validated = expect(nano.api.post("/api/settings/ai-providers/openai/validate", json={}), 200)
    assert validated.get("success") is True, validated

    create = nano.api.post(
        "/api/settings/available-models",
        json={
            "model_id": model_id,
            "provider": "openai",
            "display_name": display_name,
            "context_window": context_window,
            "supports_vision": False,
            "supports_function_calling": False,
        },
    )
    assert create.status_code in (200, 201, 409), create.text[:1000]
    model = expect(
        nano.api.put(
            f"/api/settings/available-models/{quote(model_id, safe='')}",
            json={
                "display_name": display_name,
                "context_window": context_window,
                "supports_vision": False,
                "supports_function_calling": False,
                "deprecated": False,
            },
        ),
        200,
    )
    assert model["context_window"] == context_window, model
    for agent in PERSONA_AI_AGENTS:
        configured = expect(
            nano.api.put(
                f"/api/settings/agent-models/{agent}",
                json={"model_id": model_id, "max_tokens": 4096, "temperature": 0.0, "enabled": True},
            ),
            200,
        )
        assert configured["model_id"] == model_id, configured
    return mode


@dataclass(frozen=True)
class PersonaAiSnapshot:
    target_model_id: str
    provider: dict[str, Any]
    model: dict[str, Any] | None
    agents: dict[str, dict[str, Any]]
    database: dict[str, Any] = field(repr=False)


def _psql_json(query: str) -> Any:
    """Run a read/write query against this owned stack without logging secrets."""
    parsed = urlparse(os.environ["DATABASE_URL"])
    assert parsed.hostname and parsed.username and parsed.path, "DATABASE_URL is incomplete"
    env = os.environ.copy()
    env["PGPASSWORD"] = unquote(parsed.password or "")
    command = [
        "psql",
        "--no-psqlrc",
        "--tuples-only",
        "--no-align",
        "--set",
        "ON_ERROR_STOP=1",
        "--host",
        parsed.hostname,
        "--port",
        str(parsed.port or 5432),
        "--username",
        unquote(parsed.username),
        "--dbname",
        parsed.path.lstrip("/"),
        "--file",
        "-",
    ]
    result = subprocess.run(  # noqa: S603 - fixed executable/argv; SQL is supplied on stdin
        command,
        input=query,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"persona AI snapshot SQL failed: {result.stderr[-1000:]}")
    output = result.stdout.strip()
    if not output:
        return None
    # psql prints command tags (for example ``DO``) before a following SELECT
    # even in tuples-only mode.  The final non-empty line is our JSON value.
    return json.loads(output.splitlines()[-1])


def _database_ai_snapshot(target_model_id: str) -> dict[str, Any]:
    model_id_b64 = base64.b64encode(target_model_id.encode()).decode()
    model_id_sql = f"convert_from(decode('{model_id_b64}', 'base64'), 'UTF8')"
    snapshot = _psql_json(
        f"""
        SELECT json_build_object(
          'target_model_id', {model_id_sql},
          'provider', (
            SELECT json_build_object(
              'credentials_b64', CASE WHEN credentials_encrypted IS NULL THEN NULL
                                      ELSE encode(credentials_encrypted, 'base64') END,
              'config', config,
              'enabled', enabled,
              'last_validated_at', last_validated_at,
              'validation_error', validation_error,
              'updated_at', updated_at
            )
            FROM provider_credentials WHERE provider = 'openai'
          ),
          'model', (
            SELECT row_to_json(model_row)
            FROM (
              SELECT model_id, provider, display_name, context_window,
                     input_price_per_million, output_price_per_million,
                     supports_vision, supports_function_calling, deprecated, created_at
              FROM available_models WHERE model_id = {model_id_sql}
            ) AS model_row
          ),
          'melod_enabled', (SELECT enabled FROM melod_settings WHERE id = 'default')
        );
        """  # noqa: S608 - model_id_b64 uses the base64 alphabet, which excludes SQL quotes
    )
    assert snapshot.get("provider") is not None, "fresh enterprise stack is missing seeded openai provider"
    return snapshot


def snapshot_persona_ai(nano: Nano) -> PersonaAiSnapshot | None:
    if os.environ.get("E2E_EDITION", "enterprise") == "open":
        return None
    provider = expect(nano.api.get("/api/settings/ai-providers/openai"), 200)
    models = expect(nano.api.get("/api/settings/available-models/all"), 200)
    agents = expect(nano.api.get("/api/settings/agent-models"), 200)
    agent_map = {item["agent_id"]: item for item in agents}
    missing = set(PERSONA_AI_AGENTS) - set(agent_map)
    assert not missing, f"persona AI requires seeded agent bindings; missing {sorted(missing)}"
    target_model_id = persona_ai_target_model_id()
    model = next((item for item in models if item.get("model_id") == target_model_id), None)
    return PersonaAiSnapshot(
        target_model_id=target_model_id,
        provider=provider,
        model=model,
        agents=agent_map,
        database=_database_ai_snapshot(target_model_id),
    )


def _restore_provider_database(snapshot: dict[str, Any]) -> None:
    encoded = base64.b64encode(json.dumps(snapshot, separators=(",", ":")).encode()).decode()
    query = f"""
        DO $restore$
        DECLARE s jsonb := convert_from(decode('{encoded}', 'base64'), 'UTF8')::jsonb;
        BEGIN
          UPDATE provider_credentials
          SET credentials_encrypted = CASE WHEN s->'provider'->>'credentials_b64' IS NULL THEN NULL
                                           ELSE decode(s->'provider'->>'credentials_b64', 'base64') END,
              config = s->'provider'->'config',
              enabled = (s->'provider'->>'enabled')::boolean,
              last_validated_at = (s->'provider'->>'last_validated_at')::timestamptz,
              validation_error = s->'provider'->>'validation_error',
              updated_at = (s->'provider'->>'updated_at')::timestamptz
          WHERE provider = 'openai';
          UPDATE melod_settings
          SET enabled = (s->>'melod_enabled')::boolean
          WHERE id = 'default';
        END
        $restore$;
        SELECT 'null'::json;
        """  # noqa: S608 - encoded uses the base64 alphabet, which excludes SQL quotes
    _psql_json(query)


def _restore_model_database(snapshot: dict[str, Any]) -> None:
    encoded = base64.b64encode(json.dumps(snapshot, separators=(",", ":")).encode()).decode()
    query = f"""
        DO $restore$
        DECLARE s jsonb := convert_from(decode('{encoded}', 'base64'), 'UTF8')::jsonb;
        BEGIN
          IF s->'model' IS NULL OR s->'model' = 'null'::jsonb THEN
            DELETE FROM available_models WHERE model_id = s->>'target_model_id';
          ELSE
            INSERT INTO available_models (
              model_id, provider, display_name, context_window,
              input_price_per_million, output_price_per_million,
              supports_vision, supports_function_calling, deprecated, created_at
            ) VALUES (
              s->'model'->>'model_id',
              s->'model'->>'provider',
              s->'model'->>'display_name',
              (s->'model'->>'context_window')::integer,
              (s->'model'->>'input_price_per_million')::real,
              (s->'model'->>'output_price_per_million')::real,
              (s->'model'->>'supports_vision')::boolean,
              (s->'model'->>'supports_function_calling')::boolean,
              (s->'model'->>'deprecated')::boolean,
              (s->'model'->>'created_at')::timestamptz
            )
            ON CONFLICT (model_id) DO UPDATE SET
              provider = EXCLUDED.provider,
              display_name = EXCLUDED.display_name,
              context_window = EXCLUDED.context_window,
              input_price_per_million = EXCLUDED.input_price_per_million,
              output_price_per_million = EXCLUDED.output_price_per_million,
              supports_vision = EXCLUDED.supports_vision,
              supports_function_calling = EXCLUDED.supports_function_calling,
              deprecated = EXCLUDED.deprecated,
              created_at = EXCLUDED.created_at;
          END IF;
        END
        $restore$;
        SELECT 'null'::json;
        """  # noqa: S608 - encoded uses the base64 alphabet, which excludes SQL quotes
    _psql_json(query)


def restore_persona_ai(nano: Nano, snapshot: PersonaAiSnapshot | None) -> None:
    if snapshot is None:
        return
    failures: list[Exception] = []

    def attempt(label: str, operation) -> None:
        try:
            operation()
        except Exception as exc:  # noqa: BLE001 - every restore must still be attempted
            failures.append(RuntimeError(f"persona AI restore {label} failed: {type(exc).__name__}: {exc}"))

    # Restore the encrypted credential before asking the API to reload its
    # provider/client caches.  The key never leaves process memory or a journal.
    attempt("provider database row", lambda: _restore_provider_database(snapshot.database))
    attempt(
        "provider cache",
        lambda: expect(
            nano.api.put(
                "/api/settings/ai-providers/openai",
                json={"config": snapshot.provider["config"], "enabled": snapshot.provider["enabled"]},
            ),
            200,
        ),
    )

    if snapshot.model is not None:
        model = snapshot.model
        attempt(
            "available model",
            lambda: expect(
                nano.api.put(
                    f"/api/settings/available-models/{quote(snapshot.target_model_id, safe='')}",
                    json={
                        "display_name": model["display_name"],
                        "context_window": model["context_window"],
                        "input_price_per_million": model["input_price_per_million"],
                        "output_price_per_million": model["output_price_per_million"],
                        "supports_vision": model["supports_vision"],
                        "supports_function_calling": model["supports_function_calling"],
                        "deprecated": model["deprecated"],
                    },
                ),
                200,
            ),
        )

    for agent, config in sorted(snapshot.agents.items()):
        attempt(
            f"agent {agent}",
            lambda agent=agent, config=config: expect(
                nano.api.put(
                    f"/api/settings/agent-models/{agent}",
                    json={
                        "model_id": config["model_id"],
                        "max_tokens": config["max_tokens"],
                        "temperature": config["temperature"],
                        "timeout_seconds": config["timeout_seconds"],
                        "enabled": config["enabled"],
                        "reasoning_effort": config["reasoning_effort"],
                    },
                ),
                200,
            ),
        )

    if snapshot.model is None:
        attempt(
            "remove persona model",
            lambda: expect(
                nano.api.delete(f"/api/settings/available-models/{quote(snapshot.target_model_id, safe='')}"),
                200,
                404,
            ),
        )

    # The cache-refreshing PUT changes validation/timestamps; put the exact
    # snapshotted provider/model rows back after cache reloads have completed.
    attempt("exact provider database row", lambda: _restore_provider_database(snapshot.database))
    attempt("exact model database row", lambda: _restore_model_database(snapshot.database))

    def verify() -> None:
        provider = expect(nano.api.get("/api/settings/ai-providers/openai"), 200)
        assert provider == snapshot.provider, "provider public configuration was not restored"
        models = expect(nano.api.get("/api/settings/available-models/all"), 200)
        model = next((item for item in models if item.get("model_id") == snapshot.target_model_id), None)
        assert model == snapshot.model, "persona model was not restored"
        agents = expect(nano.api.get("/api/settings/agent-models"), 200)
        actual = {item["agent_id"]: item for item in agents}
        assert actual == snapshot.agents, "persona agent bindings were not restored"
        database = _database_ai_snapshot(snapshot.target_model_id)
        assert database == snapshot.database, "provider credential or master AI state was not restored"

    attempt("verification", verify)
    if failures:
        raise ExceptionGroup("persona AI configuration did not restore cleanly", failures)


def source_by_route(nano: Nano, route_key: str) -> dict[str, Any] | None:
    for source in expect(nano.api.get("/api/log-sources"), 200):
        if route_key in (source.get("match_values") or []):
            return source
    return None


def start_push_source(page: uilib.UiPage, name: str, route_key: str) -> None:
    page.goto("/ingestion/log-sources/new")
    page.wait_for({"testid": "add-feed-linear"})
    page.click({"text": "Custom source", "exact": True, "within": {"testid": "source-catalog"}})
    page.fill(uilib.field({"css": "#add-source-name"}, name))
    page.click({"testid": "source-continue"})
    page.fill(uilib.field({"testid": "feed-identifier"}, route_key))
    page.click({"testid": "details-continue"})
    page.click({"testid": "transport-hec"})
    page.click({"testid": "transport-continue"})
    page.wait_for({"testid": "issue-credential-panel"})


def issue_ingest_token(page: uilib.UiPage, label: str) -> str:
    page.fill(uilib.field({"css": "#ingest-credential-label"}, label))
    page.click({"role": "button", "name": uilib.rx("^Issue")})
    page.wait_for({"testid": "one-time-token"})
    token = page.value({"css": 'input[aria-label="Ingest token"]'})
    page.driver.register_secret(token)
    assert re.fullmatch(r"nit_[A-Za-z0-9_-]+", token), "unexpected ingest-token shape"
    return token
