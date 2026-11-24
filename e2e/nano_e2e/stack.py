"""The stack under test, read from the environment `scripts/e2e.sh` exports (stack.env)."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


class StackNotConfigured(RuntimeError):
    """stack.env was not loaded (run the scenarios through scripts/e2e.sh)."""


def _req(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise StackNotConfigured(
            f"{name} is not set. Run scenarios with `scripts/e2e.sh run <suite>`, or export a live "
            f'stack\'s env first: `set -a; . "$(scripts/e2e.sh env)"; set +a`.'
        )
    return value


@dataclass(frozen=True)
class Stack:
    run_id: str
    project: str
    edition: str
    app_mode: str
    api_url: str
    search_url: str
    jobs_url: str
    edge_url: str
    ingest_url: str
    hec_url: str
    vector_http_url: str
    otlp_http_url: str
    vector_metrics_url: str
    api_key: str = field(repr=False)
    admin_email: str
    admin_password: str = field(repr=False)
    run_dir: Path
    artifact_dir: Path
    runner: Path
    vector_dynamic_dir: Path
    ch_url: str
    ch_admin_user: str
    ch_admin_password: str = field(repr=False)
    # "own": a throwaway stack the runner brought up. "existing": a stack it did
    # not create (nano_e2e.target, NAN-5586): no restarts, no ClickHouse admin.
    target: str = "own"

    @classmethod
    def existing(cls) -> Stack:
        """The `--target existing` stack: URLs and the acting user from the
        environment `nano_e2e.target.load_env` and the runner exported."""
        api = os.environ.get("E2E_TARGET_API_URL", "http://localhost:3000").rstrip("/")
        web = os.environ.get("E2E_TARGET_WEB_URL", "http://localhost:5173").rstrip("/")
        hec = os.environ.get("E2E_TARGET_HEC_URL", "http://127.0.0.1:8088").rstrip("/")
        run_dir = Path(_req("E2E_RUN_DIR"))
        return cls(
            run_id=_req("E2E_RUN_ID"),
            project="existing",
            edition=os.environ.get("E2E_EDITION", "enterprise"),
            app_mode="existing",
            api_url=api,
            search_url=os.environ.get("E2E_TARGET_SEARCH_URL", "http://localhost:3002").rstrip("/"),
            jobs_url="",
            edge_url=web,
            ingest_url=hec,
            hec_url=hec,
            vector_http_url="",
            otlp_http_url="",
            vector_metrics_url="",
            api_key=_req("NANOSIEM_API_KEY"),
            admin_email=_req("NANO_ADMIN_EMAIL"),
            admin_password=_req("NANO_ADMIN_PASSWORD"),
            run_dir=run_dir,
            artifact_dir=Path(_req("E2E_ARTIFACT_DIR")),
            runner=Path(os.environ.get("E2E_RUNNER", "")),
            vector_dynamic_dir=run_dir / "no-vector-dir",
            ch_url="",
            ch_admin_user="",
            ch_admin_password="",
            target="existing",
        )

    @classmethod
    def from_env(cls) -> Stack:
        return cls(
            run_id=_req("E2E_RUN_ID"),
            project=_req("E2E_PROJECT"),
            edition=os.environ.get("E2E_EDITION", "enterprise"),
            app_mode=os.environ.get("E2E_APP_MODE", "native"),
            api_url=_req("NANOSIEM_API_URL").rstrip("/"),
            search_url=_req("NANOSIEM_SEARCH_URL").rstrip("/"),
            jobs_url=_req("NANOSIEM_JOBS_URL").rstrip("/"),
            edge_url=_req("NANOSIEM_EDGE_URL").rstrip("/"),
            ingest_url=os.environ.get("NANOSIEM_INGEST_URL", _req("NANOSIEM_EDGE_URL")).rstrip("/"),
            hec_url=_req("NANOSIEM_HEC_URL").rstrip("/"),
            vector_http_url=_req("NANOSIEM_VECTOR_HTTP_URL").rstrip("/"),
            otlp_http_url=os.environ.get("NANOSIEM_OTLP_HTTP_URL", "").rstrip("/"),
            vector_metrics_url=_req("NANOSIEM_VECTOR_METRICS_URL"),
            api_key=_req("NANOSIEM_API_KEY"),
            admin_email=_req("NANO_ADMIN_EMAIL"),
            admin_password=_req("NANO_ADMIN_PASSWORD"),
            run_dir=Path(_req("E2E_RUN_DIR")),
            artifact_dir=Path(_req("E2E_ARTIFACT_DIR")),
            runner=Path(_req("E2E_RUNNER")),
            vector_dynamic_dir=Path(_req("E2E_VECTOR_DYNAMIC_DIR")),
            ch_url=_req("CLICKHOUSE_URL"),
            ch_admin_user=os.environ.get("CLICKHOUSE_ADMIN_USER", "nanosiem_admin"),
            ch_admin_password=os.environ.get("CLICKHOUSE_ADMIN_PASSWORD", ""),
        )

    @property
    def rendered_source_configs(self) -> Path:
        """Where the api writes deployed source-config TOML (Vector's dynamic dir)."""
        return self.vector_dynamic_dir / "sources" / "configs"

    def svc(
        self, action: str, service: str, timeout: float = 300, env: dict[str, str] | None = None
    ) -> None:
        """Restart/stop/start/kill a stack service through the runner (same seam in
        native and docker app mode). `env` applies for this call only: runner
        knobs (E2E_*, e.g. E2E_SEARCH_CH_LAUNCH=app-user, native mode) and app
        settings. Native processes inherit app settings; in docker/image mode
        the runner recreates the container with them (E2E_SVC_APP_ENV names
        them, NAN-5878), and a later call without them restores the template.
        Returns once the service answers its health check."""
        if self.target == "existing":
            raise RuntimeError("E2E-INFRA: an existing target's services are not the harness's to restart")
        if action not in {"restart", "stop", "start", "kill"}:
            raise ValueError(action)
        if service not in {"api", "search", "jobs", "vector"}:
            raise ValueError(service)
        app_keys = [k for k in (env or {}) if not k.startswith("E2E_")]
        for k in app_keys:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
                raise ValueError(f"svc env name {k!r} is not a plain identifier")
        proc = subprocess.run(  # noqa: S603 - fixed argv, validated values
            [str(self.runner), "svc", action, service, "--run", self.run_id],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={
                **os.environ,
                **(env or {}),
                "E2E_SVC_APP_ENV": " ".join(app_keys),
            },
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"E2E-INFRA: `e2e.sh svc {action} {service}` failed ({proc.returncode}): "
                f"{proc.stderr[-2000:]}"
            )
