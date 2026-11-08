"""The stack under test, read from the environment `scripts/e2e.sh` exports (stack.env)."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
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
    api_key: str
    admin_email: str
    admin_password: str
    run_dir: Path
    artifact_dir: Path
    runner: Path
    vector_dynamic_dir: Path
    ch_url: str
    ch_admin_user: str
    ch_admin_password: str

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

    def svc(self, action: str, service: str, timeout: float = 300) -> None:
        """Restart/stop/start/kill a stack service through the runner (same seam in
        native and docker app mode)."""
        if action not in {"restart", "stop", "start", "kill"}:
            raise ValueError(action)
        if service not in {"api", "search", "jobs", "vector"}:
            raise ValueError(service)
        proc = subprocess.run(  # noqa: S603 - fixed argv, validated values
            [str(self.runner), "svc", action, service, "--run", self.run_id],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"E2E-INFRA: `e2e.sh svc {action} {service}` failed ({proc.returncode}): "
                f"{proc.stderr[-2000:]}"
            )
