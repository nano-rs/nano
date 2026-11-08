"""NAN-4941: Log Sources is the single ingestion home. The retired pages keep
working only as redirects into its tabs; a bookmark or an old deep link must
land on the page that now owns it, with its id / `add` / `cred` intact.

Explicitly SKIPPED (naming NAN-4941) on a build without the Log Sources tabs.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import parse_qs, urlsplit

import pytest

from nano_e2e import ui as uilib
from nano_e2e import ui_pull
from nano_e2e.client import Nano, expect


@pytest.fixture
def credentials(nano: Nano, mark: str) -> Iterator[dict[str, str]]:
    """One cloud credential and one connector-vendor credential to deep-link."""
    made: dict[str, str] = {}
    for key, provider, secret in (
        (
            "cloud",
            "aws_s3",
            {"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "e2e-not-a-real-secret-0001"},
        ),
        ("connector", "okta", {"API_TOKEN": "00e2e-not-a-real-token-0001"}),
    ):
        r = nano.api.post(
            "/api/credentials",
            json={"name": f"{mark}-{key}", "provider": provider, "credentials": secret, "environment": "dev"},
        )
        made[key] = expect(r, 200, 201)["id"]
    yield made
    for cid in made.values():
        nano.api.delete(f"/api/credentials/{cid}")


def _lands(page: uilib.UiPage, path: str) -> tuple[str, dict[str, list[str]]]:
    old = urlsplit(path).path
    page.goto(path)
    page.wait_url(rf"^(?!.*{re.escape(old)}(?:[?#]|$))", timeout_ms=20_000)
    u = urlsplit(page.url)
    return u.path, parse_qs(u.query)


def test_retired_ingestion_paths_redirect(
    page: uilib.UiPage, nano: Nano, credentials: dict[str, str], timeline
) -> None:
    if ui_pull.ingestion_layout(page) != ui_pull.LOG_SOURCES_TABS:
        pytest.skip("Log Sources tabs + retired-page redirects are not in this build yet (NAN-4941)")
    configs = expect(nano.api.get("/api/source-configurations"), 200)
    cfg_id = (configs if isinstance(configs, list) else configs.get("items", []))[0]["id"]

    cases = [
        ("/ingestion/source-configurations", ui_pull.CLOUD_PULL_PATH, {}),
        (f"/ingestion/source-configurations/{cfg_id}", f"/ingestion/log-sources/inputs/{cfg_id}", {}),
        ("/ingestion/credentials", ui_pull.CLOUD_PULL_PATH, {}),
        ("/ingestion/credentials?add=gcp_pubsub", ui_pull.CLOUD_PULL_PATH, {"add": ["gcp_pubsub"]}),
        ("/ingestion/credentials/new", ui_pull.CLOUD_PULL_PATH, {"add": ["aws_s3"]}),
        (
            f"/ingestion/credentials/{credentials['cloud']}",
            ui_pull.CLOUD_PULL_PATH,
            {"cred": [credentials["cloud"]]},
        ),
        (
            f"/ingestion/credentials/{credentials['connector']}",
            ui_pull.PULL_FEEDS_PATH,
            {"cred": [credentials["connector"]]},
        ),
        ("/ingestion/pull-feeds", ui_pull.PULL_FEEDS_PATH, {}),
        ("/ingestion/connector-feeds", ui_pull.PULL_FEEDS_PATH, {}),
    ]
    for old, want_path, want_query in cases:
        path, query = _lands(page, old)
        timeline.step("redirect", old=old, landed=path, query=query)
        assert path == want_path, f"{old} -> {path}, want {want_path}"
        for k, v in want_query.items():
            # `add`/`cred` may be consumed by the page once it opens the form or
            # the credential; the redirect itself must have carried them.
            assert query.get(k, v) == v, f"{old} -> {page.url}: {k}={query.get(k)}, want {v}"
        # The landing page renders its tab, not a 404.
        assert not page.count({"text": uilib.rx(r"^(404|Page not found)$")}), f"{old} landed on a 404"
