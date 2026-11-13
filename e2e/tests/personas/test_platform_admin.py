"""Platform admin: RBAC, SSO, API keys, license state, and audit export."""

from __future__ import annotations

import csv
import io
import os
import secrets

from nano_e2e import ui as uilib
from nano_e2e.client import Http, Journal, Nano, expect, time_range
from nano_e2e.personas import (
    PLATFORM_ADMIN_PERMISSIONS,
    PLATFORM_VIEWER_PERMISSIONS,
    login_persona,
)
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually


def _api_keys(client: Nano) -> list[dict]:
    body = expect(client.api.get("/api/api-keys"), 200)
    return body if isinstance(body, list) else body.get("api_keys", body.get("items", []))


def _oidc_providers(client: Nano) -> list[dict]:
    body = expect(client.api.get("/api/settings/oidc"), 200)
    return body if isinstance(body, list) else body.get("providers", body.get("items", []))


# NAN-5238 refusal copy (nanosiem-api-lib grant_authz `admin_required` with
# nanosiem-enterprise oidc/admin.rs `SSO_TRUST_CHANGE_REASON`), surfaced
# verbatim in the provider sheet's error toast.
SSO_TRUST_REFUSAL = "Changing SSO trust settings requires administrator authority"


def _submit_oidc_provider(page: uilib.UiPage, name: str, client_id: str, client_secret: str) -> None:
    page.goto("/settings/oidc")
    page.wait_text("Add provider", exact=True, timeout_ms=60_000)
    page.click({"role": "button", "name": "Add provider", "exact": True})
    page.fill(
        uilib.field({"css": 'input[placeholder="Azure AD"]'}, name),
        uilib.field(
            {"css": 'input[placeholder="https://login.microsoftonline.com/{tenant}/v2.0"]'},
            "https://accounts.google.com",
        ),
        uilib.field({"css": 'input[placeholder="Application (client) ID"]'}, client_id),
        uilib.field({"css": 'input[placeholder="Client secret value"]'}, client_secret, secret=True),
    )
    page.click({"role": "button", "name": "Create provider", "exact": True})


def test_platform_admin_journey(
    stack: Stack,
    nano: Nano,
    mark: str,
    ui: uilib.Driver,
    artifact_dir,
    timeline,
) -> None:
    edition = os.environ["E2E_EDITION"]
    key_name = f"persona-platform-{mark[-8:]}"
    provider_name = f"Persona SSO {mark[-8:]}"

    # A read-only platform viewer can inspect keys but cannot mint delegated
    # credentials. The deep link must be reachable with apikeys:view alone.
    with login_persona(
        stack, nano, ui, artifact_dir, "platform-viewer", PLATFORM_VIEWER_PERMISSIONS
    ) as viewer:
        assert set(viewer.permissions) == set(PLATFORM_VIEWER_PERMISSIONS)
        viewer.page.goto("/settings/access-control?tab=api-keys")
        viewer.page.wait_text("API Keys", exact=True)
        assert viewer.page.count({"css": 'button[title="New API key"]'}) == 0
        forbidden = viewer.client.api.post(
            "/api/api-keys",
            json={"name": f"forbidden-{mark[-8:]}", "permissions": ["search:view"]},
        )
        assert forbidden.status_code == 403, forbidden.text[:1000]
        timeline.step("viewer API-key boundary", ui="hidden", api=forbidden.status_code)

    with login_persona(
        stack, nano, ui, artifact_dir, "platform-admin", PLATFORM_ADMIN_PERMISSIONS
    ) as platform:
        assert set(platform.permissions) == set(PLATFORM_ADMIN_PERMISSIONS)
        page = platform.page

        # API key creation is a real browser flow with an explicit two-scope
        # credential. The reveal-once value is secret-registered immediately.
        page.goto("/settings/access-control?tab=api-keys")
        page.wait_for({"css": 'button[title="New API key"]'})
        page.click({"css": 'button[title="New API key"]'})
        page.wait_text("New API key", exact=True)
        page.fill(uilib.field({"css": 'input[placeholder="e.g. ci-deploy-robot"]'}, key_name))
        page.click({"role": "button", "name": uilib.rx(r"^Custom")})
        page.fill(uilib.field({"placeholder": "Filter scopes…"}, "search:"))
        page.click({"role": "checkbox", "name": uilib.rx(r"^search:view\b")})
        page.click({"role": "checkbox", "name": uilib.rx(r"^search:execute\b")})
        page.click({"role": "button", "name": "Create key", "exact": True})
        page.wait_text("New API key — copy it now", exact=True)
        created_key = eventually(
            lambda: next((item for item in _api_keys(platform.client) if item.get("name") == key_name), None),
            timeout=30,
            interval=0.2,
            desc="browser-created API key",
        )
        assert created_key is not None
        platform.cleanup.register_http(
            f"API key {created_key['id']}",
            lambda: platform.client.api.delete(f"/api/api-keys/{created_key['id']}"),
        )
        # Read the reveal-once value from the card itself. Browser clipboard
        # state is not a reliable transport in headless Chrome even when the
        # product's copy action succeeds.
        revealed = eventually(
            lambda: page.texts({"testid": "api-key-reveal"}),
            timeout=5,
            interval=0.1,
            desc="revealed API key in the creation card",
            ok=lambda values: len(values) == 1 and bool(values[0].strip()),
        )
        secret = revealed[0].strip()
        page.driver.register_secret(secret)
        assert len(secret) >= 43 and all(char.isalnum() or char in "-_" for char in secret), (
            "unexpected API-key shape"
        )
        assert set(created_key["permissions"]) == {"search:view", "search:execute"}, created_key

        keyed_search = Http(
            stack.search_url,
            {"X-API-Key": secret},
            Journal(artifact_dir / "platform-key-search.jsonl"),
        )
        keyed_api = Http(
            stack.api_url,
            {"X-API-Key": secret},
            Journal(artifact_dir / "platform-key-api.jsonl"),
        )
        try:
            allowed = expect(
                keyed_search.post(
                    "/api/search",
                    json={
                        "query": '"persona-platform-key-probe"',
                        "time_range": time_range(),
                        "limit": 1,
                        "skip_histogram": True,
                        "skip_field_stats": True,
                        "use_cache": False,
                    },
                ),
                200,
            )
            denied = keyed_api.get("/api/users")
            assert denied.status_code == 403, denied.text[:1000]
            timeline.step(
                "scoped API key",
                key=created_key["id"],
                search=allowed.get("total_count", 0),
                users=denied.status_code,
            )
        finally:
            keyed_search.close()
            keyed_api.close()

        if edition == "enterprise":
            # NAN-5238: creating (enabling) an SSO provider is a trust change and
            # needs administrator authority -- every catalog permission -- not
            # just settings:system. The subset platform-admin persona must see
            # the server's refusal in the browser and leave nothing behind.
            oidc_secret = "e2e-oidc-" + secrets.token_hex(16)
            page.driver.register_secret(oidc_secret)
            _submit_oidc_provider(page, provider_name, f"client-{mark[-8:]}", oidc_secret)
            page.wait_text(SSO_TRUST_REFUSAL, exact=False, timeout_ms=30_000)
            assert not any(item.get("name") == provider_name for item in _oidc_providers(nano)), (
                "subset platform-admin created an SSO provider"
            )
            timeline.step("SSO trust boundary", persona="platform-admin", ui="refused")

            # A full administrator creates the enabled provider through the same
            # browser flow. The dummy secret is scrubbed from all artifacts;
            # cleanup is registered by concrete id.
            admin_page = uilib.UiPage.open(ui, artifact_dir / "ui-admin-sso", name="admin:sso")
            admin_failed = True
            try:
                uilib.login(admin_page, stack.admin_email, stack.admin_password)
                _submit_oidc_provider(admin_page, provider_name, f"client-{mark[-8:]}", oidc_secret)
                admin_page.wait_text(provider_name, exact=True, timeout_ms=60_000)
                admin_failed = False
            finally:
                admin_page.finish(admin_failed)
                if admin_failed:
                    # The POST may have landed before the UI wait failed; never
                    # leak an enabled provider onto the stack.
                    for item in _oidc_providers(nano):
                        if item.get("name") == provider_name:
                            nano.api.delete(f"/api/settings/oidc/{item['id']}")
            provider = eventually(
                lambda: next(
                    (item for item in _oidc_providers(nano) if item.get("name") == provider_name),
                    None,
                ),
                timeout=30,
                interval=0.2,
                desc="browser-created OIDC provider",
            )
            assert provider is not None
            platform.cleanup.register_http(
                f"OIDC provider {provider['id']}",
                lambda: nano.api.delete(f"/api/settings/oidc/{provider['id']}"),
            )
            assert provider["enabled"] is True
            assert provider["issuer"] == "https://accounts.google.com"
            timeline.step("SSO provider configured", provider=provider["id"], enabled=True, actor="admin")
        else:
            capabilities = expect(nano.api.get("/api/capabilities"), 200)["capabilities"]
            assert capabilities["sso"] is False
            page.goto("/settings/oidc")
            page.wait_text("Single sign-on is not available", exact=True)
            assert page.count({"role": "button", "name": "Add provider", "exact": True}) == 0
            missing = platform.client.api.get("/api/settings/oidc")
            assert missing.status_code == 404, missing.text[:1000]
            timeline.step("SSO build boundary", capability=False, ui="disabled", api=404)

        # License status is edition-concrete too: the enterprise surface and
        # API report the same live state; open has neither actionable control
        # nor a backing route.
        page.goto("/settings/license")
        if edition == "enterprise":
            status = expect(platform.client.api.get("/api/license"), 200)
            page.wait_text("Offline License", exact=True)
            page.wait_text(str(status.get("runtime_state") or status["state"]), exact=True, timeout_ms=30_000)
            assert page.count({"role": "button", "name": "Refresh", "exact": True}) == 1
            assert page.count({"role": "button", "name": uilib.rx("Upload license|Upload renewal")}) == 1
            timeline.step("license status", state=status.get("runtime_state") or status["state"])
        else:
            page.wait_text("Available in nano paid plans", exact=True)
            assert page.count({"role": "button", "name": "Refresh", "exact": True}) == 0
            assert page.count({"role": "button", "name": uilib.rx("Upload license|Upload renewal")}) == 0
            missing = platform.client.api.get("/api/license")
            assert missing.status_code == 404, missing.text[:1000]
            timeline.step("license build boundary", ui="absent", api=404)

        # Audit export is the last proof so it includes the browser-created key
        # and, in enterprise, the OIDC provider. Parse the downloaded server CSV
        # rather than merely checking that a button clicked.
        expected_actions = {"apikey_created"}
        if edition == "enterprise":
            expected_actions.add("oidc_provider_created")
        audit_rows = eventually(
            lambda: expect(platform.client.api.get("/api/audit", params={"limit": 200}), 200)["logs"],
            timeout=60,
            interval=3,
            desc="platform changes in audit",
            ok=lambda rows: expected_actions.issubset({row.get("action") for row in rows}),
        )
        page.goto("/settings/audit")
        page.wait_text(key_name, exact=False, timeout_ms=60_000)
        filename, contents = page.download({"role": "button", "name": "Export all"}, timeout_ms=60_000)
        exported = list(csv.DictReader(io.StringIO(contents)))
        assert filename == "audit_logs.csv", filename
        exported_actions = {row["action"] for row in exported}
        assert expected_actions.issubset(exported_actions), exported_actions
        assert any(row.get("resource_name") == key_name for row in exported), key_name
        if edition == "enterprise":
            assert any(row.get("resource_name") == provider_name for row in exported), provider_name
        timeline.step(
            "audit exported",
            rows=len(exported),
            actions=sorted(expected_actions),
            api_rows=len(audit_rows),
        )
        platform.checkpoint("sso-api-key-license-audit")
