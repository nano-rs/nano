"""Real vendor tenants for connector pull feeds (NAN-4961): what the vendor
itself says, read with the same credential the feed uses, so every scenario
compares nano's result with the tenant's truth instead of a hard-coded list.

Read-only against every tenant except the Okta developer org, where
`OktaTenant.generate_activity` creates and deletes one throwaway user
(`nano-e2e-<run>@example.invalid`) so the System Log has fresh events in the
feed's first window. The Google Workspace and Slack tenants are nano's own
production org: nothing here writes to them.

Secrets never leave this process: tokens are held in memory, never logged,
and error messages carry status codes and vendor error codes only.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from nano_e2e.creds import EntraCreds, OktaCreds

GRAPH = "https://graph.microsoft.com/v1.0"


class VendorError(AssertionError):
    """The vendor refused a harness call (E2E-INFRA: credentials or tenant)."""


def _check(resp: httpx.Response, what: str) -> Any:
    if resp.status_code >= 300:
        code = ""
        try:
            body = resp.json()
            code = (body.get("error") or {}).get("code", "") if isinstance(body.get("error"), dict) else ""
            code = code or str(body.get("errorCode") or body.get("error") or "")
        except ValueError:
            pass
        raise VendorError(f"{what}: vendor answered {resp.status_code} {code}".strip())
    return resp.json() if resp.content else None


# ---------------------------------------------------------------- Entra (Graph)
@dataclass
class EntraDirectory:
    creds: EntraCreds
    _token: str = field(default="", repr=False)

    def _bearer(self) -> str:
        if not self._token:
            body = _check(
                httpx.post(
                    f"https://login.microsoftonline.com/{self.creds.tenant_id}/oauth2/v2.0/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.creds.client_id,
                        "client_secret": self.creds.client_secret,
                        "scope": "https://graph.microsoft.com/.default",
                    },
                    timeout=30,
                ),
                "Entra token",
            )
            self._token = body["access_token"]
        return self._token

    def _all(self, url: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        while url:
            body = _check(
                httpx.get(url, headers={"Authorization": f"Bearer {self._bearer()}"}, timeout=60), "Graph list"
            )
            out.extend(body.get("value") or [])
            url = body.get("@odata.nextLink") or ""
        return out

    def users(self) -> dict[str, dict[str, Any]]:
        """id -> user (the fields the spec maps)."""
        sel = "id,userPrincipalName,mail,displayName,department,jobTitle,accountEnabled,userType"
        return {u["id"]: u for u in self._all(f"{GRAPH}/users?$select={sel}&$top=999")}

    def groups(self) -> dict[str, dict[str, Any]]:
        return {g["id"]: g for g in self._all(f"{GRAPH}/groups?$select=id,displayName&$top=999")}

    def group_user_members(self, group_id: str) -> set[str]:
        """Transitive USER members (what the spec's groups stream emits)."""
        return {
            m["id"]
            for m in self._all(f"{GRAPH}/groups/{group_id}/transitiveMembers/microsoft.graph.user?$select=id&$top=999")
        }

    def role_user_members(self) -> dict[str, set[str]]:
        """'role:<display name>' -> user ids holding the ACTIVATED role."""
        out: dict[str, set[str]] = {}
        for r in self._all(f"{GRAPH}/directoryRoles?$select=id,displayName"):
            users = {
                m["id"]
                for m in self._all(f"{GRAPH}/directoryRoles/{r['id']}/members?$select=id")
                if m.get("@odata.type") == "#microsoft.graph.user"
            }
            if users:
                out[f"role:{r['displayName']}"] = users
        return out


# ---------------------------------------------------------------- Okta
@dataclass
class OktaTenant:
    creds: OktaCreds

    @property
    def base(self) -> str:
        return f"https://{self.creds.domain}"

    def _h(self) -> dict[str, str]:
        return {"Authorization": f"SSWS {self.creds.api_token}", "Accept": "application/json"}

    def _all(self, url: str, params: dict[str, str] | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        while url:
            resp = httpx.get(url, headers=self._h(), params=params, timeout=60)
            out.extend(_check(resp, "Okta list") or [])
            url = resp.links.get("next", {}).get("url", "")
            params = None
        return out

    def users(self) -> dict[str, dict[str, Any]]:
        every = " or ".join(
            f'status eq "{s}"'
            for s in (
                "STAGED",
                "PROVISIONED",
                "ACTIVE",
                "RECOVERY",
                "PASSWORD_EXPIRED",
                "LOCKED_OUT",
                "SUSPENDED",
                "DEPROVISIONED",
            )
        )
        return {u["id"]: u for u in self._all(f"{self.base}/api/v1/users", {"limit": "200", "search": every})}

    def groups(self) -> dict[str, dict[str, Any]]:
        return {g["id"]: g for g in self._all(f"{self.base}/api/v1/groups", {"limit": "200"})}

    def group_members(self, group_id: str) -> set[str]:
        return {u["id"] for u in self._all(f"{self.base}/api/v1/groups/{group_id}/users", {"limit": "200"})}

    def logs(self, since_iso: str, until_iso: str) -> list[dict[str, Any]]:
        return self._all(
            f"{self.base}/api/v1/logs",
            {"since": since_iso, "until": until_iso, "sortOrder": "ASCENDING", "limit": "1000"},
        )

    def generate_activity(self, tag: str) -> dict[str, str]:
        """Create, deactivate and delete one throwaway user (dev org only).
        Emits user.lifecycle.create / .activate / .deactivate / .delete (User
        Management, OCSF 3007) and returns their identifiers for matching."""
        login = f"nano-e2e-{tag}-{secrets.token_hex(3)}@example.invalid"
        user = _check(
            httpx.post(
                f"{self.base}/api/v1/users",
                params={"activate": "true"},
                headers={**self._h(), "Content-Type": "application/json"},
                json={"profile": {"firstName": "nano", "lastName": f"e2e {tag}", "email": login, "login": login}},
                timeout=60,
            ),
            "Okta create user",
        )
        uid = user["id"]
        for _ in range(2):  # first DELETE deactivates, the second deletes
            r = httpx.delete(f"{self.base}/api/v1/users/{uid}", headers=self._h(), timeout=60)
            if r.status_code not in (200, 204, 404):
                _check(r, "Okta delete user")
            time.sleep(1)
        return {"user_id": uid, "login": login}
