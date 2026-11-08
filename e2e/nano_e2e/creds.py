"""Cloud test credentials (real AWS / GCP / Azure; no emulators, per Dan 11-03).

The runner puts them in the pytest process environment from
`doppler run -p nano-e2e -c dev` or ~/.nan2361-secrets/e2e.env (0600). They are
never written to the repo, logs or artifacts. Each loader returns None plus a
reason when a variable is missing, so cloud scenarios SKIP with that reason.
See e2e/README.md for the variables and the least-privilege permissions.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def _missing(names: list[str]) -> list[str]:
    return [n for n in names if not _env(n)]


@dataclass(frozen=True)
class AwsCreds:
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    region: str
    # Optional second key pair for the rotate step (else rotate re-submits the
    # same pair, which still proves the rotate + redeploy path).
    rotate_access_key_id: str = field(default="", repr=False)
    rotate_secret_access_key: str = field(default="", repr=False)


@dataclass(frozen=True)
class GcpCreds:
    project: str
    # A service-account key, or (when org policy blocks SA keys) gcloud
    # application-default credentials of type authorized_user.
    sa_json: str = field(repr=False)
    rotate_sa_json: str = field(default="", repr=False)

    @property
    def kind(self) -> str:
        return json.loads(self.sa_json).get("type", "")

    @property
    def sa_email(self) -> str:
        return json.loads(self.sa_json).get("client_email", "")


@dataclass(frozen=True)
class AzureCreds:
    namespace: str  # bare name or <ns>.servicebus.windows.net
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = field(default="", repr=False)
    subscription_id: str = ""
    resource_group: str = ""
    eventhub_name: str = ""  # optional pre-provisioned hub (a per-run consumer group is still created)
    storage_account: str = ""

    @property
    def namespace_host(self) -> str:
        ns = self.namespace
        return ns if "." in ns else f"{ns}.servicebus.windows.net"

    @property
    def namespace_name(self) -> str:
        return self.namespace.split(".", 1)[0]

    @property
    def has_sp(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)


def aws() -> tuple[AwsCreds | None, str]:
    need = ["NANO_E2E_AWS_ACCESS_KEY_ID", "NANO_E2E_AWS_SECRET_ACCESS_KEY", "NANO_E2E_AWS_REGION"]
    if miss := _missing(need):
        return None, f"AWS credentials absent ({', '.join(miss)}); see e2e/README.md"
    return (
        AwsCreds(
            access_key_id=_env(need[0]),
            secret_access_key=_env(need[1]),
            region=_env(need[2]),
            rotate_access_key_id=_env("NANO_E2E_AWS_ROTATE_ACCESS_KEY_ID"),
            rotate_secret_access_key=_env("NANO_E2E_AWS_ROTATE_SECRET_ACCESS_KEY"),
        ),
        "",
    )


def _sa_json(value: str) -> str:
    """NANO_E2E_GCP_SA_JSON: a path to the key file, raw JSON, or base64 JSON."""
    if not value:
        return ""
    if value.lstrip().startswith("{"):
        return value
    p = Path(value).expanduser()
    if p.is_file():
        return p.read_text()
    if value.startswith(("/", "~", ".")):
        raise ValueError(
            f"credential file not found: {p} (for ADC run `gcloud auth application-default login`)"
        )
    try:
        decoded = base64.b64decode(value, validate=True).decode()
    except ValueError as exc:
        raise ValueError("NANO_E2E_GCP_SA_JSON is neither a file path, JSON nor base64 JSON") from exc
    return decoded


def gcp() -> tuple[GcpCreds | None, str]:
    """NANO_E2E_GCP_SA_JSON (service-account key) or NANO_E2E_GCP_ADC (gcloud
    application_default_credentials.json, authorized_user) + NANO_E2E_GCP_PROJECT."""
    if not _env("NANO_E2E_GCP_PROJECT") or not (_env("NANO_E2E_GCP_SA_JSON") or _env("NANO_E2E_GCP_ADC")):
        return None, (
            "GCP credentials absent (need NANO_E2E_GCP_PROJECT + NANO_E2E_GCP_SA_JSON or NANO_E2E_GCP_ADC); "
            "see e2e/README.md"
        )
    try:
        sa = _sa_json(_env("NANO_E2E_GCP_SA_JSON") or _env("NANO_E2E_GCP_ADC"))
        if json.loads(sa).get("type") not in ("service_account", "authorized_user"):
            return None, "GCP credentials must be a service_account key or authorized_user ADC"
        rotate = _sa_json(_env("NANO_E2E_GCP_ROTATE_SA_JSON"))
    except (ValueError, OSError) as exc:
        return None, f"GCP credentials unusable: {exc}"
    return GcpCreds(project=_env("NANO_E2E_GCP_PROJECT"), sa_json=sa, rotate_sa_json=rotate), ""


def azure() -> tuple[AzureCreds | None, str]:
    """Service principal + namespace + resource group + Blob storage account.

    Every run gets its OWN consumer group and checkpoint container (created via
    ARM / Blob with the SP), so concurrent runs (e.g. the X64 and ARM64 CI legs)
    can never steal each other's events or checkpoints. Modes that cannot
    isolate (connection-string only, pre-provisioned checkpoint container) are
    refused rather than shared."""
    sp = ["NANO_E2E_AZURE_TENANT_ID", "NANO_E2E_AZURE_CLIENT_ID", "NANO_E2E_AZURE_CLIENT_SECRET"]
    need = [
        *sp,
        "NANO_E2E_AZURE_EVENTHUBS_NAMESPACE",
        "NANO_E2E_AZURE_RESOURCE_GROUP",
        "NANO_E2E_AZURE_STORAGE_ACCOUNT",
    ]
    if miss := _missing(need):
        hint = (
            " (connection-string-only mode is not supported: it cannot create the per-run consumer group "
            "and checkpoint container that keep concurrent runs isolated)"
            if _env("NANO_E2E_AZURE_EVENTHUB_CONNECTION_STRING")
            else ""
        )
        return None, f"Azure credentials absent ({', '.join(miss)}){hint}; see e2e/README.md"
    creds = AzureCreds(
        namespace=_env("NANO_E2E_AZURE_EVENTHUBS_NAMESPACE"),
        tenant_id=_env(sp[0]),
        client_id=_env(sp[1]),
        client_secret=_env(sp[2]),
        subscription_id=_env("NANO_E2E_AZURE_SUBSCRIPTION_ID"),
        resource_group=_env("NANO_E2E_AZURE_RESOURCE_GROUP"),
        eventhub_name=_env("NANO_E2E_AZURE_EVENTHUB_NAME"),
        storage_account=_env("NANO_E2E_AZURE_STORAGE_ACCOUNT"),
    )
    if not creds.subscription_id:
        # The SP is scoped to one namespace; its single visible subscription is the one.
        sub = _discover_azure_subscription(creds)
        if not sub:
            return None, "Azure: subscription unknown (set NANO_E2E_AZURE_SUBSCRIPTION_ID)"
        creds = replace(creds, subscription_id=sub)
    return creds, ""


def _discover_azure_subscription(creds: AzureCreds) -> str:
    """The SP's only visible subscription (ARM), or "" if none/ambiguous/unreachable."""
    import httpx  # local: creds stays importable without network deps in use

    try:
        tok = httpx.post(
            f"https://login.microsoftonline.com/{creds.tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": creds.client_id,
                "client_secret": creds.client_secret,
                "scope": "https://management.azure.com/.default",
            },
            timeout=30,
        ).json()["access_token"]
        subs = httpx.get(
            "https://management.azure.com/subscriptions?api-version=2022-12-01",
            headers={"Authorization": f"Bearer {tok}"},
            timeout=30,
        ).json()
    except (httpx.HTTPError, KeyError, ValueError):
        return ""
    ids = [s["subscriptionId"] for s in subs.get("value", [])]
    return ids[0] if len(ids) == 1 else ""


# ---------------------------------------------------------------- connector tenants (NAN-4961)
# Real vendor tenants for the connector pull feeds (suite `connectors`). Same
# sources and rules as the cloud credentials above; each loader returns None
# plus the reason, so the scenario SKIPs naming what is missing.


@dataclass(frozen=True)
class EntraCreds:
    """App registration `nano-e2e-entra-connector` in the Azure e2e tenant:
    Graph application permissions User.Read.All, GroupMember.Read.All and
    RoleManagement.Read.Directory (admin-consented). Two client secrets so the
    rotate step swaps to a genuinely different secret."""

    tenant_id: str
    client_id: str
    client_secret: str = field(repr=False)
    rotate_client_secret: str = field(default="", repr=False)


@dataclass(frozen=True)
class OktaCreds:
    """An Okta developer org: OKTA_ORG_URL (https://dev-NNN.okta.com) and an
    SSWS API token minted by its super admin (the scenario creates and deletes
    one throwaway user for fresh System Log events; the feeds themselves only
    read). OKTA_ROTATE_API_TOKEN (a second token) is optional; without it the
    rotate step re-submits the same token as a new version."""

    domain: str
    api_token: str = field(repr=False)
    rotate_api_token: str = field(default="", repr=False)


@dataclass(frozen=True)
class GwsCreds:
    """A service-account key with domain-wide delegation for
    admin.reports.audit.readonly, and the super-admin it impersonates."""

    sa_json: str = field(repr=False)
    admin_email: str
    streams: str = "login,admin,token"

    @property
    def client_email(self) -> str:
        return json.loads(self.sa_json).get("client_email", "")


@dataclass(frozen=True)
class SlackCreds:
    """A user token with the `admin` scope (team.accessLogs needs a paid plan
    that offers that scope: Business+ or Enterprise Grid; NAN-2200)."""

    user_token: str = field(repr=False)
    team_id: str = ""


def entra() -> tuple[EntraCreds | None, str]:
    need = ["NANO_E2E_ENTRA_TENANT_ID", "NANO_E2E_ENTRA_CLIENT_ID", "NANO_E2E_ENTRA_CLIENT_SECRET"]
    if miss := _missing(need):
        return None, f"Entra app registration absent ({', '.join(miss)}); see e2e/README.md (NAN-4961)"
    return (
        EntraCreds(
            tenant_id=_env(need[0]),
            client_id=_env(need[1]),
            client_secret=_env(need[2]),
            rotate_client_secret=_env("NANO_E2E_ENTRA_ROTATE_CLIENT_SECRET"),
        ),
        "",
    )


def okta() -> tuple[OktaCreds | None, str]:
    if miss := _missing(["OKTA_ORG_URL", "OKTA_API_TOKEN"]):
        return None, (
            f"Okta developer org absent ({', '.join(miss)}): add OKTA_ORG_URL + OKTA_API_TOKEN "
            "(an SSWS token minted by the dev org's super admin: the scenario creates and deletes one "
            "throwaway user to generate System Log activity) to ~/.nan2361-secrets/e2e.env (NAN-4961)"
        )
    from urllib.parse import urlparse

    raw = _env("OKTA_ORG_URL")
    host = (urlparse(raw).hostname if "://" in raw else raw.split("/", 1)[0]) or ""
    host = host.lower()
    if host.endswith("-admin.okta.com"):  # the admin console URL; the API lives on the org host
        host = host.removesuffix("-admin.okta.com") + ".okta.com"
    if not host:
        return None, "OKTA_ORG_URL is not a URL or host name"
    return (
        OktaCreds(domain=host, api_token=_env("OKTA_API_TOKEN"), rotate_api_token=_env("OKTA_ROTATE_API_TOKEN")),
        "",
    )


def gws() -> tuple[GwsCreds | None, str]:
    if miss := _missing(["NANO_E2E_GWS_SA_JSON", "NANO_E2E_GWS_ADMIN_EMAIL"]):
        return None, (
            f"Google Workspace credential absent ({', '.join(miss)}): a service-account key with domain-wide "
            "delegation for admin.reports.audit.readonly + the super-admin to impersonate (NAN-4961)"
        )
    try:
        sa = _sa_json(_env("NANO_E2E_GWS_SA_JSON"))
        if json.loads(sa).get("type") != "service_account":
            return None, "NANO_E2E_GWS_SA_JSON must be a service_account key"
    except (ValueError, OSError) as exc:
        return None, f"Google Workspace key unusable: {exc}"
    return (
        GwsCreds(
            sa_json=sa,
            admin_email=_env("NANO_E2E_GWS_ADMIN_EMAIL"),
            streams=_env("NANO_E2E_GWS_STREAMS") or "login,admin,token",
        ),
        "",
    )


def slack() -> tuple[SlackCreds | None, str]:
    if miss := _missing(["NANO_E2E_SLACK_USER_TOKEN"]):
        return None, (
            f"Slack credential absent ({', '.join(miss)}): team.accessLogs needs a user token with the `admin` "
            "scope, which only Business+ / Enterprise Grid offer (nano's workspace is Pro; NAN-2200) (NAN-4961)"
        )
    return SlackCreds(user_token=_env("NANO_E2E_SLACK_USER_TOKEN"), team_id=_env("NANO_E2E_SLACK_TEAM_ID")), ""
