# ruff: noqa: E501 - prose and name vocabularies read better unwrapped
"""The realistic seed profile's CONTENT (NAN-5764): what a lived-in install
holds, generated from a fixed seed. Pure: no I/O, no clock, no run id.

UI overflow bugs (NAN-5758, NAN-5759) shipped because e2e stacks were nearly
empty, with short names. This plan holds what a real SOC accumulates:

- OCSF events (Authentication 3002, Network Activity 4001, Process Activity
  1007) from hundreds of hosts and users, including unicode, apostrophes and
  very long UPNs / FQDNs;
- log sources of every ingest method, several each, with long and unicode
  names; one deleted;
- detection rules (snake_case names in the dedicated "Automated" folder, never
  a display title, never Uncategorized) in every mode, with many tags; some
  archived, some imported and then deleted, a few that fire real alerts;
- cases with long titles, unicode, up to the 32-tag limit, in every status;
  some deleted;
- hunts with long titles and subtitles and many tags, a profile draft, an
  archived hunt, and findings with long narratives;
- SOAR: every catalog pack installed, manual flows whose runs leave 20+
  pending approvals, some case-linked;
- dashboards with long names.

Every name is stable (`rs5764` prefix, no run id), so `realistic_seed.apply`
can find what an earlier run already made and only add what is missing.
Nothing here is UDM: events are OCSF objects, queries use OCSF field names.
"""

from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass, field
from typing import Any

SEED = 5764
KEY = "rs5764"  # every seeded object's name carries it (stable across runs)
FOLDER = "Automated"  # scripts never use Uncategorized or display titles
PRODUCT = "nano-e2e-realistic"
LANE = f"{KEY}_fleet_ocsf_endpoint_and_identity_telemetry"  # the ingesting source's route key
# A schedule that never comes due during a run (once a year): seeded rules
# only fire when the seed triggers them.
IDLE_CRON = "0 0 1 1 *"

# Minimums the plan must meet (the issue's list); selftest/test_realistic_seed.py.
MIN_HOSTS = 400
MIN_USERS = 250
MIN_APPROVALS = 20
MIN_CASE_LINKED_APPROVALS = 6
MIN_LONG = 120  # characters: a "long" title / name
SNAKE = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
# The case tag contract (the API refuses anything else): unicode tags stay on rules.
CASE_TAG = re.compile(r"^[a-z0-9_.:-]{1,48}$")


# ---------------------------------------------------------------- specs
@dataclass(frozen=True)
class SourceSpec:
    name: str
    method: str  # log-source source_type (ingest method)
    route_key: str
    description: str
    vendor: str
    product: str
    active: bool = False  # published + receives the seeded events (only the lane)
    deleted: bool = False


@dataclass(frozen=True)
class RuleSpec:
    name: str
    description: str
    query: str
    severity: str
    mode: str  # staging | live | alerting
    tags: tuple[str, ...]
    techniques: tuple[str, ...]  # preferred ATT&CK ids; only those the stack's catalog has are sent
    archived: bool = False
    imported_then_deleted: bool = False
    fire: bool = False  # triggered once so it raises real alerts


@dataclass(frozen=True)
class CaseSpec:
    title: str
    description: str
    severity: str
    tags: tuple[str, ...]
    status: str  # open | in_progress | resolved | closed
    deleted: bool = False


@dataclass(frozen=True)
class FindingSpec:
    entity_type: str  # host | user | ip
    entity_value: str
    severity: str
    finding_class: str  # lead | benign
    narrative: str
    benign_analysis: str


@dataclass(frozen=True)
class HuntSpec:
    title: str
    subtitle: str
    doc: str
    hypothesis: str
    category: str
    tags: tuple[str, ...]
    technique: str
    tactic: str
    findings: tuple[FindingSpec, ...] = ()
    archived: bool = False


@dataclass(frozen=True)
class DraftSpec:
    """A profile draft (`POST /api/hunts/drafts`), the shape recon proposes."""

    title: str
    doc: str
    category: str
    techniques: tuple[str, ...]  # first free one is used
    tactic: str


@dataclass(frozen=True)
class FlowSpec:
    name: str
    description: str
    modules: tuple[dict[str, Any], ...]
    runs: int
    case_linked: bool


@dataclass(frozen=True)
class DashboardSpec:
    name: str
    description: str


@dataclass
class Plan:
    events: list[dict[str, Any]]
    hosts: list[str]
    users: list[str]
    sources: list[SourceSpec]
    rules: list[RuleSpec]
    cases: list[CaseSpec]
    hunts: list[HuntSpec]
    drafts: list[DraftSpec]
    flows: list[FlowSpec]
    dashboards: list[DashboardSpec]
    soar_catalog: str = "all"  # every available pack is installed
    notes: dict[str, Any] = field(default_factory=dict)

    @property
    def pending_approvals(self) -> int:
        return sum(f.runs for f in self.flows)

    @property
    def case_linked_approvals(self) -> int:
        return sum(f.runs for f in self.flows if f.case_linked)

    def uids(self) -> set[str]:
        return {e["metadata"]["uid"] for e in self.events}


# ---------------------------------------------------------------- vocabularies
FIRST = [
    "alice",
    "bob",
    "carol",
    "dave",
    "erin",
    "frank",
    "grace",
    "heidi",
    "ivan",
    "judy",
    "mallory",
    "oscar",
    "peggy",
    "trent",
    "victor",
    "wendy",
    "yusuf",
    "zara",
    "amara",
    "bjorn",
    "chiara",
    "dmitri",
    "esperanza",
    "farouk",
    "gunnhild",
    "hiroshi",
    "ingrid",
    "jaroslav",
    "kalani",
    "lucia",
    "mateus",
    "nkechi",
    "olumide",
    "priyanka",
    "quentin",
    "rasmus",
    "siobhan",
    "tadeusz",
    "ulrike",
    "valentina",
]
LAST = [
    "nguyen",
    "okafor",
    "diaz",
    "kim",
    "walsh",
    "ito",
    "lund",
    "park",
    "rossi",
    "chen",
    "fox",
    "berg",
    "shah",
    "cole",
    "almeida",
    "kowalczyk",
    "van-der-merwe",
    "obrien",
    "fitzgerald-montgomery",
    "papadopoulos",
    "nakamura",
    "haddad",
    "johansson",
    "oyelaran",
    "featherstonehaugh",
    "abubakar",
]
# Real-world identities that break naive layouts and parsers.
UNICODE_USERS = [
    "józef.wiśniewski",
    "zoë.lefèvre",
    "søren.kierkegård",
    "ольга.смирнова",
    "李伟",
    "佐藤.花子",
    "محمد.الفارسي",
    "þórunn.guðmundsdóttir",
    "o'brien.siobhan",
    "anne-marie.d'arcy",
    "çağla.öztürk",
    "nguyễn.thị.thu",
    "ελένη.παπαδοπούλου",
    "η.ζ",
    "q",
]
LONG_USERS = [
    "svc_payroll_reconciliation_batch_prod_eu_west_1@corp-subsidiary-holdings.example.co.uk",
    "svc-azure-ad-connect-sync-account-primary-datacenter-frankfurt-02@identity.example.com",
    "CORP\\exchange-online-hybrid-migration-service-principal-do-not-disable",
    "temporary.contractor.account.for.the.quarterly.sox.audit.engagement.2026q4@external.example.org",
]
SITES = ["nyc", "lon", "fra", "sgp", "syd", "sao", "tor", "dub", "ams", "mum", "tyo", "jnb"]
ROLES = ["ws", "lt", "srv", "dc", "sql", "web", "jump", "vdi", "kiosk", "build", "k8s-node", "pos"]
LONG_HOSTS = [
    "fin-ws-accounting-floor-3-east-wing-desk-0417.corp.emea.subsidiary-holdings.example.co.uk",
    "ip-10-212-37-104.eu-west-1.compute.internal.prod-payments-cluster-blue.example.net",
    "aks-nodepool-gpu-inference-standard-nc24ads-a100-v4-vmss00000c.westeurope.cloudapp.azure.com",
    "desktop-8f3k2l9q-very-long-netbios-overflow-check-hostname-that-keeps-going.local",
]
UNICODE_HOSTS = [
    "ws-münchen-büro-04",
    "lt-zürich-straße-11",
    "srv-東京-db-01",
    "ws-são-paulo-ção-07",
    "kiosk-kraków-łódź-2",
]

TAGS = [
    "credential-access",
    "lateral-movement",
    "initial-access",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "exfiltration",
    "command-and-control",
    "discovery",
    "collection",
    "impact",
    "pci-dss-scope",
    "sox-in-scope",
    "hipaa",
    "gdpr-art-33-notifiable",
    "crown-jewels",
    "tier-0-asset",
    "vip-executive",
    "third-party-vendor",
    "contractor",
    "after-hours",
    "geo-anomaly",
    "impossible-travel",
    "needs-legal-review",
    "customer-impacting",
    "false-positive-candidate",
    "tuning-needed",
    "red-team-2026q4",
    "purple-team-exercise",
    "ransomware-precursor",
    "business-email-compromise",
    "insider-risk",
    "okta",
    "entra-id",
    "aws-cloudtrail",
    "crowdstrike",
    "zscaler",
    "palo-alto",
    "o365",
    "gcp-audit",
    "escalated-to-ir-retainer",
    "awaiting-asset-owner",
    "awaiting-hr",
    "ticket-inc0098231",
    "très-urgent",
    "要確認",
    "проверить",
]

SENTENCES = [
    "The account authenticated from {ip} roughly four minutes after a password reset was requested from an "
    "unmanaged device, which matches the help-desk social-engineering pattern seen in the last quarter.",
    "Process lineage shows {proc} spawned by an Office application with an encoded command line, and the parent "
    "document was delivered by an external sender whose domain was registered nine days ago.",
    "No change ticket, maintenance window or deployment pipeline run explains the activity; the asset owner was "
    "contacted at 09:12 UTC and has not yet confirmed whether the behaviour is expected.",
    "The same entity appears in three unrelated detections over the last 72 hours, each individually below the "
    "alerting threshold, which is why the risk-based correlation surfaced it rather than any single rule.",
    "Outbound traffic to {ip} on 443 carried a JA3 fingerprint that is rare across the fleet (seen on two of "
    "{hosts} hosts) and the byte ratio is strongly asymmetric, consistent with staged exfiltration.",
    "The strongest benign explanation considered was a backup agent upgrade rolled out by the infrastructure "
    "team; it was ruled out because the binary hash does not match the vendor's published release.",
    "Kerberos service tickets were requested with RC4 encryption for eleven SPNs in under a minute, including "
    "two service accounts with non-expiring passwords and membership in privileged groups.",
    "Geolocation for the source address resolves to a hosting provider in a region where the organization has "
    "no staff, contractors or cloud workloads, and the user agent string is a headless automation library.",
]

TECHNIQUES = [
    ("TA0006", "T1110"),
    ("TA0006", "T1558"),
    ("TA0008", "T1021"),
    ("TA0002", "T1059"),
    ("TA0003", "T1053"),
    ("TA0005", "T1070"),
    ("TA0010", "T1041"),
    ("TA0011", "T1071"),
    ("TA0007", "T1087"),
    ("TA0001", "T1078"),
    ("TA0004", "T1068"),
    ("TA0040", "T1486"),
    ("TA0009", "T1114"),
    ("TA0003", "T1136"),
    ("TA0005", "T1562"),
]

RULE_STEMS = [
    "kerberoasting_rc4_service_ticket_requests_from_non_admin_workstations_outside_business_hours",
    "password_spray_against_federated_sso_portal_from_residential_proxy_networks",
    "impossible_travel_between_consecutive_interactive_logons_for_privileged_accounts",
    "encoded_powershell_spawned_by_office_application_with_network_connection",
    "new_scheduled_task_created_by_non_system_account_pointing_to_user_writable_path",
    "security_event_log_cleared_on_domain_controller_or_tier_zero_server",
    "large_outbound_transfer_to_rare_destination_after_archive_utility_execution",
    "beaconing_to_newly_registered_domain_with_low_variance_interval",
    "enumeration_of_domain_admins_group_membership_from_workstation",
    "valid_account_logon_from_tor_exit_node_or_anonymizing_vpn",
    "local_privilege_escalation_via_vulnerable_signed_driver_load",
    "mass_file_rename_with_high_entropy_extensions_indicating_ransomware",
    "mailbox_forwarding_rule_to_external_domain_created_via_api",
    "local_account_created_and_added_to_administrators_within_five_minutes",
    "endpoint_protection_tamper_or_service_stop_on_production_server",
    "remote_service_creation_over_smb_from_non_management_subnet",
    "rare_parent_child_process_pair_across_the_fleet_in_last_seven_days",
    "service_account_interactive_logon_contrary_to_policy",
]
CASE_STEMS = [
    "Suspected business email compromise: finance mailbox forwarding rule to external domain and wire-transfer "
    "change request from the CFO's delegate",
    "Credential stuffing burst against the partner SSO portal followed by one successful logon from a residential "
    "proxy in a country with no staff",
    "Ransomware precursor activity on the EMEA file-server cluster: shadow copy deletion attempts and mass rename "
    "of finance share",
    "Kerberoasting across eleven service principals from a contractor laptop that also ran an encoded PowerShell "
    "downloader",
    "Insider-risk review: departing engineer bulk-downloaded design repositories and synced them to a personal "
    "cloud drive",
    "Cloud control-plane anomaly: access keys for the payments deployment role used from an unfamiliar ASN at 03:00 "
    "local time",
]
HUNT_STEMS = [
    (
        "Service accounts authenticating interactively from workstations they have never used before, across every "
        "site and identity provider in scope",
        "identity",
        "TA0006",
        "T1078",
    ),
    (
        "Long-lived low-volume beacons to rare destinations that only a handful of hosts in the fleet have ever "
        "contacted, excluding sanctioned SaaS",
        "network",
        "TA0011",
        "T1071",
    ),
    (
        "Living-off-the-land binaries launched by document handlers with encoded or obfuscated command lines on "
        "finance and executive endpoints",
        "endpoint",
        "TA0002",
        "T1059",
    ),
    (
        "Privileged group enumeration followed within one hour by remote service creation from the same "
        "workstation",
        "endpoint",
        "TA0007",
        "T1087",
    ),
    (
        "Archive utilities touching more than five hundred files followed by large outbound transfers to "
        "destinations first seen this week",
        "data",
        "TA0010",
        "T1041",
    ),
    (
        "Mailbox rule creation through the Graph API by applications consented in the last thirty days, focusing on "
        "forwarding and deletion rules",
        "email",
        "TA0009",
        "T1114",
    ),
]


# ---------------------------------------------------------------- helpers
def _h(*parts: str, n: int = 6) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:n]


def _paragraphs(rng: random.Random, n: int, **fmt: Any) -> str:
    out = []
    for _ in range(n):
        out.append(" ".join(rng.choice(SENTENCES).format(**fmt) for _ in range(rng.randint(3, 5))))
    return "\n\n".join(out)


def _users(rng: random.Random) -> list[str]:
    users = [f"{f}.{last}" for f in FIRST for last in LAST[:8]]  # 320 ordinary
    users += UNICODE_USERS + LONG_USERS
    return users


def _hosts(rng: random.Random) -> list[str]:
    hosts = [f"{role}-{site}-{i:03d}" for site in SITES for role in ROLES[:6] for i in range(1, 7)]  # 432
    hosts += LONG_HOSTS + UNICODE_HOSTS
    return hosts


def _ip(i: int) -> str:
    return f"10.{40 + i // 60000}.{(i // 250) % 240}.{i % 250 + 2}"


# ---------------------------------------------------------------- events
def _events(rng: random.Random, hosts: list[str], users: list[str]) -> list[dict[str, Any]]:
    """Every host and every user appears at least once (high cardinality); a
    few appear a lot. `metadata.uid` is the seed's identity for each event."""
    events: list[dict[str, Any]] = []
    publics = [f"203.0.113.{i}" for i in range(1, 60)] + [f"198.51.100.{i}" for i in range(1, 60)]

    def meta(n: int) -> dict[str, Any]:
        return {
            "uid": f"{KEY}-{n:05d}",
            "version": "1.8.0",
            "log_source": LANE,
            "product": {"name": PRODUCT, "vendor_name": "nano"},
        }

    n = 0
    for i, host in enumerate(hosts):
        n += 1
        user = users[i % len(users)]
        ok = rng.random() > 0.1
        events.append(
            {
                "class_uid": 3002,
                "category_uid": 3,
                "activity_id": 1,
                "type_uid": 300201,
                "class_name": "Authentication",
                "activity_name": "Logon",
                "severity_id": 1 if ok else 3,
                "status_id": 1 if ok else 2,
                "status": "Success" if ok else "Failure",
                "actor": {"user": {"name": user}},
                "user": {"name": user},
                "src_endpoint": {"ip": rng.choice(publics) if rng.random() < 0.2 else _ip(i)},
                "device": {"hostname": host, "ip": _ip(i)},
                "message": f"{'Successful' if ok else 'Failed'} logon for {user} on {host}",
                "metadata": meta(n),
            }
        )
    for j, user in enumerate(users):
        n += 1
        host = hosts[(j * 7) % len(hosts)]
        events.append(
            {
                "class_uid": 1007,
                "category_uid": 1,
                "activity_id": 1,
                "type_uid": 100701,
                "class_name": "Process Activity",
                "activity_name": "Launch",
                "severity_id": 1,
                "actor": {"user": {"name": user}},
                "process": {
                    "name": rng.choice(
                        ["powershell.exe", "cmd.exe", "chrome.exe", "rundll32.exe", "wmic.exe"]
                    ),
                    "cmd_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
                    + _h(user, n=48),
                    "pid": 1000 + j,
                },
                "device": {"hostname": host, "ip": _ip((j * 7) % len(hosts))},
                "message": f"{user} launched a process on {host}",
                "metadata": meta(n),
            }
        )
    # Flows: a heavy-hitter tail on a few hosts, so top-N lists have a shape.
    for k in range(600):
        n += 1
        hi = k % 25 if k % 3 else rng.randrange(len(hosts))
        host = hosts[hi]
        dst = rng.choice(publics)
        events.append(
            {
                "class_uid": 4001,
                "category_uid": 4,
                "activity_id": 6,
                "type_uid": 400106,
                "class_name": "Network Activity",
                "activity_name": "Traffic",
                "severity_id": 1,
                "src_endpoint": {"ip": _ip(hi), "port": 49152 + k},
                "dst_endpoint": {"ip": dst, "port": 443},
                "connection_info": {"protocol_num": 6},
                "traffic": {"bytes_out": rng.randint(500, 9_000_000), "bytes_in": rng.randint(500, 400_000)},
                "device": {"hostname": host, "ip": _ip(hi)},
                "message": f"{host} -> {dst}:443",
                "metadata": meta(n),
            }
        )
    return events


# ---------------------------------------------------------------- objects
def _sources() -> list[SourceSpec]:
    out = [
        SourceSpec(
            name=f"{KEY} Fleet endpoint and identity telemetry (OCSF), every site, every business unit, all regions",
            method="routed",
            route_key=LANE,
            active=True,
            vendor="nano",
            product="e2e realistic fleet",
            description="Realistic seed (NAN-5764): the source the seeded OCSF events arrive through.",
        )
    ]
    # Push methods only. A fetch method (kafka, aws_s3, gcp_pubsub,
    # azure_event_hubs) needs a bound source configuration with real cloud
    # credentials; a fetch draft without one fails every Vector render on the
    # install (NAN-5789), and syslog / otlp / file are not log-source methods.
    methods = {
        "routed": [
            ("Okta System Log", "Okta"),
            ("CrowdStrike Falcon detections", "CrowdStrike"),
            ("Zscaler ZIA web proxy (HTTP push)", "Zscaler"),
            ("1Password Events API relay", "1Password"),
        ],
        "splunk_hec": [
            ("Splunk HEC forwarder", "Splunk"),
            ("Cisco Duo authentication log", "Cisco"),
            ("Palo Alto PAN-OS firewall (HEC)", "Palo Alto Networks"),
            ("Proofpoint TAP", "Proofpoint"),
        ],
        "vector": [
            ("Vector edge aggregator", "Datadog"),
            ("Windows Event Forwarding collector", "Microsoft"),
            ("Linux auditd fleet", "Red Hat"),
            ("Kubernetes audit log shipper", "CNCF"),
        ],
    }
    regions = [
        "EMEA production (Frankfurt, Dublin, Amsterdam) shared tenant",
        "APAC",
        "Zürich – Büro Straße 11",
        "North America east",
    ]
    for method, products in methods.items():
        for i, (title, vendor) in enumerate(products):
            region = regions[i % len(regions)]
            out.append(
                SourceSpec(
                    name=f"{KEY} {title} — {region}",
                    method=method,
                    route_key=f"{KEY}_{method}_{i}",
                    vendor=vendor,
                    product=title,
                    description=f"Realistic seed (NAN-5764): {title} for {region}. " * (3 if i == 0 else 1),
                )
            )
    out.append(
        SourceSpec(
            name=f"{KEY} Decommissioned proxy logs (deleted after the migration to SASE)",
            method="routed",
            route_key=f"{KEY}_deleted_proxy",
            vendor="Bluecoat",
            product="ProxySG",
            description="Realistic seed (NAN-5764): created then deleted.",
            deleted=True,
        )
    )
    return out


def _rules(rng: random.Random, users: list[str]) -> list[RuleSpec]:
    out: list[RuleSpec] = []
    modes = ["staging", "live", "alerting"]
    sev = ["low", "medium", "high", "critical"]
    for i, stem in enumerate(RULE_STEMS):
        for v in range(2):
            name = f"{KEY}_{stem}_v{v + 1}"
            tactic, tech = TECHNIQUES[(i + v) % len(TECHNIQUES)]
            tags = tuple(rng.sample(TAGS, rng.randint(4, 18 if i % 4 == 0 else 8)))
            user = users[(i * 13 + v) % len(users)]
            out.append(
                RuleSpec(
                    name=name,
                    description=_paragraphs(rng, 1, ip="203.0.113.7", proc="powershell.exe", hosts=400),
                    query=f'source_type="{LANE}" class_uid=3002 actor.user.name="{user}"',
                    severity=sev[(i + v) % 4],
                    mode=modes[(i + v) % 3],
                    tags=tags,
                    techniques=(tech,),
                    archived=(i % 7 == 3 and v == 1),
                    fire=(modes[(i + v) % 3] == "alerting" and i < 6),
                )
            )
    for k in range(2):
        out.append(
            RuleSpec(
                name=f"{KEY}_imported_from_sigma_repository_then_removed_by_the_detection_owner_{k + 1}",
                description="Realistic seed (NAN-5764): imported through the rules import API, then deleted.",
                query=f'source_type="{LANE}" class_uid=1007 process.name="wmic.exe"',
                severity="medium",
                mode="staging",
                tags=("imported", "sigma"),
                techniques=("T1047",),
                imported_then_deleted=True,
            )
        )
    return out


def _cases(rng: random.Random, users: list[str], hosts: list[str]) -> list[CaseSpec]:
    out: list[CaseSpec] = []
    statuses = ["open", "open", "in_progress", "in_progress", "resolved", "closed"]
    for i in range(30):
        stem = CASE_STEMS[i % len(CASE_STEMS)]
        who = users[(i * 11) % len(users)]
        where = hosts[(i * 17) % len(hosts)]
        title = f"[{KEY}-{i:02d}] {stem} — {who} on {where}"
        n_tags = 32 if i == 0 else (0 if i == 1 else rng.randint(2, 14))
        case_tags = [t for t in TAGS if CASE_TAG.match(t)]
        tags = tuple(sorted(set(rng.sample(case_tags, min(n_tags, len(case_tags))))))[:32]
        out.append(
            CaseSpec(
                title=title,
                description=_paragraphs(rng, 2, ip="198.51.100.23", proc="rundll32.exe", hosts=432),
                severity=["low", "medium", "high", "critical"][i % 4],
                tags=tags,
                status=statuses[i % len(statuses)],
                deleted=i in (28, 29),
            )
        )
    return out


def _findings(rng: random.Random, hosts: list[str], users: list[str], k: int) -> tuple[FindingSpec, ...]:
    out = []
    for j in range(4):
        # ASCII entities: the server corroborates each against the evidence
        # rows' extracted entities (device.hostname / actor.user.name).
        etype = ["host", "user", "host", "ip"][j]
        idx = (k * 5 + j * 3) % 400
        value = {"host": hosts[idx], "user": users[idx % 300], "ip": _ip(idx)}[etype]
        cls = "benign" if j == 3 else "lead"
        out.append(
            FindingSpec(
                entity_type=etype,
                entity_value=value,
                severity=["high", "medium", "critical", "low"][j],
                finding_class=cls,
                narrative=_paragraphs(
                    rng, 6 if j == 0 else 3, ip="203.0.113.44", proc="powershell.exe", hosts=432
                ),
                benign_analysis=_paragraphs(rng, 2, ip="203.0.113.44", proc="msiexec.exe", hosts=432),
            )
        )
    return tuple(out)


def _hunts(rng: random.Random, hosts: list[str], users: list[str]) -> tuple[list[HuntSpec], list[DraftSpec]]:
    hunts = []
    for k, (stem, category, tactic, tech) in enumerate(HUNT_STEMS):
        hunts.append(
            HuntSpec(
                title=f"{KEY}-{k:02d} {stem}",
                subtitle=(
                    "Quarterly threat-informed hunt requested by the CISO after the sector ISAC advisory; owner: "
                    "detection engineering (EMEA), reviewers: IR retainer and the identity platform team"
                ),
                doc=f"# {stem}\n\n" + _paragraphs(rng, 4, ip="192.0.2.10", proc="wmic.exe", hosts=432),
                hypothesis=_paragraphs(rng, 1, ip="192.0.2.10", proc="wmic.exe", hosts=432),
                category=category,
                tags=tuple(rng.sample(TAGS, 12 if k == 0 else 6)),
                technique=tech,
                tactic=tactic,
                findings=_findings(rng, hosts, users, k) if k < 3 else (),
                archived=(k == 5),
            )
        )
    drafts = [
        DraftSpec(
            title=f"{KEY}_profile_draft_reconnaissance_against_externally_exposed_identity_infrastructure_{d}",
            doc="# Profile draft\n\nRealistic seed (NAN-5764): what recon proposes for an uncovered technique.",
            category="network",
            techniques=(
                "T1592.004",
                "T1592.003",
                "T1590.006",
                "T1590.003",
                "T1589.003",
                "T1597.002",
                "T1596.005",
                "T1593.003",
            )[d * 4 : (d + 1) * 4],
            tactic="TA0043",
        )
        for d in range(2)
    ]
    return hunts, drafts


def _flows() -> list[FlowSpec]:
    digest = ("a3f5c9e1" * 8)[:64]
    prompt = (
        "Isolate workstation fin-ws-accounting-floor-3-east-wing-desk-0417 and revoke every active session for "
        f"svc_payroll_reconciliation_batch_prod_eu_west_1; hash {digest}; ticket INC0098231 — approve?"
    )
    case_title = (
        f"{KEY} SOAR containment: credential stuffing burst against the partner SSO portal, "
        "followed by one successful logon from a residential proxy (automated case)"
    )

    def approval(mid: str, text: str) -> dict[str, Any]:
        return {
            "id": mid,
            "value": {"type": "approval", "prompt": text, "options": ["approve", "deny", "escalate"]},
        }

    return [
        FlowSpec(
            name=f"{KEY}_isolate_host_and_revoke_sessions_after_analyst_approval_long_prompt",
            description="Realistic seed (NAN-5764): a long approval prompt with an unbroken hash.",
            modules=(approval("gate", prompt),),
            runs=8,
            case_linked=False,
        ),
        FlowSpec(
            name=f"{KEY}_disable_okta_user_pending_manager_sign_off",
            description="Realistic seed (NAN-5764): a short approval.",
            modules=(approval("gate", "Disable the Okta user?"),),
            runs=6,
            case_linked=False,
        ),
        FlowSpec(
            name=f"{KEY}_open_case_then_request_containment_approval",
            description="Realistic seed (NAN-5764): an approval that belongs to the run's case.",
            modules=(
                {"id": "open", "value": {"type": "case.create", "title": case_title, "severity": "high"}},
                approval("gate", prompt),
            ),
            runs=6,
            case_linked=True,
        ),
        FlowSpec(
            name=f"{KEY}_case_create_requires_approval",
            description="Realistic seed (NAN-5764): a case.create step that itself needs approval.",
            modules=(
                {
                    "id": "open",
                    "value": {
                        "type": "case.create",
                        "title": case_title,
                        "severity": "medium",
                        "approval": "required",
                    },
                },
            ),
            runs=4,
            case_linked=True,
        ),
    ]


def build(seed: int = SEED) -> Plan:
    """The whole plan. Same seed, same plan, byte for byte."""
    rng = random.Random(seed)  # noqa: S311 - deterministic test content, not crypto
    users = _users(rng)
    hosts = _hosts(rng)
    events = _events(rng, hosts, users)
    hunts, drafts = _hunts(rng, hosts, users)
    dashboards = [
        DashboardSpec(
            name=f"{KEY} Executive SOC overview — EMEA & APAC — detections, cases, SOAR approvals and hunt findings {i}",
            description="Realistic seed (NAN-5764): a long dashboard name.",
        )
        for i in range(3)
    ]
    return Plan(
        events=events,
        hosts=hosts,
        users=users,
        sources=_sources(),
        rules=_rules(rng, users),
        cases=_cases(rng, users, hosts),
        hunts=hunts,
        drafts=drafts,
        flows=_flows(),
        dashboards=dashboards,
    )


def digest(plan: Plan) -> str:
    """A fingerprint of the plan's content (selftest: determinism)."""
    import json
    from dataclasses import asdict

    body = {
        "events": plan.events,
        "sources": [asdict(s) for s in plan.sources],
        "rules": [asdict(r) for r in plan.rules],
        "cases": [asdict(c) for c in plan.cases],
        "hunts": [asdict(h) for h in plan.hunts],
        "drafts": [asdict(d) for d in plan.drafts],
        "flows": [asdict(f) for f in plan.flows],
        "dashboards": [asdict(d) for d in plan.dashboards],
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
