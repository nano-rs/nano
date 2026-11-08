# Security Policy

We take security in nano seriously. nano is a SIEM; security teams trust it
to surface attacker behaviour. A vulnerability in nano is by definition a
high-impact bug.

## Reporting a vulnerability

**Please do not file a public GitHub issue for vulnerabilities.**

Email **[security@nano.rs](mailto:security@nano.rs)** with:

- A description of the issue and its impact
- Reproduction steps (and a PoC if you have one)
- The version / commit you tested against
- Your name + how you'd like to be credited (or "anonymous")

If you'd prefer encrypted disclosure, request our PGP key in your initial
mail and we'll respond with it.

## Scope

This repository (`nano-rs/nano`) is the open-core engine —
ingestion, ClickHouse / Postgres data layer, search, detection,
alerting, web UI shell.

In-scope vulnerabilities for this repo:

- Authentication / authorization bypass
- SQL or VRL injection through user-controlled input
- SSRF through the lookup, enrichment, or repository-sync paths
- XSS or other web-side vulnerabilities in the SPA
- Privilege escalation via API keys, sessions, or RBAC
- Sensitive-data leakage through audit, logs, or error responses
- DoS through unbounded queries or runaway resource use

Out of scope here (report through the same channel — we'll route them):

- Vulnerabilities in the **enterprise crate** (Cases, pivt, meloD, risk,
  incidents) — these live in a private repo and the disclosure channel is
  the same email but the patch path is private.
- Vulnerabilities in **hosted nano** (nano.rs) — the email address is the
  same; we'll engage with the appropriate operations team.
- Issues in third-party dependencies that don't have a nano-side
  exploitation path. (We still want to know — we'll just defer to the
  upstream's process.)

## Deployment & network exposure

nano ships more than one compose file, and they have very different exposure
profiles. Pick the right one:

- **`docker-compose.opensource.yml`** — the supported deployment, what
  `install.sh` (`curl … | bash` from get.nano.rs) brings up. It publishes only
  the **nginx entrypoint** (`:80`, add TLS with `docker-compose.tls.yml`) and the
  **Vector ingest ports**. Postgres, ClickHouse, Dragonfly, and the api / search /
  jobs services have **no published host ports** — they are reachable only on the
  internal Docker network. There is no Prometheus, Grafana, or exporter in this
  file. A default install does **not** expose a database or monitoring/control
  plane to the host.

- **`docker-compose.yml`** — **local development only.** It binds internal
  services (Postgres, ClickHouse HTTP/native, Prometheus with
  `--web.enable-admin-api`, Grafana with default credentials, the exporters) to
  `0.0.0.0`. **Do not run it on a public host** — on a machine with a public IP
  those services are reachable, unauthenticated, from the internet. This is by
  design for loopback development; it is not a supported production posture.

### Ingest ports and authentication

In the open-core stack, Vector's `8080` (HTTP) and `8088` (Splunk HEC) require
`VECTOR_AUTH_TOKEN` — a blank token **fails closed** (`config/vector/00-base.toml`),
so misconfiguration doesn't silently accept anonymous ingest.

The Vector native port `6000` does **not** verify a token — it trusts the upstream
forwarder. Treat it as an unauthenticated, **ingest-only** path (a caller can push
logs; it cannot read stored data or control the system) and **firewall it to your
trusted aggregators**.

`docker-compose.opensource.yml` also publishes `4317`/`4318` (OpenTelemetry) and
`24224` (Fluent Forward), but the shipped config defines **no source on those
ports** — nothing listens there until you add one. If you do enable an OTel or
Fluent source, it won't carry built-in auth either, so firewall it the same way.

### Recommended firewall posture for a public deployment

- Allow `:80`/`:443` (the nginx UI/API entrypoint) from your users.
- Allow only the **ingest ports you use**, and only from your log sources' CIDRs.
- Keep everything else off the public interface.
- Put TLS in front (`docker-compose.tls.yml`) and set `BASE_URL` to your HTTPS URL.

See `docs/getting-started/docker-deployment.md` → "Network exposure & firewall"
for concrete rules.

## Disclosure timeline

We commit to:

- **Acknowledge** receipt within **3 business days**.
- **Triage** and propose a remediation path within **14 days** of
  acknowledgment.
- **Public disclosure** within **90 days** of initial report, coordinated
  with the reporter. We will request an extension only with the reporter's
  consent and only when we have a concrete reason (e.g., a fix that
  requires a coordinated upstream patch).

After remediation, we publish a security advisory through GitHub Security
Advisories with a CVE where appropriate, credit the reporter (if desired),
and link to the patch.

## Bug bounty

We don't currently run a paid bounty programme. We do offer a hall-of-fame
acknowledgement and, for impactful reports, swag and (where it makes sense)
a hosted-plan credit. If you depend on bounty income for your research, say
so up front and we'll be honest about whether it's a fit.

## Safe harbour

Good-faith security research conducted under this policy will not result in
legal action from Nano LLC. We ask you to:

- Avoid privacy violations, destruction of data, and interruption of
  service during testing.
- Test only against your own deployments or the public sandbox (when one
  exists). Do not test against `nano.rs` production tenants.
- Give us a reasonable time to remediate before public disclosure.
