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

This repository (`nanos-sh/nano`) is the open-core engine —
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
