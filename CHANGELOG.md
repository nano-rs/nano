# Changelog

## 2.0.0

nano v2.0.0 is the first v2 release. It makes OCSF the default schema for new
installations, adds signed and journaled compose upgrades, and adds
supported enterprise deployment paths for Kubernetes and role-split sovereign
VMs.

See the [v2.0.0 release notes](docs/releases/v2.0.0.md) and the
[v0.1.x to v2.0.0 upgrade guide](docs/administration/upgrade-v2.md) before
changing an existing deployment.

### Added

- OCSF-first storage and field discovery for new installations, including the
  version-agnostic OCSF store and OCSF content validation.
- Enterprise SOAR playbooks, approvals, schedules, case triggers, connection
  scoping, run traces, and customer notification actions.
- Pipelines with draft, preview, live-tap, deployment, and rollback workflows.
- Source-bound ingest tokens, a unified source setup flow, connector pull feeds,
  and separate app and ingest frontends.
- Search background jobs, shared in-flight work, admission control, expanded
  nPL correctness coverage, and updated search workflows.
- IOC lists, platform-delivered enrichment feeds, identity feeds, risk
  watchlists, and risk explanation views.
- A Helm chart for enterprise Kubernetes and an enterprise role-split compose
  installer for sovereign VMs.
- Encrypted, signed backup and restore tooling for compose installations.
- Ed25519-signed offline release bundles and a dry-run, journaled `nano upgrade`
  coordinator for single-node and role-split compose installations.
- Resource autosizing for compose installations, ingest watchdogs, multi-ingest
  load-balancer coordination, and an optional tenant-health OTLP exporter.

### Changed

- ClickHouse is updated from the v0.1.703 26.4/26.5 deployments to 26.10.3.7.
  v2 enforces the matching configuration, migration, and CPU preflights.
- New installs default to OCSF. The installer still offers UDM, and existing
  UDM installations remain on their recorded schema profile. v2 does not
  automatically backfill, switch, or delete UDM data; `UDM-RETIREMENT.md`
  describes a future retirement plan rather than shipped cutover behavior.
- Base search and piped `search` now evaluate `OR` before explicit or implicit
  `AND`. Parenthesize existing queries whose intended grouping differs.
- Rule promote and demote requests accept an `expected_mode` guard. The field is
  optional for legacy callers in v2.0.0, but bodyless requests are deprecated.
- Kubernetes uses separate app and ingest Gateways by default. The legacy
  ingress compatibility mode is deprecated.

### Security and operations

- First-party images and third-party runtime images are digest-pinned in release
  artifacts.
- Audit events are durable across ClickHouse outages, credential keys can be
  rotated online, and sensitive service metrics require authentication when
  exposed beyond loopback.
- Role-split private traffic uses TLS by default and requires staged key
  material plus explicit firewall rules.
- ClickHouse and Keeper roles require AVX2 on x86-64. The v2 upgrade policy also
  requires at least 8 GiB RAM and 100 GiB free disk for a compose upgrade.

### Breaking changes

- `NANO_VERSION` is required for release compose files. There is no `latest`
  tag; use the exact value `2.0.0`.
- The only direct supported v0.1.x source for a v2.0.0 compose upgrade is
  `v0.1.703`.
- The new-install schema default changes from UDM to OCSF. UDM remains
  selectable; an operator must choose it explicitly for a new UDM install.
- New rule-lifecycle integrations must send `expected_mode`; a stale value
  returns `409 Conflict` without changing the rule.
- Enabling tenant-health export requires a dedicated receiver-scoped health
  token. The deployment licence token is never used as a fallback.
- Role-split installs require private TLS unless an explicit test-only plaintext
  mode is selected, and Docker-published ports require `DOCKER-USER` filtering
  in addition to normal host firewall rules.
- Kubernetes schema migrations are forward-only. `helm rollback` is not a
  supported way to cross a schema-changing release.
