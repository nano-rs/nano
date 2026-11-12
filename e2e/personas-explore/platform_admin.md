# Charter: platform admin

**Mission.** Run the platform: users, groups, roles, API keys, SSO,
settings, audit, health. Find controls that do nothing, settings that do not
take effect, audit gaps, and admin pages that still describe a UDM world.

**Login.** `$PY -m nano_e2e.explore start --persona platform_admin`
(settings view/system, groups/roles view, API keys CRUD, audit view, search).
For checks that need full admin, use `--session setup start --admin` and say so
in the finding. Setup and conventions: [README](README.md). Always `stop`.

## Tasks

1. Settings: change each setting this role can change, reload, confirm it
   persisted and had its effect (diff the behaviour, not just the form).
   Settings it cannot change must be read-only and say why, not 403 on save.
2. API keys: create (reveal-once), scope it, use it with curl against search
   and a denied endpoint, rotate, delete. The audit log must show each step.
3. Users/groups/roles (view): permission lists use current names; the
   effective-permission view matches what the persona can actually do.
4. Audit: filter by actor, action, resource; every filter changes the list;
   the events from step 2 are there with correct actor and time.
5. Health / observability: numbers agree with the ingestion pages and with
   the corpus counts (`/tmp/corpus.json`).
6. Schema / data settings pages: the field universe shown, retention,
   enrichment and prevalence configuration all describe OCSF (no UDM column
   names presented as canonical, no `*_search` columns).
7. License / edition pages (enterprise vs open): features shown match what works.
8. `idle 35 --reload` on settings with unsaved changes.
9. Empty states: no API keys, no SSO providers, empty audit filter result.

## Bug classes (focus for this role)

- **OCSF/UDM leftovers**: schema/field settings, retention and enrichment
  pages, docs links, example payloads.
- **Doubled prefixes**: field names in enrichment/prevalence configuration.
- **No-effect controls**: settings that save but do not apply; toggles with no observable change.
- **Cross-surface**: audit vs what happened; health vs ingestion vs search counts.
- **Console/network**: 403/500 on settings pages the role may view.
- **Idle return**: settings form lost or logged out without a message.
- **Empty states / validation**: unclear errors on SSO/API-key forms; secrets never shown twice.
- **UI conventions**: mono on key IDs, user IDs, timestamps; one 1px border, no shadows outside modals.

## Evidence

Use the evidence block in [README](README.md#evidence-format-one-block-per-finding).
Never paste a secret (API key, password): name it and say where it was shown.
