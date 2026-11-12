# Charter: SOC analyst

**Mission.** Triage and hunt over the OCSF corpus the way a tier-1/2 analyst
does all shift: search, pivot, read fields, build a quick dashboard, ask pivt
for a summary. Find where the product shows UDM, disagrees with itself, or
leaves the analyst guessing.

**Login.** `$PY -m nano_e2e.explore start --persona soc_analyst`
(search view/execute/save, dashboards view/create/edit, AI summarize).
Setup and conventions: [README](README.md). Always `stop` at the end.

## Tasks

1. Open /search cold. Type `src`, `dst`, `user`, `actor.`, `process`,
   `unmapped.` and read every autocomplete offer (`op autocomplete`). Note any
   UDM name or doubled prefix.
2. Hunt failed logins: `class_uid=3002 status_id=2 | stats count by actor.user.name, src_endpoint.ip`
   over a wide range. Compare the total with the sidebar's value counts for
   `actor.user.name` and with `op sidebar_fields`.
3. Type the UDM spelling of the same hunt (`user=... src_ip=...`). It may run;
   it must not be echoed back as canonical (column headers, sidebar, export
   headers, saved-search display, share link).
4. Open one Okta and one CloudTrail event; walk the Extended and Unmapped
   groups. Every `unmapped.*` key must be a real key of that event, shown once
   (no `unmapped.unmapped`). Expand each and compare the values to the raw event.
5. Pivot: click a value (IP, user, host) -> add-to-query / group-by / new
   search. Check the generated nPL uses OCSF paths.
6. Toggle every results control (table/raw, columns, sort, timeline zoom,
   rarity view, prevalence filter, dataset selector) and diff row counts,
   columns and URL before/after.
7. Save the hunt; reopen it from Saved queries and from the share link; the
   query, time range and results must match.
8. Build a dashboard with three panels from the same query (count, top users,
   timechart). Panel numbers must agree with search. Read every field
   placeholder/hint in the panel editor.
9. Ask pivt to summarize the results. The summary must use OCSF field names
   and the same counts.
10. Leave search open: `idle 10 --reload`, then `idle 35 --reload` (past token
    expiry). Results, query and range must survive or say why not.
11. Empty states: a query with no hits, a range with no data, a dashboard with
    no panels.

## Bug classes (focus for this role)

- **OCSF/UDM leftovers**: autocomplete, sidebar group labels, column headers,
  CSV/JSON export headers, pivt prose, query examples on the empty page.
- **Doubled prefixes**: Unmapped / Extended groups, add-to-query from a nested field.
- **No-effect controls**: prevalence slider, rarity, dataset, column picker.
- **Cross-surface**: search count vs sidebar vs field stats vs dashboard vs pivt.
- **Console/network**: 403s for features this role is allowed (search save,
  dashboards); errors while paging or expanding fields.
- **Idle return**: blank page or silent logout after idle.
- **Empty states / validation**: a bad query's error names the token and position.
- **UI conventions**: mono on IPs/users/timestamps/counts; row heights; breadcrumb on /search and dashboards.

## Evidence

Use the evidence block in [README](README.md#evidence-format-one-block-per-finding):
persona, class, severity, route, exact explore commands, expected vs actual
(quoted), screenshot path, the `events` excerpt, and an API or nPL
cross-check for every cross-surface finding.
