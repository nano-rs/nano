# Charter: SIEM engineer

**Mission.** Onboard and operate data: parsers, log sources, routing,
prevalence, roles. Find where the platform side still thinks in UDM, where a
deploy "succeeds" without effect, and where the parser tooling and search
disagree about what a field is called.

**Login.** `$PY -m nano_e2e.explore start --persona siem_engineer`
(log sources view/create/edit/deploy, parser repositories view, source
configs view, prevalence, roles create, settings:system, AI parser).
Setup and conventions: [README](README.md). Always `stop` at the end.

## Tasks

1. Ingestion > log sources: open three corpus sources (okta, aws_cloudtrail,
   apache). Status, last event, EPS and health must match what search shows
   for `metadata.log_source="<lane>"`.
2. Parser editor / test lab on a corpus sample: run the bundled sample, read
   the output tree and every field name in it, the OCSF validation panel and
   the "fields this parser produces" list. No UDM names, no doubled paths,
   OCSF class shown matches the row's `class_uid` in search.
3. Edit a parser (add one mapping), publish, send the sample again (corpus
   `--only <name>`), and confirm the new field appears in search, the sidebar
   and field stats. Then revert. A publish that reports success but changes
   nothing in search is a finding.
4. Parser repository: browse, preview an import, compare the preview's
   field list with what the deployed parser produces.
5. Use the AI parser assistant on a raw sample: the proposed VRL and the
   explanation must target OCSF paths.
6. Routing: an event with an unknown sourcetype. Where does it land, what
   does the UI say, is it searchable, and under which lane?
7. Prevalence: configure a field. The picker must offer OCSF paths only;
   the result must be visible in search enrichment.
8. Roles: create a role, toggle permissions, diff the effective access (as
   another session). A permission that changes nothing is a finding.
9. Health / delivery status after the corpus: no stale errors, numbers agree
   with ingestion history.
10. `idle 10 --reload` on the parser editor with unsaved changes.

## Bug classes (focus for this role)

- **OCSF/UDM leftovers**: parser output tree, field lists, "suggested
  mappings", prevalence field picker, example VRL, help text.
- **Doubled prefixes**: `unmapped.unmapped`, `event.event`, parser test output vs search.
- **No-effect controls**: publish/deploy/toggle/enable that changes nothing; dry-run vs real.
- **Cross-surface**: source health vs search counts vs ingestion history vs delivery status.
- **Console/network**: 4xx during deploy, polling errors on health pages.
- **Idle return**: unsaved parser edits lost silently.
- **Empty states / validation**: VRL compile errors name the line; OCSF gate failures name the attribute.
- **UI conventions**: mono for source names, lanes, counts, timestamps; dense tables.

## Evidence

Use the evidence block in [README](README.md#evidence-format-one-block-per-finding).
For deploy findings include the log source id, the version before/after and
the search query proving the (missing) effect.
