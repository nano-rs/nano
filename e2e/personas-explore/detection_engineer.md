# Charter: detection engineer

**Mission.** Write, validate, tune and promote detections over the OCSF
corpus. Find where the rule editor validates against UDM, where preview,
test and live results disagree, and where content coverage reports
fields that are not this tenant's fields.

**Login.** `$PY -m nano_e2e.explore start --persona detection_engineer`
(search incl. SQL, detections view/create/edit/promote, alerts/cases view,
AI detection). Setup and conventions: [README](README.md). Always `stop`.

## Tasks

1. /rules/editor/new: type field prefixes and read every autocomplete offer
   (`op autocomplete`); type a UDM query (`src_ip="203.0.113.7" | stats count by user`).
   It may be accepted, but the editor must hint at the OCSF path (the API
   warns, see `/api/rules/validate`); "Valid" with no hint is a finding.
   Typos (`src_endpoint.ipp`, `actor.usr.name`) must suggest real OCSF paths.
2. Write a rule over the corpus (e.g. Okta MFA failure, CloudTrail
   ConsoleLogin without MFA). Test rule over a wide range; the match count
   must equal search for the same nPL and range.
3. Flow and Form views of the same rule: switching must keep the query and
   fields; every field picker in Form lists OCSF paths.
4. Promote staging -> live -> alerting. Matches/alerts must show up with the
   same fields; the alert detail must use OCSF names.
5. Rule repositories / coverage: read "missing fields" and
   "requires fields" for OCSF content. Every listed field must be an OCSF
   path (the checker currently flags e.g. `bytes_out`, `subject`).
6. MITRE coverage: numbers agree with the rule list filters.
7. Tuning: add an exclusion from a match; re-test; the exclusion must use
   the OCSF path and actually reduce matches.
8. AI detection wizard: generated nPL and explanation use OCSF paths and
   validate.
9. Retro hunt over the corpus window vs search count.
10. Leave the editor dirty: `idle 10 --reload`.

## Bug classes (focus for this role)

- **OCSF/UDM leftovers**: validation messages, autocomplete, Form field
  pickers, coverage "missing fields", rule templates, AI output.
- **Doubled prefixes**: Form/Flow round-trips adding a prefix twice.
- **No-effect controls**: severity/mode/schedule changes not persisted; exclusions not applied.
- **Cross-surface**: rule test vs search vs matches page vs alerts count vs retro hunt.
- **Console/network**: errors on validate (fires per keystroke), test, promote.
- **Idle return**: dirty editor state on return.
- **Empty states / validation**: unclear "invalid" with no field named; Save blocked with no reason.
- **UI conventions**: mono on rule names, IDs, counts; breadcrumb on editor pages.

## Evidence

Use the evidence block in [README](README.md#evidence-format-one-block-per-finding).
Include the exact rule nPL, the range, and the `/api/rules/validate` response
for validation findings.
