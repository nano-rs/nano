# Charter: incident responder

**Mission.** Work alerts into cases and drive them to closure: assign,
investigate in notebooks, run playbooks, hand off. Find where entity and
field names leak UDM, where case/alert numbers disagree with search, and
where long-running investigation pages break on return.

**Login.** `$PY -m nano_e2e.explore start --persona incident_responder`
(alerts view/ack/assign, cases view/edit/assign/close/comment, notebooks,
playbooks/SOAR run, users view). Use an admin `--session setup` (or the
detection_engineer charter) first to create a rule that alerts on corpus data.
Setup and conventions: [README](README.md). Always `stop`.

## Tasks

1. Alerts queue: filter, sort, group. Every filter must change the list
   (diff counts); counts must match the alert totals elsewhere (home tiles,
   rule detail).
2. Open an alert: the evidence/event view, entity chips and "related events"
   must use OCSF paths and agree with search for the same entity.
3. Create a case from the alert; add a second alert; assign; comment.
   Timeline entries, counts and entity lists must agree.
4. Notebook in the case: run a query cell over the corpus; result counts
   equal search; pivot from an entity into a new cell.
5. Auto-investigation / shadow investigation entries: read the queries it ran
   and the narrative; field names OCSF, numbers match.
6. Run a playbook / SOAR flow on the case (enterprise); approvals and results
   are visible and auditable.
7. Hand off to another user and close the case with a disposition; reopen;
   the history must be complete.
8. pivt in the case context: answers must not mix up Cases and pivt surfaces
   (see CLAUDE.md boundary) and must cite OCSF fields.
9. `idle 10 --reload` and `idle 35 --reload` on an open case and a notebook.
10. Empty states: a case with no alerts, a notebook with no cells, no playbooks.

## Bug classes (focus for this role)

- **OCSF/UDM leftovers**: entity extraction labels, related-event queries,
  notebook suggestions, shadow-investigation queries, exported case report.
- **Doubled prefixes**: entity pivots generating `actor.actor.user...`.
- **No-effect controls**: status/assignee/severity changes not persisted; filters no-ops.
- **Cross-surface**: alert counts vs case counts vs search vs notebook cells vs pivt.
- **Console/network**: 403 for allowed case actions; failing polling on case pages.
- **Idle return**: notebook state lost, case page blank after idle.
- **Empty states / validation**: closing without a disposition, unclear errors.
- **UI conventions**: mono on case IDs, alert IDs, IPs, timestamps; page structure.

## Evidence

Use the evidence block in [README](README.md#evidence-format-one-block-per-finding).
Include case and alert IDs and the search query used to cross-check.
