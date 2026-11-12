# Exploratory persona charters (NAN-5291)

One charter per persona. An exploratory agent takes ONE charter, works through
it on a kept stack, and reports findings in the evidence format below. The
goal is bugs the scripted persona suite (`e2e/tests/personas/`) misses: it
proves the paths we wrote down; you find the ones we did not.

## Setup (once per stack)

```bash
# 1. a kept stack on the release under test. VECTOR_MEM_LIMIT: the whole
#    first-party OCSF library in one Vector OOMs the 512M compose default.
VECTOR_MEM_LIMIT=3G scripts/e2e.sh run personas --fresh --keep --edition enterprise --app image:<tag>   # or --edition open
PY=e2e/.venv/bin/python

# 2. data in every OCSF class: the parsers-ocsf sample corpus (~787 samples)
$PY -m nano_e2e.corpus --json /tmp/corpus.json

# 3. baseline field-name invariants (API + UI)
$PY -m nano_e2e.field_invariants --ui --json /tmp/field-invariants.json
```

The corpus keeps each sample's NATIVE timestamp (some are months or years
old). Search with a wide range: `--start 2000-01-01T00:00:00Z`, or the time
picker's custom range. Lanes are `metadata.log_source="<lane>"` (e.g. `okta`,
`apache_access`, `aws_cloudtrail`).

## Driving the browser

```bash
$PY -m nano_e2e.explore start --persona <soc_analyst|siem_engineer|detection_engineer|incident_responder|platform_admin>
$PY -m nano_e2e.explore goto /search
$PY -m nano_e2e.explore search 'metadata.log_source="okta" | stats count by actor.user.name' --start 2000-01-01T00:00:00Z
$PY -m nano_e2e.explore click --role button --name Save
$PY -m nano_e2e.explore click --text 'Unmapped' --regex
$PY -m nano_e2e.explore type --css .cm-content --clear 'src_endpoint.'
$PY -m nano_e2e.explore op autocomplete '{"find":{"css":".cm-content"},"text":"actor."}'
$PY -m nano_e2e.explore op sidebar_fields
$PY -m nano_e2e.explore wait --text 'Query complete' --wait-timeout 60
$PY -m nano_e2e.explore text                     # visible main text (bounded)
$PY -m nano_e2e.explore screenshot /tmp/<persona>-<n>.png
$PY -m nano_e2e.explore idle 10 --reload         # leave it, come back, reload
$PY -m nano_e2e.explore stop                     # ALWAYS: deletes the persona user
```

- Every command prints JSON with `events.console` (errors) and
  `events.network` (requests >= 400 or failed) since the previous command.
  Read them every step; a 403/404/500 behind a page that "looks fine" is a
  finding.
- Finders: `--role/--name`, `--text`, `--testid`, `--css`, `--placeholder`,
  `--has`, `--nth`, `--exact`, `--regex`. Any other driver op: `op <name> '<json>'`
  (see `OPS` in `nanosiem-web/tests/e2e/ui/driver.mjs`).
- Two agents on one stack: give each its own `--session <name>`.
- Need admin for setup (create data the persona cannot)? A second session:
  `--session setup start --admin`. Never use admin to test the persona's view.
- Do not touch anything outside this stack (no nanoch-* containers, no
  :5173/:3000/:3002/:8123).

## Bug classes to hunt (every charter)

1. **OCSF/UDM leftovers.** nano is OCSF-canonical. UDM names (`src_ip`,
   `dest_ip`, `user`, `process_name`, `command_line`, `ext.*`, `source_type`)
   may be ACCEPTED in a query, but must never be suggested, shown as a field,
   used in a placeholder or example, or presented as canonical in help text,
   validation messages, AI output, exports or docs links.
2. **Doubled path prefixes.** `unmapped.unmapped.x`, `actor.actor.user`,
   `event.event.*`, a prefix added twice by a UI that also gets it from the API.
3. **Controls with no effect.** Toggle/select/filter, then DIFF what changed
   (row count, columns, SQL in explain, URL). A control that changes nothing,
   or changes the label but not the data, is a finding.
4. **Cross-surface disagreement.** The same question asked on several
   surfaces must give the same answer: search count vs field stats vs the
   sidebar value counts vs a dashboard panel vs a rule preview/test vs pivt.
   Note the exact query, time range and both numbers.
5. **Console / network errors.** Any `events.console` error or 4xx/5xx in
   `events.network` during a normal task (403s for the persona's own allowed
   features especially).
6. **Idle return.** `idle 10 --reload` (and longer, past token expiry): blank
   page, lost state, logged out without a message, spinner forever.
7. **Empty states.** No data / no permission / no results: does the page say
   which, and what to do? A blank panel or a raw error JSON is a finding.
8. **Unclear validation.** Errors that do not name the field/value, block
   with no reason, or accept bad input silently (e.g. a UDM name reported
   "Valid" with no hint).
9. **UI-convention drift** (CLAUDE.md "UI conventions"): Geist + Geist Mono
   (mono on IDs, IPs, rule names, timestamps, counts); 11-13px body, 10.5px
   mono meta, 24-28px rows; single 1px borders, no shadows except modal/
   popover; stroke-only 24x24 icons at 1.5 stroke; breadcrumb -> title -> meta
   row -> content on every page; no gradients or `rounded-xl` sprawl; "pivt"
   lowercase.

## Evidence format (one block per finding)

```markdown
### F<n>: <one-line symptom, in user terms>
- persona: soc_analyst            edition: enterprise   release: <tag>
- class: ocsf-udm-leftover | doubled-prefix | no-effect-control | cross-surface | console-network | idle-return | empty-state | validation | ui-convention
- severity: blocker | high | medium | low
- where: <route> > <panel/control>
- steps (exact explore commands, copy-pasteable):
  1. `$PY -m nano_e2e.explore search '...' --start 2000-01-01T00:00:00Z`
  2. ...
- expected: <what the OCSF-canonical / consistent behaviour is>
- actual: <what happened; quote the text or the numbers>
- evidence: /tmp/<persona>-<n>.png ; events JSON excerpt (method url status) ; API cross-check (curl or nPL + result)
- reproducible: yes (3/3) | flaky (1/3)
```

Group findings by class, highest severity first. Say what you covered with no
finding too (one line per task), so coverage is visible. Do not file a
finding without a screenshot or a quoted response.
