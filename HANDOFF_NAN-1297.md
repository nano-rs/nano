# Handoff — NAN-1297: AI re-triage (verdict drives severity + priority)

Branch: `feat/NAN-1241-ocsf-schema-support`. Linear: **NAN-1297** (Backlog).
Foundation committed in `6eab9707`.

## STATUS: FEATURE COMPLETE (uncommitted working tree)
All "Remaining work" below is now implemented. Builds clean:
`cargo check --tests -p nanosiem-core -p nanosiem-enterprise`, `tsc -b`, and
`cargo test -p nanosiem-enterprise shadow_investigation::` all green.
Decision made on the open knob: **reused `auto_close_min_confidence`** as the
escalation floor (no separate setting). The UI shows the pending-escalation
prompt only; the "applied" marker was intentionally dropped (can't distinguish
auto-applied from "AI agrees with current severity" without an extra column, and
the wall entry + severity badge already record it).
Next step: `/code-review-expert` → commit → push. Verify steps in §4 unchanged.

---
Original remaining-work plan (all done) below for reference:

## Goal / design (locked with user)
The AI shadow-investigation verdict should **re-triage** the case symmetrically:
- **TP** (high confidence) → **escalate** severity + priority.
- **FP/benign** → close (already exists via `maybe_auto_close`).
- **Both levers** move; the model **decides** the new severity; priority is derived from severity.
- **Gated by autonomy** (mirrors auto_close): `recommend_only` (default) = surface a
  recommendation, don't mutate; auto mode = apply, gated by a min-confidence floor.
- **UI** lives in the **AI cases view** (`AiVerdictStrip.tsx`), showing current→recommended
  severity/priority + Accept/Dismiss (recommend_only) / "applied" marker (auto).

Open knob the user didn't pin down: reuse `case_auto_close_min_confidence` as the escalate
floor, **or** add a separate `case_auto_escalate_min_confidence`. Default chosen: reuse
auto_close_min_confidence unless they ask otherwise.

## DONE (6eab9707)
- `shadow_investigation/verdict.rs`: added `recommended_severity` to the JSON schema (enum
  critical/high/medium/low/informational) + `StructuredVerdict.recommended_severity: Option<String>`.
- `migrations/postgres-enterprise/9000015_case_ai_recommended_severity.sql`: adds
  `cases.ai_recommended_severity TEXT`. (Highest enterprise migration is now 9000015.)
- Compiles (`cargo check -p nanosiem-enterprise`).

## Remaining work (every file + the drift traps)

### 1. Persist the recommendation
- `nanosiem-core/src/models/case.rs`:
  - `UpdateCaseAiVerdict` (~576): add `pub ai_recommended_severity: Option<String>,`.
  - `Case` (251), `CaseWithDetails` (350), `CaseWithDetailsRow` (451): add the same field
    next to `ai_confidence`/`ai_recommended_action`.
- `nanosiem-core/src/db/repository/cases/crud.rs`:
  - `update_ai_verdict` (~819): add `ai_recommended_severity = $7` to the SET and
    `.bind(&verdict.ai_recommended_severity)` (uses `RETURNING *` — safe).
  - **DRIFT TRAP** — the list query SELECT (~404) is an **explicit column list** (it names
    `c.ai_confidence, c.ai_recommended_action`). You MUST add `c.ai_recommended_severity`
    there in the same change as the `CaseWithDetailsRow` struct field, or `query_as` 500s at
    runtime (this is exactly the ai_confidence/NUMERIC bug class — NAN-1292). `Case` queries
    use `SELECT *`/`RETURNING *`, so those are safe.
  - If `CaseWithDetails` is built by transforming `CaseWithDetailsRow`, map the new field there too.
- `shadow_investigation/investigation.rs` (~1440): add
  `ai_recommended_severity: verdict.recommended_severity.clone(),` to the `UpdateCaseAiVerdict {…}`.

### 2. Symmetric auto-escalation
- `shadow_investigation/disposition_action.rs`: today `maybe_auto_close` only closes FP/benign
  in `AutonomyMode::AutoClose` (gated by `auto_close_min_confidence`, severity ≤
  `auto_close_max_severity`). Add the TP branch: in auto mode, when disposition is actionable
  (TP) AND confidence ≥ floor AND `verdict.recommended_severity` is set and MORE severe than
  current → apply via the existing `CaseRepository` update (`UpdateCase` already has
  `severity: Option<Severity>` + `priority: Option<i32>`). Thread `recommended_severity` from the
  `maybe_auto_close(...)` call site in investigation.rs (~1474). Add a `severity_str → priority i32`
  mapping helper (severity_rank already exists at the top of disposition_action.rs).
- Keep `recommend_only` a no-op (the recommendation is persisted in step 1, surfaced by the UI).

### 3. UI — `nanosiem-web`
- `Case` API type (`src/lib/api/types.ts`): add `ai_recommended_severity?: string` (+ priority is
  already there).
- `src/enterprise/components/case-investigate/AiVerdictStrip.tsx`: render disposition + confidence
  (already there) PLUS, when `ai_recommended_severity` differs from `severity`: a
  "current → recommended" severity row and the derived priority. In recommend_only: **Accept**
  (calls the existing case-update API with `{severity, priority}`) / **Dismiss**. In auto mode the
  case already shows the applied severity; show an "AI-escalated" marker (analogous to `ai_closed`).
- No new endpoint needed — `UpdateCase` (PATCH case) already accepts severity + priority.

### 4. Verify
- `cargo check -p nanosiem-enterprise` (+ -p nanosiem-core), `cargo test` for case crud if touched.
- `npm run build` / `tsc -b` in nanosiem-web.
- Live test: set autonomy to auto, run the injector, confirm a high-confidence TP case escalates
  severity+priority; set recommend_only, confirm the strip shows the recommendation + Accept works.
- Migration auto-applies on next stack rebuild.

## Session context (broader)
This was a long OCSF-hardening session. Feat branch is **ahead 14 of origin, unpushed**.
Standing decisions still open for the user:
- **Push** `feat/NAN-1241-ocsf-schema-support` to origin.
- **NAN-1292** (cases.ai_confidence NUMERIC→double precision) is committed on feat but is a
  general prod-affecting bug — user may want it cherry-picked to a fast standalone `main` PR.
- A rebuild/restart deploys all the session's Rust changes (grouping/entity/hunt/agents); the
  frontend changes are already live via HMR.

Key shipped this session (all on feat): demo-ocsf rules (separate `nano-rs/rules` PR #4, merged);
OCSF matches entity/timeline, EntityExtractor, prevalence `l.if`, shadow entity extraction,
OCSF-native hunt prompt + all ~12 melod agents, schema-aware entity classification everywhere
(NAN-1296: grouping + EntityExtractor + frontend), case-grouping device.hostname fix, hunt
sequence-alias + time_dt fixes, tuning cleanup, ai_confidence live-patch+migration.
