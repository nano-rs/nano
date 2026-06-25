# OCSF security audit — findings (NAN-1350)

**Date:** 2026-06-09 · **Range:** `ee9c3f6a..d52c5f87` (NAN-1241 epic + NAN-1299..1348 waves)
**Method:** code trace of the SQL-generation core + profile resolution, live `/api/search/explain`
+ `/api/search` injection probes, and a throwaway in-process generator harness (deleted) that
dumped raw SQL on **both** profiles and ran each payload through `validate_sql_query`.

## Bottom line

**OCSF did not introduce or regress a SQL injection.** Every profile-resolved field flows through
escaping (`escape_identifier` for columns, `escape_string` for values/JSON-path segments,
`sanitize_json_path` for the `ext.` spill). OCSF's dotted columns (`src_endpoint.ip`) always
contain `.`, which forces `escape_identifier` to quote them. UDM behavior is preserved.

One **pre-existing** query-safety gap surfaced (eval alias, **NAN-1352**) — unrelated to OCSF but
in scope for the "general security pass," with only an accidental backstop. Everything else checked
clean.

---

## Finding — eval target alias not escaped → SQL injection on the nPL path (NAN-1352, medium, pre-existing)

`commands.rs:258` interpolates the eval alias raw: `format!("{} AS {}", expr_sql, assignment.field)`.
`eval` is the **only** output-naming command that skips `escape_identifier` (bin/rex/spath/mvexpand/
stats/rename all escape). The alias parses as `alt((quoted_string, field_name))`, and `quoted_string`
accepts any char except the quote — so `eval "a, b"=1` → `SELECT *, 1 AS a, b FROM stage_0` (raw
comma injects a second projection).

Defense today is **incidental and fragile**:
- The nPL path does **not** run `validate_sql_query` (the allowlist/subquery/keyword backstop guards
  only the raw-SQL endpoints). `validate_query_fields` is **not wired into the search path at all**,
  and never validates the eval LHS anyway.
- The only thing blocking it is `enforce_non_audit_query`, which re-parses the **pretty-printed**
  query; the eval pretty-printer emits the alias unquoted, so the round-trip fails to parse. That
  (a) relies on a pretty-print round-trip *bug* and (b) is **skipped for `AUDIT_VIEW` users**, who
  could execute the injected SQL today (bounded by ClickHouse grants — SELECT-only, no DML).

**Fix:** wrap in `escape_identifier` at `commands.rs:258` (byte-identical for normal aliases, matches
all siblings). Detail + repro in NAN-1352.

---

## Verified clean

| Area | Result |
|---|---|
| `field_access_expr` / `field_to_sql_expr` / `by_field_sql` | Every branch escapes — `ExplicitColumn`→`escape_identifier`, `JsonPath`→`escape_string`'d args, `Unknown`→`sanitize_json_path`. Resolved column names come from the manifest (fixed) and are escaped regardless. |
| `generate_json_extract` | Each dot-segment wrapped as an `escape_string`'d string literal; tail column fixed. |
| `identity.rs` (resolve_identity) | `field_escaped` is the already-escaped `field_access_expr` output; `dictGetOrDefault` field/suffix/prefix/default are fixed consts; `user_expr` escaped. |
| stats / rename / bin / rex / spath / mvexpand aliases | All wrap output names in `escape_identifier`; rex/spath patterns `escape_string`'d. |
| Class-split (`class_split_column` / `class_split_value_sql`) | Operate over fixed schema columns; `escape_identifier` on emit. |
| `lateral.rs` seeds | Parameterized via `base_binds`/`execute_lateral_query(&binds)`, not interpolated. NAN-1348 only changed which result-row key is read. |
| Error surfacing (#2062) | Un-masked `Invalid query:` / `Unsupported operation:` messages echo only the user's own field/function names; internal-gen failures + DB errors stay masked. No schema/table/path leakage. |
| Manifest `dest_user → user.name` (#2061) | Intentional duplicate-column mapping (activity_id precedent); correct OCSF semantics (`user`=target, `actor.user.name`=initiator→`src_user`). Points where intended. |
| Wildcard expansion | Legacy `expand_wildcard_pattern` uses an unescaped regex, but it only filters a fixed column list and matched names are escaped on emit — ReDoS/over-match correctness nit, no SQL reach. The new `expand_wildcard` uses `regex::escape`. |
| Raw-SQL endpoint backstop (`validate_sql_query`) | Single-statement, table allowlist on every AST position incl. subqueries/CTEs/joins, table-functions blocked, comments blocked, dangerous-keyword scan. Unchanged by OCSF. |

## Defense-in-depth recommendation (beyond NAN-1352)

The field-format validator (`validate_query_fields`, SECURITY-tagged) is documented as a control but
is **not invoked on the live search/explain path**. Consider wiring it in (or stop relying on it in
docs). It would not, by itself, have caught the eval alias (that arm validates only the RHS).
