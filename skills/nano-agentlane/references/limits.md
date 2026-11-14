# Agent Lane limits and etiquette

Agent Lane runs your queries under a locked-down, read-only ClickHouse profile
at low priority, next to ingest and the analysts' own searches. The limits
below protect the SIEM. Work with them: a refused query costs you a round trip
and teaches you nothing.

## Limits

| Limit | Value | What happens |
|---|---|---|
| Time filter | required on `timestamp` (`observed_at` on `identity_observations`) | Refused with Code 277 |
| Rows and bytes read per query | capped; the admin sizes it from the install's daily volume | Refused with Code 158 / 307 (too many rows or bytes to read) |
| Query time | 60 s | Code 159 (timeout). You may lower it, never raise it |
| Result rows | 100,000 | Code 396 (result too big). You may lower it |
| Result size | 64 MiB | Code 396 |
| Concurrent queries per token | 2 | Code 202 (too many simultaneous queries) |
| Queries, rows read and run time per token | hourly and daily quotas | Code 201 (quota exceeded) until the interval ends |
| Memory per query | capped | Code 241 (memory limit exceeded) |
| Statements per request | 1 | Code 62 (multi-statements are not allowed) |
| Active tokens per install | a maximum set by the admin | The admin can't create another token until one is revoked or expires (HTTP 409 in Settings → Agent Lane); not a query error |

The time filter is enforced but **does not bound the range**.
`timestamp > '2000-01-01'` passes the check and then scans everything until a
read cap stops it. Bound the range yourself.

## How to work

1. **Start with 24 hours.** `WHERE timestamp >= now() - INTERVAL 24 HOUR`.
   For a known incident, use explicit bounds:
   `timestamp BETWEEN '2026-11-12 08:00:00' AND '2026-11-12 14:00:00'`
   (UTC unless you set `session_timezone`).
2. **Widen on purpose.** If 24 h finds nothing, try 3 d, then 7 d, then 30 d,
   and say each time why you widened. Data is kept for 365 days, but a year-wide
   scan of a busy install will hit the read cap.
3. **Aggregate before you pull rows.** `count()`, `uniq()`, top-N with
   `GROUP BY … ORDER BY … LIMIT`, or a timechart tells you where to look. Then
   fetch rows for the narrow slice.
4. **Always LIMIT.** 20 to 100 rows is usually enough to read. Pull more only
   when you'll process them, not to show them.
5. **Select the columns you need.** `SELECT *` on `ocsf_logs` carries
   `raw_data` and the `event` JSON, and fills the 64 MiB cap fast.
6. **Filter on the sort key.** `ocsf_logs` is sorted by
   `(class_uid, source_type, timestamp, src_endpoint.ip)`. A `class_uid` or
   `source_type` filter skips most of the data.
7. **Use the indexed forms** in [schema.md](schema.md) for text, user, host,
   IP and hash filters. ClickHouse matches an index by its exact expression.
8. **One WHERE clause, no PREWHERE.** ClickHouse moves filters to PREWHERE
   itself. An explicit PREWHERE turns that off and reads more.
9. **Set `log_comment` to your session id** on every query. It's how the
   audit log groups your queries.
10. **Run queries one at a time** unless they are independent and small. You
    get 2 concurrent queries per token.

## Errors and what to do

Every error comes back as a non-200 HTTP status with `Code: NNN.
DB::Exception: …` in the body.

| Code | Name | Do this |
|---|---|---|
| 277 | INDEX_NOT_USED | Add a time filter on `timestamp` (or `observed_at`) to the WHERE clause. |
| 158, 307 | TOO_MANY_ROWS / TOO_MANY_BYTES (read) | Narrow the window, add a `class_uid` / `source_type` filter, or use an indexed predicate. |
| 159 | TIMEOUT_EXCEEDED | Same as above; also aggregate instead of sorting raw rows. |
| 396 | TOO_MANY_ROWS_OR_BYTES (result) | Aggregate, select fewer columns, or LIMIT. |
| 241 | MEMORY_LIMIT_EXCEEDED | Reduce `GROUP BY` cardinality, or narrow the window. |
| 201 | QUOTA_EXCEEDED | Stop. The message names the interval end; wait until then. Tell the operator. |
| 202 | TOO_MANY_SIMULTANEOUS_QUERIES | Wait for a running query to finish, then retry once. |
| 497 | ACCESS_DENIED | The table, function or dictionary is not granted to Agent Lane. Use a granted table instead. |
| 164 | READONLY | The setting can't be changed on the lane. Remove it. |
| 452 | SETTING_CONSTRAINT_VIOLATION | You tried to raise a capped setting. Remove it or lower it. |
| 62 | SYNTAX_ERROR | Fix the SQL. One statement per request; no trailing second statement. |
| 47 | UNKNOWN_IDENTIFIER | Wrong column name. Check backticks around dotted names and the schema reference. |
| 60 | UNKNOWN_TABLE | On a cluster, use `<table>_distributed`. Run the `tables_available` recipe. |
| 516 | AUTHENTICATION_FAILED | Token expired, revoked, mis-split, or your IP isn't allowed. Ask the admin. Don't retry in a loop. |

Back off on 201 and 202. Never retry a refused query unchanged.

## What the lane refuses

- Writes of any kind: INSERT, ALTER, CREATE, DROP, OPTIMIZE, SYSTEM, KILL.
- Table functions (`url`, `s3`, `file`, `remote`, `cluster`, `executable`,
  `dictionary`…) and `dictGet`. `numbers()` is allowed.
- `system.*` tables other than `system.one`, `system.tables` and
  `system.columns` (both show only the tables you can read), and
  `system.settings`.
- Raw ingest errors (`ingestion_errors`) and the source-less prevalence
  tables (`*_prevalence_summary`, `*_prevalence_agg`).
- nano's own audit events (`source_type = 'audit'`): hidden, not refused.
  Queries run normally and those rows aren't there.

## Settings you may set

Only these, in the `SETTINGS` clause or as URL parameters:

- `log_comment`, `session_timezone`;
- `default_format` and the `FORMAT` clause (`JSONCompact`, `JSONEachRow`,
  `TSVWithNames`, `CSVWithNames`…);
- `date_time_output_format`, `output_format_json_quote_64bit_integers`,
  `output_format_json_named_tuples_as_objects`, `enable_http_compression`;
- `max_execution_time` and `max_result_rows`, lower than the caps only.

Everything else, such as `max_threads`, `max_memory_usage` or
`distributed_product_mode` (pinned to `'global'`), is refused.
