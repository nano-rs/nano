# nano SQLx PostgreSQL patch

Vendored from the crates.io sqlx-postgres 0.8.6 package (licenses preserved).
Original package checksum: `db58fcd5a53cf07c184b154801ff91347e4c30d17a3562a635ff028ad5deda46`.
Driver changes:
- `executor.rs::get_or_prepare` ANDs `persistent` with `cache_statement.is_enabled()`.
- `executor.rs::run` sends a fresh unnamed Parse with Bind/Execute, without an
  intervening Sync. Preparation's earlier Sync can release a PgBouncer backend;
  custom-type/argument discovery can also overwrite the unnamed statement.
- `describe.rs` conservatively returns unknown nullability for unnamed statement
  metadata rather than trying unsupported EXPLAIN EXECUTE of an unnamed plan.

Upstream 0.8.6 still allocates named protocol statements when cache capacity is
zero, never inserts them into its disabled cache, and never evicts/closes them.
Multiple clients then collide on `sqlx_s_1` on transaction-pooled backends when
PgBouncer statement tracking is disabled. A zero-capacity connection now uses
unnamed protocol statements. Positive-capacity named statement caching retains upstream behavior.
This also covers internal describe/prepare calls and avoids patching thousands
of application query call sites with `.persistent(false)`.

Regression qualification: `scripts/pgbouncer/local/test.sh`, with PgBouncer
`pool_mode=transaction`, `max_prepared_statements=0`, and two server connections.
The unpatched driver fails the API tests with SQLSTATE 42P05; the patched driver
must pass autocommit/transaction contention, custom-type discovery, lock fencing,
and both zero cached-statements and zero named server statements assertions.
A first unnamed-only patch without Parse/Bind co-location reproduced SQLSTATE
26000 under autocommit contention; the final patch covers that protocol gap.

Remove this override after the selected upstream version implements equivalent
zero-capacity behavior and the same local qualification passes without it.
