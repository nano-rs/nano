These are production `lake_query_compile` responses captured by
`mythos_ocsf_40k_point_groups_hunts` / `mythos_ocsf_production_hunts`.
The queries are instantiated in `benchmarks/agent-query/hunts.fixture.json`.
The requests use `table_view=false`, result caching off, and the normal
`audit` source exclusion. Preserve the flag and SQL together: changing only
`table_view` does not reproduce the compiler's different source projection.

The native tests invoke the real compiler and assert execution, exact rows,
producer payload preservation, and cursor continuation. The snapshots provide
fast parser/refusal coverage without loading chDB.
