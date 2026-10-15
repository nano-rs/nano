# Local patch: idle polling

Source: crates.io iceberg-storage-opendal 0.10.1 (registry source pinned in Cargo.lock before this patch).

Only src/lib.rs differs: add a OnceLock HTTP client and an optional HttpClientLayer at the existing operator construction point. With no client installed, upstream behavior is unchanged. This lets the lake count actual requests below Iceberg internal pagination, retries, range reads, and multipart uploads without reimplementing Storage. Credentials, retry/timeout layers, reads, writes, and serialization are unchanged.

Remove this patch once an upstream equivalent is available. The lake installs the same default OpenDAL HttpClient wrapped by its process-local counters before loading any REST catalog.
