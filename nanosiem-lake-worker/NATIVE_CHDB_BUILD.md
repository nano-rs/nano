# Native chDB artifact provenance

`nanosiem-lake-worker` dynamically loads chDB. The library is a build input, not
a runtime download: production images must copy an immutable, checksum-verified
artifact built by CI for the target platform.

## Validated development artifact

The local product validation used the following macOS arm64 artifact:

| Input | Value |
|---|---|
| chDB repository | `chdb-io/chdb` at `3ff61c3f847af0fe9eebcc5a231e67ab96b2fcd2` |
| chDB core / ClickHouse source | `84e403c61e9ea0b3d6a52a131b99c7bf917baa57` |
| `libchdb.so` SHA-256 | `5ff47cfe34a43eadf83e3cf243f2c2826369d99c8b866729767c15a8a87c509e` |
| architecture | Mach-O arm64 |

The core commit contains the fresh-persistent-session `DROP ... SYNC` fix that
was validated separately before being proposed upstream. Do not silently
replace this artifact with a package-manager or PyPI copy: the worker's Iceberg
reader and lifecycle validation apply to this exact native build.

## Reproducible build shape

For each supported production target, CI should:

1. Check out the pinned `chdb-io/chdb` revision recursively and pin its core
   source revision explicitly.
2. Install the toolchain documented by that revision's `CONTRIBUTING.md`.
3. Run `make buildlib` from the chDB core checkout. The documented output is
   `buildlib/libchdb.so` (or the platform-equivalent dynamic library).
4. Record the repository revisions, target triple, compiler versions, build
   command, artifact size, and SHA-256 in the image attestation.
5. Copy the library into the worker image by digest and set
   `native_library_path` to that immutable path.
6. Run the worker's native smoke and lifecycle tests against the copied file,
   including a fresh persistent session followed by `DROP ... SYNC`.

The development checksum above is evidence for the local validation only. A
Linux production artifact needs its own reproducible build and attestation; it
must not claim the macOS checksum.

