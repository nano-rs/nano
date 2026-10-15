# Native cell startup crash capture

The September 30 evidence reports SIGSEGV ~9.4 seconds after first detect
startup, before query memory-budget/service-ready logs. A supervisor restart
succeeds. No fault instruction or native stack was recorded; the cause is
**not confirmed**.

Code inspection rules out the proposed shared role state/tmp directory:
`child::bootstrap` sets separate assignment state/tmp directories and the
query engine places its embedded ClickHouse directory under the role's cwd.
Both detect and query use `open_query_service` / `open_engine_timed`; detect
first exchanges a different credential and loads identity/IOC state before
opening the engine. There is no early model load or role-specific allocator.

Leading native suspects are library constructors in `Library::new`, chDB
connection initialization, and native unload during an early error. In
`part_query/server.rs`, native loading runs concurrently with part-log reads;
a read error can abandon the load task and drop its result. `Api` owns a
`libloading::Library`, so dropping the last runtime unloads the library.
Existing job-path comments in `main.rs` document previous SIGSEGVs during
native teardown/error unwinding. This fits a transient first-start error, but
requires crash evidence before changing ownership or initialization policy.
Stack overflow remains possible. No speculative path, allocator, stack-size,
or scheduling changes were made.

Cell bootstrap installs default-on fatal-signal capture before the jail,
credentials, or runtime. Main, Tokio workers/blocking threads in the cell
query/ingest binaries, and native executor lanes have alternate signal stacks.
Foreign library-created threads get the process-wide handler but must use
ordinary stacks. A native library can also replace a signal handler later.

`lake_native_crash` emits signal number, fault address, interrupted instruction
address (x86_64/aarch64), alternate-stack flags, and bounded `/proc/self/maps`
to stderr, which the supervisor already forwards to tenant logs. It restores
the default signal action and re-raises on the faulting thread. It never dumps
stack/heap/environment contents. All handler I/O uses libc syscalls and fixed
buffers; no allocation, symbol lookup, tracing, or unwinder is called. As with
all stderr crash reporting, a blocked/full log pipe can delay output.

This is a minimal native fault record, **not a full backtrace or core dump**.
The fault PC plus mappings can identify the exact library/function offline:
retain the cell image's exact native artifact and matching debug symbols, find
the PC's mapping, and compute `PC - mapping_start + mapping_file_offset` for
`addr2line`/`llvm-symbolizer` (adjust using ELF PT_LOAD segments if virtual
and file offsets differ). Release Rust binaries are stripped; retain
matching debug artifacts for Rust symbolization. Mapping capture is best effort
and capped at 256 KiB. No kernel core_pattern or live pod access is required.

New begin/complete startup markers delimit credential exchange, identity/IOC,
and engine open without including credentials. Deploy a new **cell image** to
collect the next intermittent failure; API/search/jobs/web images are not
needed. Root-cause confirmation and any resulting fix remain follow-up work.
