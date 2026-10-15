// SPDX-License-Identifier: AGPL-3.0-or-later

//! Digest-pinned bindings to the stable chDB C ABI.

use libloading::Library;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fs::File;
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::{Duration, Instant};

const SHA256_HEX_LENGTH: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum NativeChdbError {
    #[error("native chDB artifact does not exist: {0}")]
    MissingLibrary(PathBuf),
    #[error("native chDB artifact digest must be 64 lowercase hexadecimal characters")]
    InvalidExpectedDigest,
    #[error("native chDB artifact digest mismatch")]
    DigestMismatch,
    #[error("failed to read native chDB artifact: {0}")]
    LibraryRead(#[source] std::io::Error),
    #[error("failed to load native chDB artifact: {0}")]
    LibraryLoad(#[source] libloading::Error),
    #[error("native chDB artifact is missing required symbol {symbol}: {source}")]
    MissingSymbol {
        symbol: &'static str,
        #[source]
        source: libloading::Error,
    },
    #[error("chDB connection failed")]
    ConnectionFailed,
    #[error("query parameter name is invalid: {0}")]
    InvalidParameterName(String),
    #[error("query parameter name is duplicated: {0}")]
    DuplicateParameter(String),
    #[error("query text, format, argument, or parameter contains a NUL byte")]
    InteriorNul,
    #[error("chDB returned no query result")]
    NoResult,
    #[error("chDB query failed: {0}")]
    Query(String),
    #[error("the native chDB artifact does not export the streaming query ABI")]
    StreamingUnsupported,
}

type Result<T> = std::result::Result<T, NativeChdbError>;

#[repr(C)]
struct ChdbConnection {
    _internal_data: *mut c_void,
}

type ChdbConnectionHandle = *mut ChdbConnection;

#[repr(C)]
struct ChdbResult {
    _internal_data: *mut c_void,
}

type ConnectFn = unsafe extern "C" fn(c_int, *mut *mut c_char) -> *mut ChdbConnectionHandle;
type CloseFn = unsafe extern "C" fn(*mut ChdbConnectionHandle);
type QueryWithParamsFn = unsafe extern "C" fn(
    ChdbConnectionHandle,
    *const c_char,
    *const c_char,
    *const *const c_char,
    *const *const c_char,
    usize,
) -> *mut ChdbResult;
type ResultBufferFn = unsafe extern "C" fn(*mut ChdbResult) -> *mut c_char;
type ResultLengthFn = unsafe extern "C" fn(*mut ChdbResult) -> usize;
type ResultElapsedFn = unsafe extern "C" fn(*mut ChdbResult) -> f64;
type ResultCounterFn = unsafe extern "C" fn(*mut ChdbResult) -> u64;
type ResultErrorFn = unsafe extern "C" fn(*mut ChdbResult) -> *const c_char;
type DestroyResultFn = unsafe extern "C" fn(*mut ChdbResult);
type VersionFn = unsafe extern "C" fn() -> *const c_char;
type SetSignalHandlersEnabledFn = unsafe extern "C" fn(c_int);
type StreamFetchFn = unsafe extern "C" fn(ChdbConnectionHandle, *mut ChdbResult) -> *mut ChdbResult;
type StreamCancelFn = unsafe extern "C" fn(ChdbConnectionHandle, *mut ChdbResult);

/// chDB's streaming query ABI (NAN-3060). Optional: an artifact without it
/// still serves every materialized query; only streamed reads are refused.
#[derive(Clone, Copy)]
struct StreamApi {
    query_with_params: QueryWithParamsFn,
    fetch: StreamFetchFn,
    cancel: StreamCancelFn,
}

struct Api {
    // chDB owns process-global pools/TLS beyond the final connection. dlclose
    // can run its finalizers on a lane thread concurrently with process exit.
    // Keep native code mapped until the OS tears down the process; callers
    // must not need to leak a runtime clone themselves to stay safe.
    _library: std::mem::ManuallyDrop<Library>,
    connect: ConnectFn,
    close: CloseFn,
    query_with_params: QueryWithParamsFn,
    result_buffer: ResultBufferFn,
    result_length: ResultLengthFn,
    result_elapsed: ResultElapsedFn,
    result_storage_rows_read: ResultCounterFn,
    result_storage_bytes_read: ResultCounterFn,
    result_error: ResultErrorFn,
    destroy_result: DestroyResultFn,
    version: VersionFn,
    /// `chdb_set_signal_handlers_enabled` (optional export; NAN-3141).
    set_signal_handlers_enabled: Option<SetSignalHandlersEnabledFn>,
    stream: Option<StreamApi>,
}

impl Api {
    unsafe fn load(path: &Path) -> Result<Self> {
        // chDB's bundled getauxval falls back to walking beyond environ when
        // procfs is denied. setenv may have moved environ to the heap, where
        // no auxv follows it; __vdsosym then dereferences a bogus ELF address.
        // Never enter that initialization path inside a non-dumpable jail.
        File::open("/proc/self/auxv").map_err(NativeChdbError::LibraryRead)?;
        // SAFETY: the artifact's exact bytes were verified before this call.
        let library = unsafe { Library::new(path) }.map_err(NativeChdbError::LibraryLoad)?;
        macro_rules! symbol {
            ($name:literal, $ty:ty) => {{
                // SAFETY: each symbol type below is copied from chDB's stable C header.
                *unsafe { library.get::<$ty>(concat!($name, "\0").as_bytes()) }.map_err(
                    |source| NativeChdbError::MissingSymbol {
                        symbol: $name,
                        source,
                    },
                )?
            }};
        }
        Ok(Self {
            connect: symbol!("chdb_connect", ConnectFn),
            close: symbol!("chdb_close_conn", CloseFn),
            query_with_params: symbol!("chdb_query_with_params", QueryWithParamsFn),
            result_buffer: symbol!("chdb_result_buffer", ResultBufferFn),
            result_length: symbol!("chdb_result_length", ResultLengthFn),
            result_elapsed: symbol!("chdb_result_elapsed", ResultElapsedFn),
            result_storage_rows_read: symbol!("chdb_result_storage_rows_read", ResultCounterFn),
            result_storage_bytes_read: symbol!("chdb_result_storage_bytes_read", ResultCounterFn),
            result_error: symbol!("chdb_result_error", ResultErrorFn),
            destroy_result: symbol!("chdb_destroy_query_result", DestroyResultFn),
            version: symbol!("chdb_version", VersionFn),
            set_signal_handlers_enabled: {
                // SAFETY: the type is copied from chDB's C header.
                unsafe { library.get::<SetSignalHandlersEnabledFn>(b"chdb_set_signal_handlers_enabled\0") }.ok().map(|symbol| *symbol)
            },
            stream: {
                // SAFETY: the types are copied from chDB's stable C header.
                let optional = |name: &[u8]| unsafe { library.get::<*const c_void>(name) }.is_ok();
                if optional(b"chdb_stream_query_with_params\0")
                    && optional(b"chdb_stream_fetch_result\0")
                    && optional(b"chdb_stream_cancel_query\0")
                {
                    Some(StreamApi {
                        query_with_params: symbol!("chdb_stream_query_with_params", QueryWithParamsFn),
                        fetch: symbol!("chdb_stream_fetch_result", StreamFetchFn),
                        cancel: symbol!("chdb_stream_cancel_query", StreamCancelFn),
                    })
                } else {
                    None
                }
            },
            _library: std::mem::ManuallyDrop::new(library),
        })
    }
}

/// A verified native chDB runtime. Connections retain the loaded artifact.
#[derive(Clone)]
pub struct NativeChdb {
    api: Arc<Api>,
    artifact_path: PathBuf,
    artifact_sha256: String,
}

static CELL_RUNTIME: std::sync::OnceLock<NativeChdb> = std::sync::OnceLock::new();

/// Load only the root-owned release artifact, before tenant confinement.
/// Retain it for the process lifetime: unloading loses chDB's auxv cache.
pub fn initialize_cell_runtime() -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let path = Path::new("/usr/local/lib/nano-chdb/libchdb.so");
    let digest_path = path.with_file_name("libchdb.sha256");
    for artifact in [path, digest_path.as_path()] {
        for component in artifact.ancestors() {
            let metadata = std::fs::symlink_metadata(component)?;
            anyhow::ensure!(
                !metadata.file_type().is_symlink() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                "native release path must be root-owned and immutable: {}",
                component.display()
            );
        }
        anyhow::ensure!(artifact.is_file(), "native release artifact is not a file");
    }
    let digest = std::fs::read_to_string(digest_path)?;
    let runtime = NativeChdb::load_verified(path, digest.trim())?;
    anyhow::ensure!(CELL_RUNTIME.set(runtime).is_ok(), "cell native runtime already initialized");
    Ok(())
}

fn cell_runtime(path: &Path, digest: &str) -> Result<Option<NativeChdb>> {
    match CELL_RUNTIME.get() {
        Some(runtime) if path == runtime.artifact_path && digest == runtime.artifact_sha256 => Ok(Some(runtime.clone())),
        Some(_) => Err(NativeChdbError::DigestMismatch),
        None => Ok(None),
    }
}

impl NativeChdb {
    /// Verify the exact native artifact before loading any executable code.
    pub fn load_verified(path: impl AsRef<Path>, expected_sha256: &str) -> Result<Self> {
        let path = path.as_ref();
        if let Some(runtime) = cell_runtime(path, expected_sha256)? {
            return Ok(runtime);
        }
        if !path.is_file() {
            return Err(NativeChdbError::MissingLibrary(path.to_path_buf()));
        }
        if expected_sha256.len() != SHA256_HEX_LENGTH
            || !expected_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(NativeChdbError::InvalidExpectedDigest);
        }
        let actual = file_sha256_without_retained_cache(path)?;
        if actual != expected_sha256 {
            return Err(NativeChdbError::DigestMismatch);
        }
        // SAFETY: Api::load resolves a fixed required symbol set from the
        // verified artifact and copies the function pointers before storing
        // the Library for the process lifetime (chDB's pools/TLS outlive
        // individual connections).
        let api = unsafe { Api::load(path)? };
        Ok(Self {
            api: Arc::new(api),
            artifact_path: path.to_path_buf(),
            artifact_sha256: actual,
        })
    }

    pub fn artifact_path(&self) -> &Path {
        &self.artifact_path
    }

    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    pub fn version(&self) -> Result<String> {
        // SAFETY: the function pointer belongs to the retained Library.
        let version = unsafe { (self.api.version)() };
        if version.is_null() {
            return Err(NativeChdbError::ConnectionFailed);
        }
        // SAFETY: chDB documents a non-null, NUL-terminated static string.
        Ok(unsafe { CStr::from_ptr(version) }
            .to_string_lossy()
            .into_owned())
    }

    pub fn connect(&self, args: &[&str]) -> Result<NativeConnection> {
        NativeConnection::open(self.api.clone(), args)
    }

    /// Whether the artifact exports chDB's streaming query ABI.
    pub fn supports_streaming(&self) -> bool {
        self.api.stream.is_some()
    }
}

/// Observable boundaries of stream initialization. The native ABI call includes
/// SQL analysis, planning and file setup; it exposes no timers within that call.
#[derive(Default, Debug)]
pub struct NativeInitTimings {
    pub bind_ms: f64,
    pub abi_ms: f64,
}

pub struct NativeConnection {
    api: Arc<Api>,
    inner: NonNull<ChdbConnectionHandle>,
}

impl NativeConnection {
    fn open(api: Arc<Api>, args: &[&str]) -> Result<Self> {
        let arguments = std::iter::once("clickhouse")
            .chain(args.iter().copied())
            .map(CString::new)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| NativeChdbError::InteriorNul)?;
        let mut pointers = arguments
            .iter()
            .map(|argument| argument.as_ptr().cast_mut())
            .collect::<Vec<_>>();
        disable_engine_signal_handlers(&api);
        // SAFETY: pointers remain valid for the call and argc matches argv.
        let raw = unsafe { (api.connect)(pointers.len() as c_int, pointers.as_mut_ptr()) };
        // Starting the engine runs Poco::Application's constructor, which
        // installs Poco's own SIGSEGV/SIGBUS/SIGILL/SIGSYS handlers.
        reinstall_crash_capture();
        let inner = NonNull::new(raw).ok_or(NativeChdbError::ConnectionFailed)?;
        // SAFETY: a successful chdb_connect returns a pointer to its handle.
        if unsafe { *inner.as_ptr() }.is_null() {
            // SAFETY: even a null inner handle must release the outer allocation.
            unsafe { (api.close)(inner.as_ptr()) };
            return Err(NativeChdbError::ConnectionFailed);
        }
        Ok(Self { api, inner })
    }

    /// Execute one query with typed, server-side named parameters.
    pub fn query_with_params(
        &self,
        sql: &str,
        format: &str,
        params: &[(&str, &str)],
    ) -> Result<NativeQueryOutput> {
        let raw = self.start(self.api.query_with_params, sql, format, params, None)?;
        let result = NonNull::new(raw).ok_or(NativeChdbError::NoResult)?;
        let guard = NativeResult {
            api: self.api.clone(),
            inner: result,
        };
        guard.into_output(params)
    }

    /// Start one streamed query (NAN-3060): chDB executes the statement once
    /// and hands its output back block by block through
    /// [`NativeStream::fetch`], so no caller ever holds the whole result.
    /// The connection runs nothing else until the stream is dropped.
    pub fn stream_query_with_params<'a>(
        &'a self,
        sql: &str,
        format: &str,
        params: &[(&str, &str)],
    ) -> Result<NativeStream<'a>> {
        self.stream_query_with_params_timed(sql, format, params, &mut NativeInitTimings::default())
    }

    /// As above, recording binding and the native call even when init fails.
    pub fn stream_query_with_params_timed<'a>(
        &'a self,
        sql: &str,
        format: &str,
        params: &[(&str, &str)],
        timings: &mut NativeInitTimings,
    ) -> Result<NativeStream<'a>> {
        let stream = self.api.stream.ok_or(NativeChdbError::StreamingUnsupported)?;
        let raw = self.start(stream.query_with_params, sql, format, params, Some(timings))?;
        let handle = NonNull::new(raw).ok_or(NativeChdbError::NoResult)?;
        let stream = NativeStream {
            connection: self,
            handle: NativeResult { api: self.api.clone(), inner: handle },
            api: stream,
            params: params.iter().map(|(_, value)| (*value).to_string()).collect(),
            finished: false,
            failed: false,
        };
        // An init failure (parse, analysis, unknown column) is reported on
        // the stream handle itself.
        stream.handle_error()?;
        Ok(stream)
    }

    fn start(
        &self,
        entry: QueryWithParamsFn,
        sql: &str,
        format: &str,
        params: &[(&str, &str)],
        mut timings: Option<&mut NativeInitTimings>,
    ) -> Result<*mut ChdbResult> {
        let bind_started = Instant::now();
        validate_params(params)?;
        #[cfg(feature = "part-lab")]
        if let Some(dir) = std::env::var_os("NAN3152_SQL_DUMP_DIR") {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let mut text = format!("{sql}\n-- params\n");
            for (name, value) in params {
                text.push_str(&format!("-- {name} = {value}\n"));
            }
            let _ = std::fs::write(std::path::Path::new(&dir).join(format!("{n:05}.sql")), text);
        }
        let query = CString::new(sql).map_err(|_| NativeChdbError::InteriorNul)?;
        let format = CString::new(format).map_err(|_| NativeChdbError::InteriorNul)?;
        let names = params
            .iter()
            .map(|(name, _)| CString::new(*name))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| NativeChdbError::InteriorNul)?;
        let values = params
            .iter()
            .map(|(_, value)| CString::new(*value))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| NativeChdbError::InteriorNul)?;
        let name_pointers = names.iter().map(|name| name.as_ptr()).collect::<Vec<_>>();
        let value_pointers = values
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        if let Some(timings) = timings.as_deref_mut() {
            timings.bind_ms += bind_started.elapsed().as_secs_f64() * 1000.0;
        }
        let abi_started = Instant::now();
        // SAFETY: all C strings and pointer arrays live through the call. The
        // connection handle is owned by self and chDB scopes parameters to the
        // call (a stream captures them before its init returns).
        let raw = unsafe {
            entry(
                *self.inner.as_ptr(),
                query.as_ptr(),
                format.as_ptr(),
                name_pointers.as_ptr(),
                value_pointers.as_ptr(),
                params.len(),
            )
        };
        if let Some(timings) = timings {
            timings.abi_ms += abi_started.elapsed().as_secs_f64() * 1000.0;
        }
        Ok(raw)
    }
}

/// One streamed statement on a connection (see
/// [`NativeConnection::stream_query_with_params`]). Dropping it before the
/// end cancels the statement.
pub struct NativeStream<'a> {
    connection: &'a NativeConnection,
    handle: NativeResult,
    api: StreamApi,
    params: Vec<String>,
    finished: bool,
    failed: bool,
}

impl NativeStream<'_> {
    fn handle_error(&self) -> Result<()> {
        // SAFETY: the accessor is valid while the handle is alive.
        let error = unsafe { (self.handle.api.result_error)(self.handle.inner.as_ptr()) };
        if error.is_null() {
            return Ok(());
        }
        // SAFETY: chDB documents a NUL-terminated error string.
        let message = unsafe { CStr::from_ptr(error) }.to_string_lossy();
        if message.is_empty() {
            return Ok(());
        }
        let params = self.params.iter().map(|value| ("_", value.as_str())).collect::<Vec<_>>();
        Err(query_error(&message, &params))
    }

    /// The next block of output, `None` at the end of the result. An error
    /// ends the stream.
    pub fn fetch(&mut self) -> Result<Option<NativeQueryOutput>> {
        if self.finished || self.failed {
            return Ok(None);
        }
        // SAFETY: the connection outlives this stream (borrowed) and the
        // handle came from a stream init on it; fetches are serialized by
        // `&mut self`.
        let raw = unsafe { (self.api.fetch)(*self.connection.inner.as_ptr(), self.handle.inner.as_ptr()) };
        let Some(inner) = NonNull::new(raw) else {
            self.failed = true;
            return Err(NativeChdbError::NoResult);
        };
        let chunk = NativeResult {
            api: self.handle.api.clone(),
            inner,
        };
        let params = self.params.iter().map(|value| ("_", value.as_str())).collect::<Vec<_>>();
        match chunk.into_output(&params) {
            Ok(output) if output.data.is_empty() => {
                self.finished = true;
                Ok(None)
            }
            Ok(output) => Ok(Some(output)),
            Err(error) => {
                // An error is terminal for the reader, but is not natural
                // EOF. Drop must cancel before destroying the stream handle
                // and before the executor closes the failed connection.
                self.failed = true;
                Err(error)
            }
        }
    }

    /// Whether the statement ran to its natural end.
    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

impl Drop for NativeStream<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // SAFETY: as in `fetch`; cancel leaves the handle to be destroyed
            // by `NativeResult`'s drop.
            unsafe { (self.api.cancel)(*self.connection.inner.as_ptr(), self.handle.inner.as_ptr()) };
        }
    }
}

impl Drop for NativeConnection {
    fn drop(&mut self) {
        // SAFETY: this connection is uniquely owned and closed exactly once.
        unsafe { (self.api.close)(self.inner.as_ptr()) };
    }
}

struct NativeResult {
    api: Arc<Api>,
    inner: NonNull<ChdbResult>,
}

impl NativeResult {
    fn into_output(&self, params: &[(&str, &str)]) -> Result<NativeQueryOutput> {
        // SAFETY: accessors are valid while this result handle is alive.
        let error = unsafe { (self.api.result_error)(self.inner.as_ptr()) };
        if !error.is_null() {
            // SAFETY: chDB documents a NUL-terminated error string.
            let message = unsafe { CStr::from_ptr(error) }.to_string_lossy();
            if !message.is_empty() {
                return Err(query_error(&message, params));
            }
        }
        // SAFETY: chDB owns the buffer until the result is destroyed below.
        let length = unsafe { (self.api.result_length)(self.inner.as_ptr()) };
        let buffer = unsafe { (self.api.result_buffer)(self.inner.as_ptr()) };
        let data = if buffer.is_null() || length == 0 {
            Vec::new()
        } else {
            // SAFETY: the result reports a buffer containing exactly length bytes.
            unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) }.to_vec()
        };
        let elapsed_seconds = unsafe { (self.api.result_elapsed)(self.inner.as_ptr()) };
        if !elapsed_seconds.is_finite() || elapsed_seconds.is_sign_negative() {
            return Err(NativeChdbError::Query(
                "native result reported an invalid elapsed time".to_string(),
            ));
        }
        Ok(NativeQueryOutput {
            data,
            elapsed: Duration::from_secs_f64(elapsed_seconds),
            // SAFETY: scalar accessors are valid for this live result.
            storage_rows_read: unsafe { (self.api.result_storage_rows_read)(self.inner.as_ptr()) },
            storage_bytes_read: unsafe {
                (self.api.result_storage_bytes_read)(self.inner.as_ptr())
            },
        })
    }
}

/// NAN-3141: embedded chDB's deadly-signal handler is a server design: it
/// marks the engine crashed, hands the fault to a SignalListener thread that
/// embedded chDB never starts (so nothing is logged), parks the faulting
/// thread for ~303 s and only then re-raises. Meanwhile every query in the
/// process fails with Code 236 and no reconnect can clear the flag. The
/// engine's handlers are disabled before the first connect and the cell's
/// async-signal-safe crash record (`lake_native_crash signal= pc=` + maps on
/// stderr, then the default action) owns the deadly signals instead: a
/// fault kills the process at once and the supervisor restarts it.
fn disable_engine_signal_handlers(api: &Api) {
    static DISABLED: std::sync::Once = std::sync::Once::new();
    if let Some(set_enabled) = api.set_signal_handlers_enabled {
        // SAFETY: a plain flag store plus sigaction(SIG_DFL) in the library.
        DISABLED.call_once(|| unsafe { set_enabled(0) });
    }
}

/// Re-own SIGSEGV/SIGBUS/SIGILL/SIGABRT/SIGFPE with the crash record. Cheap
/// and idempotent; run after every connect (a recycled engine reinstalls
/// Poco's handlers).
fn reinstall_crash_capture() {
    if let Err(error) = nanosiem_lake_cell::crash_capture::install() {
        eprintln!("lake_native_crash handler reinstall failed: {error}");
    }
}

/// The text chDB answers every query with once a fatal signal marked the
/// engine crashed (`executeQuery`: `isCrashed()`, ErrorCodes::ABORTED).
pub const FATAL_ENGINE_ERROR: &str = "The server is shutting down due to a fatal error";
/// Exit status of a process whose engine reported [`FATAL_ENGINE_ERROR`].
pub const FATAL_ENGINE_EXIT_CODE: i32 = 70;
static EXIT_ON_FATAL_ENGINE_ERROR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Tests only: report a crashed engine as an error instead of exiting.
#[doc(hidden)]
pub fn set_exit_on_fatal_engine_error(exit: bool) {
    EXIT_ON_FATAL_ENGINE_ERROR.store(exit, std::sync::atomic::Ordering::SeqCst);
}

/// Whether a chDB error says the engine is permanently crashed (Code 236).
/// Only the engine's OWN error counts: chDB echoes query text into other
/// errors (e.g. a syntax error quoting a string literal), so matching the
/// phrase anywhere would let a search kill its query process on demand.
pub fn is_fatal_engine_error(message: &str) -> bool {
    // The FIRST "Code: " is the error being reported; anything after it may
    // be echoed input. Wrapper prefixes ("chDB query failed: ") are fine.
    message.find("Code: ").is_some_and(|at| message[at..]
        .starts_with(concat!("Code: 236. DB::Exception: ", "The server is shutting down due to a fatal error")))
}

fn query_error(message: &str, params: &[(&str, &str)]) -> NativeChdbError {
    let sanitized = sanitize_query_error(message, params);
    if is_fatal_engine_error(&sanitized) && EXIT_ON_FATAL_ENGINE_ERROR.load(std::sync::atomic::Ordering::SeqCst) {
        exit_on_fatal_engine_error(&sanitized);
    }
    NativeChdbError::Query(sanitized)
}

/// A crashed engine never recovers in this process: log and exit so the
/// supervisor respawns it. `_exit`, not `exit`: static destructors would run
/// against an engine with a thread parked in its signal handler.
fn exit_on_fatal_engine_error(message: &str) -> ! {
    tracing::error!(error = %message, exit_code = FATAL_ENGINE_EXIT_CODE,
        "native chDB engine is crashed (Code 236); exiting so the supervisor restarts this process");
    eprintln!("lake_native_fatal exit_code={FATAL_ENGINE_EXIT_CODE} error={message}");
    // SAFETY: terminates the process without running any further user code.
    unsafe { libc::_exit(FATAL_ENGINE_EXIT_CODE) }
}

fn sanitize_query_error(message: &str, params: &[(&str, &str)]) -> String {
    let mut sanitized = message.to_string();
    let mut values = params
        .iter()
        .map(|(_, value)| *value)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort_unstable_by_key(|value| std::cmp::Reverse(value.len()));
    values.dedup();
    for value in values {
        sanitized = sanitized.replace(value, "[PARAM]");
        let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
        if escaped != value {
            sanitized = sanitized.replace(&escaped, "[PARAM]");
        }
    }
    sanitized
}

impl Drop for NativeResult {
    fn drop(&mut self) {
        // SAFETY: this result handle is uniquely owned and destroyed exactly once.
        unsafe { (self.api.destroy_result)(self.inner.as_ptr()) };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeQueryOutput {
    pub data: Vec<u8>,
    pub elapsed: Duration,
    pub storage_rows_read: u64,
    pub storage_bytes_read: u64,
}

fn validate_params(params: &[(&str, &str)]) -> Result<()> {
    let mut names = BTreeSet::new();
    for (name, _) in params {
        let mut bytes = name.bytes();
        let first = bytes.next();
        if !matches!(first, Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(NativeChdbError::InvalidParameterName((*name).to_string()));
        }
        if !names.insert(*name) {
            return Err(NativeChdbError::DuplicateParameter((*name).to_string()));
        }
    }
    Ok(())
}

pub fn file_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(NativeChdbError::LibraryRead)?;
    let mut hasher = Sha256::new();
    // Heap, not stack (NAN-2651/NAN-2655): hot-tail cache admission calls
    // this from a nested current-thread runtime on a 2 MiB tokio blocking
    // thread, where a 1 MiB stack array leaves little room for the frames
    // above it; a stack overflow there is a SIGSEGV with no Rust panic.
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(NativeChdbError::LibraryRead)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// The verified library is much larger than a 20 eps query role's memory
/// ceiling. Hashing it with the ordinary page cache can charge the entire
/// artifact to that role before `dlopen` faults the useful code pages. Drop
/// only clean, already-hashed pages; the digest still covers every byte.
fn file_sha256_without_retained_cache(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(NativeChdbError::LibraryRead)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    #[cfg(target_os = "linux")]
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
    #[cfg(target_os = "linux")]
    let mut evicted = 0_u64;
    #[cfg(target_os = "linux")]
    let mut read_bytes = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(NativeChdbError::LibraryRead)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
        #[cfg(target_os = "linux")]
        {
            read_bytes += count as u64;
            let completed_pages = read_bytes / page_size * page_size;
            if completed_pages > evicted {
                // SAFETY: `file` stays open and the range covers only bytes
                // already included in the hash. `posix_fadvise` returns the
                // error number directly instead of setting errno.
                let status = unsafe { libc::posix_fadvise(file.as_raw_fd(), evicted as i64,
                    (completed_pages - evicted) as i64, libc::POSIX_FADV_DONTNEED) };
                if status != 0 {
                    return Err(NativeChdbError::LibraryRead(std::io::Error::from_raw_os_error(status)));
                }
                evicted = completed_pages;
            }
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

/// File identity a verified digest is bound to: device, inode, size, and
/// modification and status-change times in nanoseconds. Replacing or
/// rewriting the file changes the inode or ctime (which user space cannot
/// set), so a memoized digest never outlives the bytes it was taken over.
#[cfg(unix)]
fn file_identity(path: &Path) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).map_err(NativeChdbError::LibraryRead)?;
    Ok(format!("{}:{}:{}:{}.{}:{}.{}", m.dev(), m.ino(), m.size(), m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()))
}

/// SHA-256 of a large, read-only artifact (libchdb ~550 MB, the query
/// compiler), memoized in `memo_dir` by [`file_identity`] (NAN-3008). A
/// query[T] cold start hashed both on every spawn, with libchdb read past
/// the page cache: under a CPU-throttled tenant that alone took seconds.
/// `memo_dir` is the process's own private state dir; a stale or foreign
/// entry is simply recomputed. `retain_cache = false` hashes without keeping
/// the file's pages cached (the libchdb path).
pub fn artifact_sha256_memoized(path: &Path, memo_dir: Option<&Path>, retain_cache: bool) -> Result<String> {
    let hash = || if retain_cache { file_sha256(path) } else { file_sha256_without_retained_cache(path) };
    #[cfg(unix)]
    if let Some(dir) = memo_dir {
        let identity = file_identity(path)?;
        let memo = dir.join(format!("artifact-sha256-{}.memo", hex::encode(Sha256::digest(path.as_os_str().as_encoded_bytes()))));
        if let Ok(text) = std::fs::read_to_string(&memo) {
            if let Some((seen, digest)) = text.trim().rsplit_once(' ') {
                if seen == identity && digest.len() == SHA256_HEX_LENGTH && digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Ok(digest.to_owned());
                }
            }
        }
        let digest = hash()?;
        // Only if the file did not change while it was hashed.
        if file_identity(path)? == identity {
            let tmp = memo.with_extension("tmp");
            if std::fs::write(&tmp, format!("{identity} {digest}\n")).is_ok() {
                let _ = std::fs::rename(&tmp, &memo);
            }
        }
        return Ok(digest);
    }
    hash()
}

impl NativeChdb {
    /// [`Self::load_verified`] with the digest memoized in `memo_dir`
    /// ([`artifact_sha256_memoized`]); the expected digest is still checked
    /// on every load.
    pub fn load_verified_memoized(path: impl AsRef<Path>, expected_sha256: &str, memo_dir: Option<&Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(runtime) = cell_runtime(path, expected_sha256)? {
            return Ok(runtime);
        }
        if !path.is_file() {
            return Err(NativeChdbError::MissingLibrary(path.to_path_buf()));
        }
        if expected_sha256.len() != SHA256_HEX_LENGTH
            || !expected_sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(NativeChdbError::InvalidExpectedDigest);
        }
        let actual = artifact_sha256_memoized(path, memo_dir, false)?;
        if actual != expected_sha256 {
            return Err(NativeChdbError::DigestMismatch);
        }
        // SAFETY: as in `load_verified`: the artifact's digest was verified.
        let api = unsafe { Api::load(path)? };
        Ok(Self { api: Arc::new(api), artifact_path: path.to_path_buf(), artifact_sha256: actual })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-3141 child fixture (no-op unless spawned by the tests below).
    #[test]
    fn nan3141_fatal_match_ignores_echoed_query_text() {
        assert!(is_fatal_engine_error(
            "Code: 236. DB::Exception: The server is shutting down due to a fatal error. (ABORTED)"));
        assert!(is_fatal_engine_error(
            "chDB query failed: Code: 236. DB::Exception: The server is shutting down due to a fatal error. (ABORTED)"));
        // A user string literal echoed inside an unrelated error never matches.
        assert!(!is_fatal_engine_error(
            "Code: 62. DB::Exception: Syntax error: failed at position 8 ('Code: 236. DB::Exception: The server is shutting down due to a fatal error'). (SYNTAX_ERROR)"));
        assert!(!is_fatal_engine_error(
            "Code: 236. DB::Exception: Query was cancelled. (ABORTED)"));
    }

    #[test]
    fn nan3141_child_fixture() {
        let Ok(mode) = std::env::var("NAN3141_CHILD") else { return };
        // SAFETY: never dump core from a test child.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &libc::rlimit { rlim_cur: 0, rlim_max: 0 }) };
        match mode.as_str() {
            "fatal-error" => {
                let _ = query_error("Code: 236. DB::Exception: The server is shutting down due to a fatal error. (ABORTED)", &[]);
                panic!("a crashed engine must exit the process");
            }
            fault => {
                let runtime = NativeChdb::load_verified(
                    std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
                    &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
                ).unwrap();
                let connection = runtime.connect(&crate::executor::executor_connection_args(Some(1 << 30))
                    .iter().map(String::as_str).collect::<Vec<_>>()).unwrap();
                connection.query_with_params("SELECT 1", "JSONEachRow", &[]).unwrap();
                let signal = if fault == "abort" { libc::SIGABRT } else { libc::SIGSEGV };
                std::thread::spawn(move || {
                    nanosiem_lake_cell::crash_capture::register_thread().unwrap();
                    if signal == libc::SIGSEGV {
                        // SAFETY: a real synchronous fault on a PROT_NONE page.
                        unsafe {
                            let page = libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_NONE,
                                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
                            std::ptr::write_volatile(page.cast::<u8>(), 1);
                        }
                    } else {
                        // SAFETY: raising a signal on this thread.
                        unsafe { libc::raise(signal) };
                    }
                }).join().ok();
                std::thread::sleep(Duration::from_secs(30));
                panic!("the fault left the process alive (engine handler parked the thread)");
            }
        }
    }

    fn nan3141_child(mode: &str) -> (std::process::ExitStatus, String, Duration) {
        let started = Instant::now();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native::tests::nan3141_child_fixture", "--nocapture", "--include-ignored"])
            .env("NAN3141_CHILD", mode)
            .output()
            .unwrap();
        (output.status, String::from_utf8_lossy(&output.stderr).into_owned(), started.elapsed())
    }

    /// NAN-3141: a chDB error saying the engine is crashed exits the process
    /// (the supervisor restarts it) instead of failing every query forever.
    #[test]
    fn nan3141_a_crashed_engine_error_exits_the_process() {
        assert!(is_fatal_engine_error("chDB query failed: Code: 236. DB::Exception: The server is shutting down due to a fatal error. (ABORTED)"));
        assert!(!is_fatal_engine_error("Code: 236. DB::Exception: Mutation was aborted. (ABORTED)"));
        assert!(!is_fatal_engine_error("Code: 241. DB::Exception: Memory limit (total) exceeded"));
        let (status, stderr, _) = nan3141_child("fatal-error");
        assert_eq!(status.code(), Some(FATAL_ENGINE_EXIT_CODE), "{stderr}");
        assert!(stderr.contains("lake_native_fatal exit_code=70"), "{stderr}");
    }

    /// NAN-3141: with chDB loaded and connected, a fault on any thread is
    /// recorded by crash_capture and kills the process at once (no 303 s
    /// window of Code 236 answers).
    #[test]
    #[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
    fn nan3141_a_fault_after_connect_is_recorded_and_kills_the_process() {
        use std::os::unix::process::ExitStatusExt;
        for (mode, signal) in [("segv", libc::SIGSEGV), ("abort", libc::SIGABRT)] {
            let (status, stderr, elapsed) = nan3141_child(mode);
            assert_eq!(status.signal(), Some(signal), "{mode}: {status:?} {stderr}");
            assert!(stderr.contains("lake_native_crash signal=") && stderr.contains(" pc=0x"), "{mode}: {stderr}");
            assert!(stderr.contains("lake_native_crash maps_end"), "{mode}: {stderr}");
            assert!(elapsed < Duration::from_secs(20), "{mode}: took {elapsed:?}");
            println!("NAN3141 {mode}: {status:?} in {elapsed:?}");
        }
    }

    #[test]
    #[ignore = "requires digest-verified native library"]
    fn failed_stream_is_terminal_but_still_requires_cancellation() {
        let runtime = NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        std::mem::forget(runtime.clone());
        let connection = runtime.connect(&crate::executor::executor_connection_args(Some(3 << 30))
            .iter().map(String::as_str).collect::<Vec<_>>()).unwrap();
        let mut stream = connection.stream_query_with_params(
            "SELECT count() FROM (SELECT repeat(toString(cityHash64(number)), 16) AS k FROM numbers(1500000) GROUP BY k) SETTINGS max_memory_usage=268435456, max_threads=2, max_bytes_before_external_group_by=0",
            "JSONEachRow", &[],
        ).unwrap();
        let error = loop {
            match stream.fetch() {
                Err(error) => break error,
                Ok(Some(_)) => {},
                Ok(None) => panic!("statement must fail at the small-lane memory cap"),
            }
        };
        assert!(error.to_string().contains("MEMORY_LIMIT_EXCEEDED"));
        assert!(!stream.is_finished(), "only natural EOF may skip cancellation");
        assert!(stream.fetch().unwrap().is_none(), "failure is terminal for the reader");
        drop(stream);
        drop(connection);
        let connection = runtime.connect(&[]).unwrap();
        let output = connection.query_with_params("SELECT 42 AS n", "JSONEachRow", &[]).unwrap();
        assert_eq!(output.data, b"{\"n\":42}\n");
    }

    /// Runs in fresh processes because dumpability and the native cache are
    /// process-wide. No other test may inherit a relaxed or restricted jail.
    #[test]
    #[ignore = "requires NANO_CHDB_LIBRARY_PATH and NANO_CHDB_LIBRARY_SHA256"]
    fn non_dumpable_native_initialization() {
        const CHILD: &str = "NAN3100_NATIVE_CHILD";
        if let Ok(mode) = std::env::var(CHILD) {
            let path = std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap();
            let digest = std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap();
            if mode == "preload" {
                let threads = nanosiem_lake_cell::jail::thread_count();
                let runtime = NativeChdb::load_verified(&path, &digest).unwrap();
                assert_eq!(nanosiem_lake_cell::jail::thread_count(), threads, "dlopen must not start threads before jail");
                assert!(CELL_RUNTIME.set(runtime).is_ok());
            }
            // Bootstrap sets HOME/TMPDIR after confinement. This must
            // never cause native initialization to walk beyond heap environ.
            std::env::set_var("NAN3100_ENV_MOVED", "1");
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
            assert!(File::open("/proc/self/auxv").is_err());
            let loaded = NativeChdb::load_verified(&path, &digest);
            if mode == "refuse" {
                assert!(matches!(loaded, Err(NativeChdbError::LibraryRead(_))));
                return;
            }
            let loaded = loaded.unwrap();
            assert!(matches!(NativeChdb::load_verified(&path, &"0".repeat(64)), Err(NativeChdbError::DigestMismatch)));
            let again = NativeChdb::load_verified_memoized(&path, &digest, None).unwrap();
            assert!(Arc::ptr_eq(&loaded.api, &again.api));
            let connection = loaded.connect(&["--path=:memory:"]).unwrap();
            let result = connection.query_with_params("SELECT 1 AS alive", "JSONEachRow", &[]).unwrap();
            assert_eq!(result.data, b"{\"alive\":1}\n");
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
            return;
        }
        for mode in ["refuse", "preload"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "native::tests::non_dumpable_native_initialization", "--ignored", "--test-threads=1"])
                .env(CHILD, mode).status().unwrap();
            assert!(status.success(), "native initialization mode {mode}: {status}");
        }
    }

    /// NAN-3008: a memoized artifact digest is reused only for the same file
    /// identity; rewriting the file (new ctime/size) recomputes it.
    #[test]
    fn artifact_digest_memo_is_bound_to_file_identity() {
        let dir = tempfile::tempdir().unwrap();
        let memo = dir.path().join("memo");
        std::fs::create_dir_all(&memo).unwrap();
        let path = dir.path().join("libchdb.so");
        std::fs::write(&path, b"first bytes").unwrap();
        let first = artifact_sha256_memoized(&path, Some(&memo), false).unwrap();
        assert_eq!(first, file_sha256(&path).unwrap());
        assert_eq!(std::fs::read_dir(&memo).unwrap().count(), 1, "memo written");
        // The threat the memo must not hide: the file changes.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&path, b"other bytes, longer").unwrap();
        let second = artifact_sha256_memoized(&path, Some(&memo), false).unwrap();
        assert_eq!(second, file_sha256(&path).unwrap());
        assert_ne!(first, second, "a changed file is re-hashed, never served from the memo");
        // Same identity: served from the memo (a planted digest proves it).
        let entry = std::fs::read_dir(&memo).unwrap().next().unwrap().unwrap().path();
        let text = std::fs::read_to_string(&entry).unwrap();
        let (identity, _) = text.trim().rsplit_once(' ').unwrap();
        std::fs::write(&entry, format!("{identity} {}\n", "a".repeat(64))).unwrap();
        assert_eq!(artifact_sha256_memoized(&path, Some(&memo), false).unwrap(), "a".repeat(64));
        // No memo dir: always hashed.
        assert_eq!(artifact_sha256_memoized(&path, None, true).unwrap(), second);
    }

    /// NAN-2655: hashing must not need a 1 MiB stack frame. Hot-tail cache
    /// admission hashes on tokio blocking threads (2 MiB) under nested
    /// runtime/future frames; a stack array made that a SIGSEGV hazard.
    /// Before the heap buffer this thread overflowed its 512 KiB stack.
    #[test]
    fn file_sha256_runs_on_a_small_stack() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("object.parquet");
        std::fs::write(&path, vec![7_u8; 3 * 1024 * 1024 + 5]).unwrap();
        let digest = std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || file_sha256(&path).unwrap())
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(
            digest,
            hex::encode(Sha256::digest(vec![7_u8; 3 * 1024 * 1024 + 5]))
        );
    }

    #[test]
    fn parameter_names_are_bounded_identifiers_without_duplicates() {
        assert!(validate_params(&[("source", "one"), ("candidate_2", "two")]).is_ok());
        assert!(matches!(
            validate_params(&[("source-name", "one")]),
            Err(NativeChdbError::InvalidParameterName(_))
        ));
        assert!(matches!(
            validate_params(&[("source", "one"), ("source", "two")]),
            Err(NativeChdbError::DuplicateParameter(_))
        ));
    }

    #[test]
    fn malformed_digest_is_rejected_before_loading() {
        let executable = std::env::current_exe().expect("test executable path");
        assert!(matches!(
            NativeChdb::load_verified(executable, "ABC"),
            Err(NativeChdbError::InvalidExpectedDigest)
        ));
    }

    #[test]
    fn query_error_diagnostics_redact_all_bound_values() {
        let error = "Unknown name in scope SELECT * FROM icebergS3('https://store/table', 'access-id', 'secret-value') WHERE uid = 'event-123'";
        let sanitized = sanitize_query_error(
            error,
            &[
                ("source", "https://store/table"),
                ("access", "access-id"),
                ("secret", "secret-value"),
                ("event_id", "event-123"),
            ],
        );
        for value in [
            "https://store/table",
            "access-id",
            "secret-value",
            "event-123",
        ] {
            assert!(!sanitized.contains(value));
        }
        assert!(sanitized.contains("[PARAM]"));
    }

    #[test]
    #[ignore = "requires NANO_CHDB_LIBRARY_PATH and NANO_CHDB_LIBRARY_SHA256"]
    fn pinned_native_library_binds_query_parameters() {
        let path = std::env::var("NANO_CHDB_LIBRARY_PATH").expect("library path");
        let digest = std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("library digest");
        let runtime = NativeChdb::load_verified(path, &digest).expect("load chDB");
        let connection = runtime.connect(&[]).expect("connect");
        let output = connection
            .query_with_params(
                "SELECT {probe:String} AS value",
                "JSONEachRow",
                &[("probe", "nano")],
            )
            .expect("parameterized query");
        let row: serde_json::Value =
            serde_json::from_slice(&output.data).expect("JSONEachRow result");
        assert_eq!(row["value"], "nano");
        assert!(!runtime.version().expect("version").is_empty());
    }

    #[test]
    #[ignore = "requires the pinned native artifact and a test Iceberg snapshot"]
    fn pinned_native_library_reads_guarded_iceberg_snapshot() {
        let path = std::env::var("NANO_CHDB_LIBRARY_PATH").expect("library path");
        let digest = std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("library digest");
        let source = std::env::var("NANO_CHDB_TEST_SOURCE").expect("Iceberg source");
        let access = std::env::var("NANO_CHDB_TEST_ACCESS_KEY").expect("access key");
        let secret = std::env::var("NANO_CHDB_TEST_SECRET_KEY").expect("secret key");
        let metadata = std::env::var("NANO_CHDB_TEST_METADATA").expect("metadata path");
        assert!(
            !metadata.is_empty()
                && metadata
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte)),
            "trusted metadata path is outside the supported character set"
        );
        let sql = format!(
            "SELECT count() AS matches FROM (SELECT * FROM icebergS3(\
             {{source:String}}, {{access:String}}, {{secret:String}}, SETTINGS \
             iceberg_metadata_file_path='{metadata}') WHERE _path != '') \
             ARRAY JOIN resources.hostname AS hostname WHERE hostname != ''"
        );
        let runtime = NativeChdb::load_verified(path, &digest).expect("load chDB");
        let connection = runtime.connect(&[]).expect("connect");
        let output = connection
            .query_with_params(
                &sql,
                "JSONEachRow",
                &[
                    ("source", source.as_str()),
                    ("access", access.as_str()),
                    ("secret", secret.as_str()),
                ],
            )
            .expect("Iceberg query");
        let row: serde_json::Value =
            serde_json::from_slice(&output.data).expect("JSONEachRow result");
        let matches = row["matches"].as_u64().unwrap_or_default();
        assert!(matches > 0);
        eprintln!(
            "chdb_version={} matches={} engine_ms={:.3} storage_rows={} storage_bytes={}",
            runtime.version().expect("version"),
            matches,
            output.elapsed.as_secs_f64() * 1_000.0,
            output.storage_rows_read,
            output.storage_bytes_read
        );
    }
}
