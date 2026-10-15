// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal native crash record for jailed cell children (NAN-3098).
//!
//! Capture the faulting native frame and load addresses without unwinding,
//! allocating, taking Rust/loader locks, or reading credential-bearing memory.
//! A corrupted stack/allocator can make even a prewarmed `backtrace()` deadlock.
//! PC plus `/proc/self/maps` permits offline symbolization against the exact
//! image. This is not a full backtrace or core dump. Alternate stacks are
//! thread-local: register Rust runtime/native lane threads explicitly; foreign
//! library-created threads still get the handler on their ordinary stack.

use std::cell::RefCell;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

const STACK_BYTES: usize = 64 * 1024;
static CAPTURING: AtomicBool = AtomicBool::new(false);

struct SignalStack(Box<[u8]>);
impl Drop for SignalStack {
    fn drop(&mut self) {
        // SAFETY: TLS destruction runs on the ordinary thread stack. Disable
        // only our own descriptor before freeing it. Do not restore the old
        // stack: Rust's thread cleanup may already have freed its allocation.
        unsafe {
            let mut current: libc::stack_t = std::mem::zeroed();
            if libc::sigaltstack(std::ptr::null(), &mut current) != 0 {
                std::mem::forget(std::mem::replace(&mut self.0, Box::new([])));
                return;
            }
            if current.ss_sp == self.0.as_mut_ptr().cast() {
                let disabled = libc::stack_t {
                    ss_sp: std::ptr::null_mut(),
                    ss_flags: libc::SS_DISABLE,
                    ss_size: 0,
                };
                if libc::sigaltstack(&disabled, std::ptr::null_mut()) != 0 {
                    std::mem::forget(std::mem::replace(&mut self.0, Box::new([])));
                }
            }
        }
    }
}
thread_local! {
    static STACK: RefCell<Option<SignalStack>> = const { RefCell::new(None) };
}

/// Register an alternate signal stack on the calling thread, once.
pub fn register_thread() -> io::Result<()> {
    STACK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Ok(());
        }
        let mut memory = vec![0u8; STACK_BYTES].into_boxed_slice();
        let descriptor = libc::stack_t {
            ss_sp: memory.as_mut_ptr().cast(),
            ss_flags: 0,
            ss_size: memory.len(),
        };
        // SAFETY: the thread-local allocation remains stable until thread exit.
        if unsafe { libc::sigaltstack(&descriptor, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        *slot = Some(SignalStack(memory));
        Ok(())
    })
}

/// Install before the jail, runtime, native library, and credential exchange.
/// Called once by the single-threaded cell bootstrap.
pub fn install() -> io::Result<()> {
    register_thread()?;
    // SAFETY: fully initialized sigaction; the kernel supplies siginfo/ucontext.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = capture as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_RESETHAND;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [
            libc::SIGSEGV,
            libc::SIGBUS,
            libc::SIGILL,
            libc::SIGABRT,
            libc::SIGFPE,
        ] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn write_stderr(mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: bytes is a valid slice; write is async-signal-safe.
        let written =
            unsafe { libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len()) };
        if written <= 0 {
            break;
        }
        bytes = &bytes[written as usize..];
    }
}

fn hex(value: usize) {
    let mut bytes = [b'0'; 2 + 2 * std::mem::size_of::<usize>()];
    bytes[1] = b'x';
    for i in 0..2 * std::mem::size_of::<usize>() {
        bytes[bytes.len() - 1 - i] = b"0123456789abcdef"[(value >> (4 * i)) & 15];
    }
    write_stderr(&bytes);
}

extern "C" fn capture(signal: libc::c_int, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    // This atomic is lock-free on the supported Linux architectures. A second
    // simultaneous fault must not recurse or interleave unbounded diagnostics.
    if CAPTURING.swap(true, Ordering::Relaxed) {
        unsafe { libc::_exit(128 + signal) };
    }
    write_stderr(b"lake_native_crash signal=");
    hex(signal as usize);
    write_stderr(b" fault_address=");
    // SAFETY: SA_SIGINFO gives valid pointers for the duration of the handler.
    unsafe {
        hex(if (*info).si_code > 0 {
            (*info).si_addr() as usize
        } else {
            0
        });
        write_stderr(b" pc=");
        #[cfg(target_arch = "x86_64")]
        hex(
            (*(context.cast::<libc::ucontext_t>())).uc_mcontext.gregs[libc::REG_RIP as usize]
                as usize,
        );
        #[cfg(target_arch = "aarch64")]
        hex((*(context.cast::<libc::ucontext_t>())).uc_mcontext.pc as usize);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = context;
            hex(0);
        }
        let mut stack: libc::stack_t = std::mem::zeroed();
        libc::sigaltstack(std::ptr::null(), &mut stack);
        write_stderr(b" alt_stack_flags=");
        hex(stack.ss_flags as usize);
    }
    write_stderr(b"\nlake_native_crash maps_begin\n");
    // Only mappings, never stack/heap contents or environment. The jail allows
    // the child's own proc directory. Bound work even if procfs is unavailable.
    unsafe {
        let fd = libc::open(
            c"/proc/self/maps".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        );
        if fd >= 0 {
            let mut buffer = [0u8; 4096];
            for _ in 0..64 {
                let count = libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len());
                if count <= 0 {
                    break;
                }
                write_stderr(&buffer[..count as usize]);
            }
            libc::close(fd);
        }
    }
    write_stderr(b"lake_native_crash maps_end\n");
    // SA_RESETHAND already restored default disposition. Queue on this exact
    // thread; delivery occurs as we return/unblock the signal. Preserve signal
    // exit status for the supervisor, including on a raise()-generated crash.
    unsafe {
        if libc::raise(signal) != 0 {
            libc::_exit(128 + signal);
        }
    }
}
