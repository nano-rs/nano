// SPDX-License-Identifier: AGPL-3.0-or-later
//! H02 CP27 LAB-ONLY native protocol child (`sandbox-integration` only).
//!
//! It takes the REAL native bootstrap (advertise LandingBytesV1, validate the
//! reduced assignment, apply the native jail, accept NativeRun) and then
//! serves one fixed command byte per routed stream so a lab operator can
//! observe the actual kernel confinement. It is not the LandingBytesV1 leaf,
//! converts nothing and is never packaged.
//!   'e' echo the rest of the stream back
//!   'n' report socket(AF_INET, SOCK_DGRAM) errno as 4 LE bytes (0 = opened)
//!   'x' the same through the x32 syscall number (NAN-4545)
//!   'r' behave hostile: send a raw RefreshSecrets frame on the control fd
use nanosiem_lake_cell::child::{self, NativeEvent, ServiceBoot};
use nanosiem_lake_cell::contract::{NativeChildService, CONTROL_FD};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn inet_errno() -> i32 {
    // SAFETY: plain socket(2); a returned fd is closed immediately.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd >= 0 {
        // SAFETY: fd was just returned by socket(2).
        unsafe { libc::close(fd) };
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

fn x32_inet_errno() -> i32 {
    // SAFETY: raw socket(2) through the x32 number; a returned fd is closed.
    let fd = unsafe { libc::syscall(0x4000_0000 | libc::SYS_socket, libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd >= 0 {
        // SAFETY: fd was just returned by socket(2).
        unsafe { libc::close(fd as libc::c_int) };
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

fn hostile_refresh() {
    let frame = br#"{"type":"refresh_secrets"}"#;
    // SAFETY: the supervisor's control seqpacket is the inherited CONTROL_FD.
    unsafe {
        libc::send(
            CONTROL_FD,
            frame.as_ptr().cast(),
            frame.len(),
            libc::MSG_NOSIGNAL,
        )
    };
}

fn main() -> anyhow::Result<()> {
    let ServiceBoot::Native(native) =
        child::bootstrap_with_services(&[NativeChildService::LandingBytesV1])?
    else {
        anyhow::bail!("lab child requires a native assignment");
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let (_assignment, control) = native.into_async()?;
        loop {
            match control.next_event().await? {
                NativeEvent::Rpc { mut stream, .. } => {
                    let mut command = [0u8; 1];
                    stream.read_exact(&mut command).await?;
                    match command[0] {
                        b'e' => {
                            let mut body = Vec::new();
                            stream.read_to_end(&mut body).await?;
                            stream.write_all(&body).await?;
                        }
                        b'n' => stream.write_all(&inet_errno().to_le_bytes()).await?,
                        b'x' => stream.write_all(&x32_inet_errno().to_le_bytes()).await?,
                        b'r' => hostile_refresh(),
                        _ => {}
                    }
                    let _ = stream.shutdown().await;
                }
                NativeEvent::Shutdown { .. } | NativeEvent::Closed => return Ok(()),
            }
        }
    })
}
