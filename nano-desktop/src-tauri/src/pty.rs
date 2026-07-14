//! The embedded terminal: a real PTY running the user's login shell.
//!
//! Not a command runner. `claude`, `codex`, `vim` and `less` all need a terminal
//! that reports a size, forwards signals, and speaks in escape sequences — so we
//! allocate an actual pty and let xterm.js render its bytes.

use std::io::{Read, Write};
use std::sync::Mutex;

use base64::Engine;
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use tauri::ipc::Channel;

use crate::error::{Error, Result};

/// The shell's raw output, base64-encoded. xterm decodes UTF-8 itself, and
/// encoding sidesteps the fact that a read can split a multi-byte character —
/// or emit bytes that aren't valid UTF-8 at all.
type Output = Channel<String>;

struct Session {
    writer: Box<dyn Write + Send>,
    master: Box<dyn portable_pty::MasterPty + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

#[derive(Default)]
pub struct Terminal {
    session: Mutex<Option<Session>>,
}

fn login_shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_string())
}

/// Where the shell starts, and how the agent CLIs find nano.
pub struct AgentEnv {
    /// Holds `.mcp.json`, which Claude Code reads from the working directory.
    pub workspace: std::path::PathBuf,
    /// Codex layers config from here, leaving the user's ~/.codex untouched.
    pub codex_home: std::path::PathBuf,
}

impl Terminal {
    /// Spawn the shell. Re-opening replaces any existing session — the drawer
    /// only ever shows one terminal.
    pub fn open(&self, rows: u16, cols: u16, agent: Option<AgentEnv>, on_output: Output) -> Result<()> {
        self.close()?;

        let pty = NativePtySystem::default()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| Error::Internal(format!("open pty: {e}")))?;

        // `-l` so the user's real environment (PATH, nvm, asdf…) is loaded —
        // without it, `claude` and `codex` frequently aren't on PATH.
        let mut command = CommandBuilder::new(login_shell());
        command.arg("-l");
        // Tells the shell and anything it launches what the terminal can do.
        command.env("TERM", "xterm-256color");

        match agent {
            // Start in the agent workspace so `claude` picks up its
            // project-scoped .mcp.json, and point Codex at our config instead
            // of the user's.
            Some(env) => {
                command.cwd(&env.workspace);
                command.env("CODEX_HOME", &env.codex_home);
            }
            None => {
                if let Some(home) = dirs_home() {
                    command.cwd(home);
                }
            }
        }

        let child = pty
            .slave
            .spawn_command(command)
            .map_err(|e| Error::Internal(format!("spawn shell: {e}")))?;

        let writer = pty
            .master
            .take_writer()
            .map_err(|e| Error::Internal(format!("pty writer: {e}")))?;
        let mut reader = pty
            .master
            .try_clone_reader()
            .map_err(|e| Error::Internal(format!("pty reader: {e}")))?;

        // The read is blocking, so it gets its own thread; it ends when the
        // shell exits and the pty closes.
        std::thread::spawn(move || {
            let mut buffer = [0u8; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        let encoded =
                            base64::engine::general_purpose::STANDARD.encode(&buffer[..n]);
                        if on_output.send(encoded).is_err() {
                            break; // webview went away
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        *self.locked()? = Some(Session {
            writer,
            master: pty.master,
            child,
        });
        Ok(())
    }

    pub fn write(&self, data: &str) -> Result<()> {
        let mut guard = self.locked()?;
        let session = guard.as_mut().ok_or(Error::Internal("no terminal".into()))?;
        session
            .writer
            .write_all(data.as_bytes())
            .map_err(|e| Error::Internal(format!("pty write: {e}")))?;
        session
            .writer
            .flush()
            .map_err(|e| Error::Internal(format!("pty flush: {e}")))
    }

    /// Without this the shell keeps its original size and every full-screen
    /// program (vim, less, claude's TUI) wraps at the wrong column.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        let guard = self.locked()?;
        let Some(session) = guard.as_ref() else {
            return Ok(());
        };
        session
            .master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| Error::Internal(format!("pty resize: {e}")))
    }

    /// Kill the shell. Called when the drawer closes and on app exit — a pty
    /// whose master is dropped without this can leave the child running.
    pub fn close(&self) -> Result<()> {
        if let Some(mut session) = self.locked()?.take() {
            let _ = session.child.kill();
            let _ = session.child.wait();
        }
        Ok(())
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Option<Session>>> {
        self.session
            .lock()
            .map_err(|_| Error::Internal("terminal lock poisoned".into()))
    }
}

fn dirs_home() -> Option<String> {
    std::env::var("HOME").ok()
}
