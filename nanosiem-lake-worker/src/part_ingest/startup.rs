// SPDX-License-Identifier: AGPL-3.0-or-later

//! Startup progress is separate from the service loop and never counts timer ticks.
use nanosiem_lake_cell::{child::ControlChannel, contract::Heartbeat};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct StartupProgress(Arc<Mutex<Heartbeat>>);

tokio::task_local! { pub static PROGRESS: StartupProgress; }

impl Default for StartupProgress {
    fn default() -> Self { Self::new() }
}

impl StartupProgress {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Heartbeat {
            busy: true,
            detail: Some("starting: credentials".into()),
            startup_progress: Some(1),
            ..Heartbeat::default()
        })))
    }

    pub fn advance(&self, phase: &str) {
        let mut hb = self.0.lock().unwrap();
        // A monotonic startup revision, not elapsed time. The supervisor
        // measures the time between revisions with its own Instant.
        hb.startup_progress = hb.startup_progress.map(|revision| revision + 1);
        hb.detail = Some(format!("starting: {phase}"));
    }

    pub fn snapshot(&self) -> Heartbeat {
        self.0.lock().unwrap().clone()
    }

    pub async fn send(&self, control: ControlChannel) -> std::io::Result<()> {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let hb = self.snapshot();
            control.heartbeat(&hb).await?;
        }
    }
}

pub fn advance(phase: &str) {
    let _ = PROGRESS.try_with(|progress| progress.advance(phase));
}

/// Stop the independent heartbeat when startup completes or fails.
pub struct StartupHeartbeat(tokio::task::JoinHandle<std::io::Result<()>>);
impl StartupHeartbeat {
    pub async fn wait(&mut self) -> anyhow::Result<()> {
        (&mut self.0).await??;
        anyhow::bail!("startup heartbeat stopped")
    }

    pub async fn stop(&mut self) {
        self.0.abort();
        let _ = (&mut self.0).await;
    }

    pub fn start(progress: StartupProgress, control: ControlChannel) -> Self {
        Self(tokio::spawn(async move { progress.send(control).await }))
    }
}
impl Drop for StartupHeartbeat {
    fn drop(&mut self) {
        self.0.abort();
    }
}
