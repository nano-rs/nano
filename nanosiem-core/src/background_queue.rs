// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded, nonblocking dispatch for routine telemetry (never authority writes).
use std::future::Future;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct BackgroundQueue<T> { sender: mpsc::Sender<T> }
impl<T: Send + 'static> BackgroundQueue<T> {
    pub fn spawn<F, Fut>(capacity: usize, mut flush: F) -> Self
    where F: FnMut(Vec<T>) -> Fut + Send + 'static, Fut: Future<Output = ()> + Send {
        let (sender, mut receiver) = mpsc::channel(capacity);
        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(64);
            while receiver.recv_many(&mut batch, 64).await != 0 {
                flush(std::mem::take(&mut batch)).await;
            }
        });
        Self { sender }
    }
    /// Returns ownership for diagnostic logging when full/closed. Never waits
    /// for database I/O or allocates an overflow task.
    pub fn try_send(&self, event: T) -> Result<(), T> {
        self.sender.try_send(event).map_err(|error| error.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn full_channel_does_not_wait_for_flusher() {
        let (sender, _receiver) = mpsc::channel(1);
        let queue = BackgroundQueue { sender };
        assert!(queue.try_send(1).is_ok());
        assert_eq!(queue.try_send(2), Err(2));
    }
    #[tokio::test]
    async fn flusher_drains_accepted_events_on_close() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let queue = BackgroundQueue::spawn(4, move |batch| {
            let sender = sender.clone();
            async move { for value in batch { sender.send(value).unwrap(); } }
        });
        for value in 0..4 { queue.try_send(value).unwrap(); }
        drop(queue);
        for value in 0..4 {
            assert_eq!(tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv()).await.unwrap(), Some(value));
        }
        assert_eq!(receiver.recv().await, None);
    }
}
