//! Optional bounded idle backoff. Never gates writes, heartbeats or explicit refreshes.
use std::time::Duration;
use tokio::time::Instant;

#[derive(Default)]
pub(crate) struct IdlePoll {
    next: Option<Instant>,
    delay: Duration,
}
impl IdlePoll {
    pub(crate) fn due(&self, active: bool) -> bool {
        active || self.next.is_none_or(|next| Instant::now() >= next)
    }
    pub(crate) fn finish(&mut self, idle: bool, base: Duration, ceiling: Option<Duration>) {
        self.delay = if idle {
            self.delay
                .max(base)
                .saturating_mul(2)
                .min(ceiling.unwrap_or(base).max(base))
        } else {
            base
        };
        self.next = Some(Instant::now() + self.delay);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn idle_backoff_is_bounded_and_activity_bypasses_wait() {
        let mut poll = IdlePoll::default();
        assert!(poll.due(false));
        for seconds in [10, 20, 40, 60, 60] {
            poll.finish(true, Duration::from_secs(5), Some(Duration::from_secs(60)));
            assert_eq!(poll.delay.as_secs(), seconds);
            assert!(!poll.due(false));
            assert!(poll.due(true));
            tokio::time::advance(Duration::from_secs(seconds)).await;
            assert!(poll.due(false));
        }
        poll.finish(false, Duration::from_secs(5), Some(Duration::from_secs(60)));
        assert_eq!(poll.delay.as_secs(), 5);
    }
}
