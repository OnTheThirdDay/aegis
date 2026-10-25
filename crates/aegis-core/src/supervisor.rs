//! Supervision helpers (B-002): bounded exponential backoff with jitter and
//! a circuit breaker so a rapidly failing component cannot restart
//! infinitely fast.

use rand::Rng;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Backoff {
            base,
            max,
            attempt: 0,
        }
    }

    /// Next delay: `min(max, base * 2^attempt)` with ±25% jitter.
    pub fn next_delay(&mut self) -> Duration {
        let exp = self.base.saturating_mul(1u32 << self.attempt.min(16));
        let capped = exp.min(self.max);
        self.attempt = self.attempt.saturating_add(1);
        let ms = capped.as_millis() as u64;
        let jitter = ms / 4;
        let jittered = if jitter == 0 {
            ms
        } else {
            ms - jitter + rand::thread_rng().gen_range(0..=jitter * 2)
        };
        Duration::from_millis(jittered.min(self.max.as_millis() as u64 + jitter))
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn attempts(&self) -> u32 {
        self.attempt
    }
}

/// Opens after `threshold` failures within `window`; stays open for
/// `cooldown`, then allows a single trial.
#[derive(Debug)]
pub struct CircuitBreaker {
    threshold: u32,
    window: Duration,
    cooldown: Duration,
    failures: Vec<Instant>,
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, window: Duration, cooldown: Duration) -> Self {
        CircuitBreaker {
            threshold: threshold.max(1),
            window,
            cooldown,
            failures: Vec::new(),
            open_until: None,
        }
    }

    pub fn allow(&mut self) -> bool {
        match self.open_until {
            Some(t) if Instant::now() < t => false,
            Some(_) => {
                self.open_until = None;
                self.failures.clear();
                true
            }
            None => true,
        }
    }

    pub fn record_failure(&mut self) {
        let now = Instant::now();
        self.failures
            .retain(|t| now.duration_since(*t) < self.window);
        self.failures.push(now);
        if self.failures.len() as u32 >= self.threshold {
            self.open_until = Some(now + self.cooldown);
        }
    }

    pub fn record_success(&mut self) {
        self.failures.clear();
    }

    pub fn is_open(&self) -> bool {
        self.open_until.is_some_and(|t| Instant::now() < t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_u04_backoff_is_bounded() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(5));
        let mut last = Duration::ZERO;
        for _ in 0..40 {
            last = b.next_delay();
            assert!(last <= Duration::from_millis(6250));
        }
        assert!(last >= Duration::from_millis(3750), "reaches the ceiling");
        b.reset();
        assert!(b.next_delay() <= Duration::from_millis(125));
    }

    #[test]
    fn tc_u04_circuit_breaker_opens_and_recovers() {
        let mut c = CircuitBreaker::new(3, Duration::from_secs(10), Duration::from_millis(50));
        assert!(c.allow());
        for _ in 0..3 {
            c.record_failure();
        }
        assert!(c.is_open());
        assert!(!c.allow());
        std::thread::sleep(Duration::from_millis(60));
        assert!(c.allow(), "half-open trial after cooldown");
    }
}
