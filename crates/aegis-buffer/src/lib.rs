//! Hierarchical byte budgets (02 §7).
//!
//! A [`Budget`] has a hard ceiling and an optional parent. Reserving from a
//! child also reserves from every ancestor, so per-stream, per-session and
//! per-process limits are enforced together. A [`Reservation`] releases its
//! bytes on drop, so a cancelled task can never leak accounted capacity.
//!
//! Budgets are ceilings, not promises: admission must consult the remaining
//! aggregate capacity before granting credit.
#![forbid(unsafe_code)]

use aegis_contracts::observability::PoolClass;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const CLASSES: usize = PoolClass::ALL.len();

#[derive(Debug)]
pub struct Budget {
    limit: u64,
    used: AtomicU64,
    parent: Option<Arc<Budget>>,
    /// Per-class usage, maintained only on the root.
    class_used: [AtomicU64; CLASSES],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetExceeded {
    pub requested: u64,
    pub available: u64,
}

impl fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "budget exceeded: requested {} bytes, {} available",
            self.requested, self.available
        )
    }
}

impl std::error::Error for BudgetExceeded {}

fn class_index(class: PoolClass) -> usize {
    match class {
        PoolClass::Receive => 0,
        PoolClass::Transmit => 1,
        PoolClass::Control => 2,
        PoolClass::Handshake => 3,
        PoolClass::Telemetry => 4,
    }
}

impl Budget {
    pub fn root(limit: u64) -> Arc<Budget> {
        Arc::new(Budget {
            limit,
            used: AtomicU64::new(0),
            parent: None,
            class_used: Default::default(),
        })
    }

    pub fn child(self: &Arc<Self>, limit: u64) -> Arc<Budget> {
        Arc::new(Budget {
            limit,
            used: AtomicU64::new(0),
            parent: Some(Arc::clone(self)),
            class_used: Default::default(),
        })
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }

    /// Remaining capacity considering every ancestor.
    pub fn available(&self) -> u64 {
        let own = self.limit.saturating_sub(self.used());
        match &self.parent {
            Some(p) => own.min(p.available()),
            None => own,
        }
    }

    /// Usage by pool class (root budget only; children report zero).
    pub fn class_used(&self, class: PoolClass) -> u64 {
        self.class_used[class_index(class)].load(Ordering::Acquire)
    }

    fn try_add_local(&self, bytes: u64) -> Result<(), BudgetExceeded> {
        let mut cur = self.used.load(Ordering::Acquire);
        loop {
            let next =
                cur.checked_add(bytes)
                    .filter(|n| *n <= self.limit)
                    .ok_or(BudgetExceeded {
                        requested: bytes,
                        available: self.limit.saturating_sub(cur),
                    })?;
            match self
                .used
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(()),
                Err(actual) => cur = actual,
            }
        }
    }

    fn sub_local(&self, bytes: u64) {
        let prev = self.used.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(prev >= bytes, "budget underflow");
    }

    fn try_add_chain(&self, bytes: u64, class: PoolClass) -> Result<(), BudgetExceeded> {
        self.try_add_local(bytes)?;
        match &self.parent {
            Some(parent) => {
                if let Err(e) = parent.try_add_chain(bytes, class) {
                    self.sub_local(bytes);
                    return Err(e);
                }
            }
            None => {
                self.class_used[class_index(class)].fetch_add(bytes, Ordering::AcqRel);
            }
        }
        Ok(())
    }

    fn sub_chain(&self, bytes: u64, class: PoolClass) {
        self.sub_local(bytes);
        match &self.parent {
            Some(parent) => parent.sub_chain(bytes, class),
            None => {
                self.class_used[class_index(class)].fetch_sub(bytes, Ordering::AcqRel);
            }
        }
    }

    /// Reserve `bytes` from this budget and all ancestors, all-or-nothing.
    pub fn try_reserve(
        self: &Arc<Self>,
        bytes: u64,
        class: PoolClass,
    ) -> Result<Reservation, BudgetExceeded> {
        self.try_add_chain(bytes, class)?;
        Ok(Reservation {
            budget: Arc::clone(self),
            bytes,
            class,
        })
    }

    /// Reserve up to `max` bytes but at least `min`; returns the largest
    /// amount that fits. Used to advertise a smaller window instead of failing.
    pub fn try_reserve_range(
        self: &Arc<Self>,
        min: u64,
        max: u64,
        class: PoolClass,
    ) -> Result<Reservation, BudgetExceeded> {
        let want = max.min(self.available()).max(min);
        match self.try_reserve(want, class) {
            Ok(r) => Ok(r),
            // Lost a race with a concurrent reservation; settle for `min`.
            Err(_) if want > min => self.try_reserve(min, class),
            Err(e) => Err(e),
        }
    }
}

/// Accounted bytes; released exactly once, on drop.
#[derive(Debug)]
pub struct Reservation {
    budget: Arc<Budget>,
    bytes: u64,
    class: PoolClass,
}

impl Reservation {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn class(&self) -> PoolClass {
        self.class
    }

    /// Try to extend this reservation by `extra` bytes.
    pub fn try_grow(&mut self, extra: u64) -> Result<(), BudgetExceeded> {
        self.budget.try_add_chain(extra, self.class)?;
        self.bytes += extra;
        Ok(())
    }

    /// Release part of the reservation early.
    pub fn shrink(&mut self, by: u64) {
        let by = by.min(self.bytes);
        if by > 0 {
            self.budget.sub_chain(by, self.class);
            self.bytes -= by;
        }
    }

    /// Move `bytes` out into a separate reservation (no re-accounting).
    pub fn split_off(&mut self, bytes: u64) -> Option<Reservation> {
        if bytes > self.bytes {
            return None;
        }
        self.bytes -= bytes;
        Some(Reservation {
            budget: Arc::clone(&self.budget),
            bytes,
            class: self.class,
        })
    }

    /// Fold another reservation from the same budget into this one.
    pub fn merge(&mut self, mut other: Reservation) -> Result<(), Reservation> {
        if !Arc::ptr_eq(&self.budget, &other.budget) || self.class != other.class {
            return Err(other);
        }
        self.bytes += other.bytes;
        other.bytes = 0;
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.budget.sub_chain(self.bytes, self.class);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn hierarchy_enforces_every_level() {
        let process = Budget::root(1000);
        let peer = process.child(600);
        let other = process.child(600);
        let a = peer.try_reserve(500, PoolClass::Receive).expect("fits");
        assert!(
            peer.try_reserve(200, PoolClass::Receive).is_err(),
            "peer cap"
        );
        let b = other.try_reserve(500, PoolClass::Transmit).expect("fits");
        assert!(
            other.try_reserve(1, PoolClass::Transmit).is_err(),
            "process cap"
        );
        assert_eq!(process.used(), 1000);
        assert_eq!(process.class_used(PoolClass::Receive), 500);
        drop(a);
        drop(b);
        assert_eq!(process.used(), 0);
        assert_eq!(peer.used(), 0);
        assert_eq!(process.class_used(PoolClass::Receive), 0);
    }

    #[test]
    fn failed_parent_rolls_back_child() {
        let process = Budget::root(100);
        let peer = process.child(1000);
        let _hold = process.try_reserve(90, PoolClass::Control).expect("fits");
        assert!(peer.try_reserve(50, PoolClass::Receive).is_err());
        assert_eq!(peer.used(), 0, "child must be rolled back");
    }

    #[test]
    fn grow_shrink_split() {
        let root = Budget::root(100);
        let mut r = root.try_reserve(10, PoolClass::Receive).expect("r");
        r.try_grow(20).expect("grow");
        assert_eq!(root.used(), 30);
        let s = r.split_off(5).expect("split");
        assert_eq!(root.used(), 30);
        r.shrink(10);
        assert_eq!(root.used(), 20);
        drop(s);
        assert_eq!(root.used(), 15);
        assert!(r.try_grow(1000).is_err());
        drop(r);
        assert_eq!(root.used(), 0);
    }

    #[test]
    fn reserve_range_settles_for_smaller_window() {
        let root = Budget::root(100);
        let _a = root.try_reserve(70, PoolClass::Receive).expect("a");
        let r = root
            .try_reserve_range(10, 64, PoolClass::Receive)
            .expect("range");
        assert_eq!(r.bytes(), 30);
        assert!(root.try_reserve_range(10, 64, PoolClass::Receive).is_err());
    }

    proptest! {
        #[test]
        fn never_exceeds_limit_and_always_returns_to_zero(ops in proptest::collection::vec((0u64..300, any::<bool>()), 1..200)) {
            let root = Budget::root(1024);
            let child = root.child(700);
            let mut held = Vec::new();
            for (n, use_child) in ops {
                let b = if use_child { &child } else { &root };
                if let Ok(r) = b.try_reserve(n, PoolClass::Receive) {
                    held.push(r);
                }
                prop_assert!(root.used() <= 1024);
                prop_assert!(child.used() <= 700);
                if held.len() > 8 {
                    held.remove(0);
                }
            }
            drop(held);
            prop_assert_eq!(root.used(), 0);
            prop_assert_eq!(child.used(), 0);
        }
    }
}
