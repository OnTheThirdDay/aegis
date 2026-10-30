//! Bounded in-memory counters (05 §4). Every dimension is a finite enum, so
//! series counts are fixed at compile time. Recording is a relaxed atomic add:
//! no I/O, no locks, no allocation on the data path.

use crate::catalog::DURATION_BOUNDARIES;
use crate::diagnostic::DiagnosticSink;
use aegis_contracts::observability::{Direction, Event, Observability, OperationResult};
use aegis_contracts::reason::ReasonGroup;
use aegis_contracts::route::{RouteAction, RuleClass};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const REASONS: usize = 12;
const RESULTS: usize = 5;
const ACTIONS: usize = 3;
const CLASSES: usize = 7;
const BUCKETS: usize = 12; // 11 boundaries + overflow

fn result_idx(r: OperationResult) -> usize {
    match r {
        OperationResult::Ok => 0,
        OperationResult::Error => 1,
        OperationResult::Cancelled => 2,
        OperationResult::Denied => 3,
        OperationResult::Timeout => 4,
    }
}

const RESULT_NAMES: [&str; RESULTS] = ["ok", "error", "cancelled", "denied", "timeout"];
const ACTION_NAMES: [&str; ACTIONS] = ["proxy", "direct", "deny"];
const CLASS_NAMES: [&str; CLASSES] = [
    "explicit_deny",
    "privacy",
    "identity",
    "domain",
    "cidr",
    "default",
    "other",
];

fn action_idx(a: RouteAction) -> usize {
    match a {
        RouteAction::Proxy => 0,
        RouteAction::Direct => 1,
        RouteAction::Deny => 2,
    }
}

fn class_idx(c: RuleClass) -> usize {
    match c {
        RuleClass::ExplicitDeny => 0,
        RuleClass::Privacy => 1,
        RuleClass::Identity => 2,
        RuleClass::Domain => 3,
        RuleClass::Cidr => 4,
        RuleClass::Default => 5,
        RuleClass::Other => 6,
    }
}

#[derive(Default)]
struct Histogram {
    buckets: [AtomicU64; BUCKETS],
    count: AtomicU64,
    /// Sum in microseconds.
    sum_us: AtomicU64,
}

impl Histogram {
    fn observe(&self, seconds: f64) {
        let idx = DURATION_BOUNDARIES
            .iter()
            .position(|b| seconds <= *b)
            .unwrap_or(BUCKETS - 1);
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us
            .fetch_add((seconds.max(0.0) * 1e6) as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> HistogramSnapshot {
        HistogramSnapshot {
            boundaries: DURATION_BOUNDARIES.to_vec(),
            buckets: self
                .buckets
                .iter()
                .map(|b| b.load(Ordering::Relaxed))
                .collect(),
            count: self.count.load(Ordering::Relaxed),
            sum_seconds: self.sum_us.load(Ordering::Relaxed) as f64 / 1e6,
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct HistogramSnapshot {
    pub boundaries: Vec<f64>,
    pub buckets: Vec<u64>,
    pub count: u64,
    pub sum_seconds: f64,
}

/// Authoritative gauges read from the core at snapshot time (active counts
/// are never reconstructed from a lossy event stream).
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub struct CoreGauges {
    pub sessions_active: u64,
    pub streams_active: u64,
    pub buffer_receive: u64,
    pub buffer_transmit: u64,
    pub buffer_control: u64,
    pub buffer_total: u64,
}

#[derive(Default)]
pub struct LocalMetrics {
    sessions_opened: AtomicU64,
    sessions_closed: AtomicU64,
    streams_opened: AtomicU64,
    stream_closed: [[AtomicU64; REASONS]; RESULTS],
    open_duration: [Histogram; RESULTS],
    handshake_duration: [Histogram; RESULTS],
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    reconnects: [AtomicU64; REASONS],
    route_decisions: [[AtomicU64; CLASSES]; ACTIONS],
    throttles: [AtomicU64; REASONS],
    activations: [AtomicU64; RESULTS],
    auth_failures: [AtomicU64; REASONS],
    /// Indexed by catalog `runtime.reason`.
    telemetry_dropped: [AtomicU64; 5],
    diagnostics: Option<Arc<DiagnosticSink>>,
}

impl LocalMetrics {
    pub fn new(diagnostics: Option<Arc<DiagnosticSink>>) -> Self {
        LocalMetrics {
            diagnostics,
            ..Default::default()
        }
    }

    /// The on-demand diagnostics recorder events are mirrored into.
    pub fn diagnostics(&self) -> Option<&Arc<DiagnosticSink>> {
        self.diagnostics.as_ref()
    }

    /// Count a dropped telemetry item (`runtime.reason` index).
    pub fn telemetry_dropped(&self, reason: &str) {
        let idx = crate::catalog::RUNTIME_REASON_VALUES
            .iter()
            .position(|r| *r == reason)
            .unwrap_or(4);
        self.telemetry_dropped[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Completed operations folded into the coarse `runtime.result` classes.
    pub fn operations_by_result(&self) -> [u64; 4] {
        let mut out = [0u64; 4];
        for (ri, row) in self.stream_closed.iter().enumerate() {
            let total: u64 = row.iter().map(|c| c.load(Ordering::Relaxed)).sum();
            let slot = match ri {
                0 => 0,         // ok
                1 | 3 | 4 => 1, // error/denied/timeout -> failed
                2 => 2,         // cancelled
                _ => 3,
            };
            out[slot] += total;
        }
        out
    }

    pub fn telemetry_dropped_by_reason(&self) -> [u64; 5] {
        let mut out = [0u64; 5];
        for (i, c) in self.telemetry_dropped.iter().enumerate() {
            out[i] = c.load(Ordering::Relaxed);
        }
        out
    }

    pub fn snapshot(&self, gauges: CoreGauges) -> MetricsSnapshot {
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let reason_map = |arr: &[AtomicU64; REASONS]| -> BTreeMap<&'static str, u64> {
            ReasonGroup::ALL
                .iter()
                .map(|r| (r.as_str(), load(&arr[r.index()])))
                .filter(|(_, v)| *v > 0)
                .collect()
        };
        let mut stream_closed = BTreeMap::new();
        for (ri, row) in self.stream_closed.iter().enumerate() {
            let m = reason_map(row);
            if !m.is_empty() {
                stream_closed.insert(RESULT_NAMES[ri], m);
            }
        }
        let mut route = BTreeMap::new();
        for (ai, row) in self.route_decisions.iter().enumerate() {
            let m: BTreeMap<&'static str, u64> = row
                .iter()
                .enumerate()
                .map(|(ci, v)| (CLASS_NAMES[ci], load(v)))
                .filter(|(_, v)| *v > 0)
                .collect();
            if !m.is_empty() {
                route.insert(ACTION_NAMES[ai], m);
            }
        }
        let per_result = |arr: &[AtomicU64; RESULTS]| -> BTreeMap<&'static str, u64> {
            arr.iter()
                .enumerate()
                .map(|(i, v)| (RESULT_NAMES[i], load(v)))
                .filter(|(_, v)| *v > 0)
                .collect()
        };
        MetricsSnapshot {
            gauges,
            sessions_opened: load(&self.sessions_opened),
            sessions_closed: load(&self.sessions_closed),
            streams_opened: load(&self.streams_opened),
            stream_closed,
            stream_open_duration: RESULT_NAMES
                .iter()
                .enumerate()
                .map(|(i, n)| (*n, self.open_duration[i].snapshot()))
                .filter(|(_, h)| h.count > 0)
                .collect(),
            handshake_duration: RESULT_NAMES
                .iter()
                .enumerate()
                .map(|(i, n)| (*n, self.handshake_duration[i].snapshot()))
                .filter(|(_, h)| h.count > 0)
                .collect(),
            transport_bytes_up: load(&self.bytes_up),
            transport_bytes_down: load(&self.bytes_down),
            transport_reconnects: reason_map(&self.reconnects),
            route_decisions: route,
            resource_throttles: reason_map(&self.throttles),
            config_activations: per_result(&self.activations),
            auth_failures: reason_map(&self.auth_failures),
            telemetry_dropped: crate::catalog::RUNTIME_REASON_VALUES
                .iter()
                .enumerate()
                .map(|(i, n)| (*n, load(&self.telemetry_dropped[i])))
                .filter(|(_, v)| *v > 0)
                .collect(),
        }
    }
}

impl Observability for LocalMetrics {
    fn record(&self, event: Event) {
        match event {
            Event::SessionOpened => {
                self.sessions_opened.fetch_add(1, Ordering::Relaxed);
            }
            Event::SessionClosed { .. } => {
                self.sessions_closed.fetch_add(1, Ordering::Relaxed);
            }
            Event::StreamOpened => {
                self.streams_opened.fetch_add(1, Ordering::Relaxed);
            }
            Event::StreamClosed { result, reason } => {
                self.stream_closed[result_idx(result)][reason.index()]
                    .fetch_add(1, Ordering::Relaxed);
            }
            Event::StreamOpenDuration { seconds, result } => {
                self.open_duration[result_idx(result)].observe(seconds);
            }
            Event::HandshakeDuration { seconds, result } => {
                self.handshake_duration[result_idx(result)].observe(seconds);
            }
            Event::TransportBytes { direction, bytes } => match direction {
                Direction::Up => {
                    self.bytes_up.fetch_add(bytes, Ordering::Relaxed);
                }
                Direction::Down => {
                    self.bytes_down.fetch_add(bytes, Ordering::Relaxed);
                }
            },
            Event::TransportReconnect { reason } => {
                self.reconnects[reason.index()].fetch_add(1, Ordering::Relaxed);
            }
            Event::RouteDecision { action, class } => {
                self.route_decisions[action_idx(action)][class_idx(class)]
                    .fetch_add(1, Ordering::Relaxed);
            }
            Event::ResourceThrottle { reason } => {
                self.throttles[reason.index()].fetch_add(1, Ordering::Relaxed);
            }
            Event::ConfigActivation { result } => {
                self.activations[result_idx(result)].fetch_add(1, Ordering::Relaxed);
            }
            Event::AuthFailure { reason } => {
                self.auth_failures[reason.index()].fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some(d) = &self.diagnostics {
            d.record(event);
        }
    }
}

/// Authenticated local status payload. Contains counts only: no
/// destinations, identities, rule IDs or free-form strings.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct MetricsSnapshot {
    pub gauges: CoreGauges,
    pub sessions_opened: u64,
    pub sessions_closed: u64,
    pub streams_opened: u64,
    pub stream_closed: BTreeMap<&'static str, BTreeMap<&'static str, u64>>,
    pub stream_open_duration: BTreeMap<&'static str, HistogramSnapshot>,
    pub handshake_duration: BTreeMap<&'static str, HistogramSnapshot>,
    pub transport_bytes_up: u64,
    pub transport_bytes_down: u64,
    pub transport_reconnects: BTreeMap<&'static str, u64>,
    pub route_decisions: BTreeMap<&'static str, BTreeMap<&'static str, u64>>,
    pub resource_throttles: BTreeMap<&'static str, u64>,
    pub config_activations: BTreeMap<&'static str, u64>,
    pub auth_failures: BTreeMap<&'static str, u64>,
    pub telemetry_dropped: BTreeMap<&'static str, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_o02_bounded_series_under_diverse_load() {
        let m = LocalMetrics::new(None);
        // 100k diverse events: series stay bounded by enum cardinality.
        for i in 0..100_000u64 {
            let reason = ReasonGroup::ALL[(i % 12) as usize];
            let result = [
                OperationResult::Ok,
                OperationResult::Error,
                OperationResult::Cancelled,
                OperationResult::Denied,
                OperationResult::Timeout,
            ][(i % 5) as usize];
            m.record(Event::StreamClosed { result, reason });
            m.record(Event::StreamOpenDuration {
                seconds: (i % 1000) as f64 / 37.0,
                result,
            });
            m.record(Event::RouteDecision {
                action: RouteAction::Proxy,
                class: RuleClass::Domain,
            });
        }
        let s = m.snapshot(CoreGauges::default());
        let series: usize = s.stream_closed.values().map(|v| v.len()).sum();
        assert!(series <= RESULTS * REASONS);
        assert!(s
            .stream_open_duration
            .values()
            .all(|h| h.buckets.len() == BUCKETS));
        let total: u64 = m.operations_by_result().iter().sum();
        assert_eq!(total, 100_000);
    }

    #[test]
    fn snapshot_contains_no_free_form_strings() {
        let m = LocalMetrics::new(None);
        m.record(Event::AuthFailure {
            reason: ReasonGroup::Auth,
        });
        let json = serde_json::to_string(&m.snapshot(CoreGauges::default())).expect("json");
        assert!(!json.contains("example"));
        assert!(json.contains("\"auth\":1"));
    }
}
