//! On-demand diagnostics (11 §2, ADR-0008): an explicitly started, expiring,
//! in-memory recording of connection events.
//!
//! * **Off by default.** Nothing is recorded until an administrator (gateway)
//!   or the device's user (client app) starts a recording; a restart always
//!   comes back off.
//! * **Time-boxed.** Recording stops by itself after at most [`MAX_DURATION`];
//!   what was recorded is kept for [`RETAIN_AFTER`] so it can be reviewed,
//!   then dropped. Nothing is ever written to disk here.
//! * **Size-capped.** A recording holds at most [`MAX_BYTES`] of records;
//!   beyond that the oldest are deleted first. Identical consecutive records
//!   collapse into a repeat count, and a counter per event kind survives
//!   deletion.
//! * **No traffic metadata.** Core events carry only finite codes and reason
//!   groups: no destinations, identities, stream IDs or payload. Component
//!   notes ([`DiagnosticSink::note`]) may carry a bounded error message,
//!   which is why recording needs an explicit action.

use aegis_contracts::observability::{Event, OperationResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_DURATION: Duration = Duration::from_secs(60 * 60);
pub const RETAIN_AFTER: Duration = Duration::from_secs(60 * 60);
/// Storage cap for one recording's records (approximate encoded size).
pub const MAX_BYTES: usize = 5 * 1024 * 1024;
const MAX_ATTRS: usize = 8;
const MAX_VALUE: usize = 300;
/// Identical consecutive records within this window collapse into one.
const COLLAPSE_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Debug,
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Debug => "DEBUG",
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
        }
    }

    /// OpenTelemetry log severity number (DEBUG=5, INFO=9, WARN=13, ERROR=17).
    pub fn number(self) -> u8 {
        match self {
            Severity::Debug => 5,
            Severity::Info => 9,
            Severity::Warn => 13,
            Severity::Error => 17,
        }
    }

    pub fn from_text(s: &str) -> Severity {
        match s.to_ascii_uppercase().as_str() {
            "ERROR" | "FATAL" => Severity::Error,
            "WARN" | "WARNING" => Severity::Warn,
            "DEBUG" | "TRACE" => Severity::Debug,
            _ => Severity::Info,
        }
    }
}

fn is_one(n: &u64) -> bool {
    *n == 1
}

fn one() -> u64 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub time_unix_ms: u64,
    pub severity: Severity,
    pub code: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attrs: BTreeMap<String, String>,
    /// How many identical consecutive records this one stands for.
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub repeat: u64,
}

impl Record {
    /// Approximate encoded size, used for the storage cap.
    pub fn approx_bytes(&self) -> usize {
        64 + self.code.len()
            + self
                .attrs
                .iter()
                .map(|(k, v)| 24 + k.len() + v.len())
                .sum::<usize>()
    }

    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.get(key).map(String::as_str)
    }
}

/// Everything one recording holds.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Recording {
    pub started_unix_ms: u64,
    /// When recording stopped (or will stop, while still recording).
    pub ended_unix_ms: u64,
    pub records: Vec<Record>,
    /// Occurrences per event kind, including kinds not kept as records.
    pub counts: BTreeMap<String, u64>,
    /// Records pushed out of the bounded buffer.
    pub dropped: u64,
}

#[derive(Debug)]
struct Session {
    expires: Instant,
    discard_at: Instant,
    started_unix_ms: u64,
    ends_unix_ms: u64,
    stopped: bool,
    records: VecDeque<Record>,
    bytes: usize,
    counts: BTreeMap<String, u64>,
    dropped: u64,
}

impl Session {
    fn recording(&self) -> bool {
        !self.stopped && Instant::now() < self.expires
    }

    fn push(&mut self, mut r: Record) {
        *self.counts.entry(r.code.clone()).or_default() += 1;
        if let Some(last) = self.records.back_mut() {
            if last.code == r.code
                && last.severity == r.severity
                && last.attrs == r.attrs
                && r.time_unix_ms.saturating_sub(last.time_unix_ms) <= COLLAPSE_MS
            {
                last.repeat += 1;
                return;
            }
        }
        let size = r.approx_bytes();
        while self.bytes + size > MAX_BYTES {
            let Some(old) = self.records.pop_front() else {
                break;
            };
            self.bytes -= old.approx_bytes();
            self.dropped += 1;
        }
        r.repeat = 1;
        self.bytes += size;
        self.records.push_back(r);
    }
}

#[derive(Debug, Default)]
pub struct DiagnosticSink {
    state: Mutex<Option<Session>>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DiagnosticStatus {
    /// Recording right now.
    pub active: bool,
    /// `off`, `recording` or `stopped` (recorded data still held).
    pub state: &'static str,
    pub started_unix: Option<u64>,
    /// When recording stops (or stopped).
    pub ends_unix: Option<u64>,
    pub remaining_seconds: Option<u64>,
    /// When the recorded data is dropped.
    pub discard_unix: Option<u64>,
    pub events: usize,
    /// Approximate size of the held records, capped at [`MAX_BYTES`].
    pub bytes: usize,
    pub dropped: u64,
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn result_str(r: OperationResult) -> &'static str {
    match r {
        OperationResult::Ok => "ok",
        OperationResult::Error => "error",
        OperationResult::Cancelled => "cancelled",
        OperationResult::Denied => "denied",
        OperationResult::Timeout => "timeout",
    }
}

fn ms(seconds: f64) -> String {
    format!("{}", (seconds * 1000.0).round().max(0.0) as u64)
}

/// How a core event is recorded: `(code, severity, attributes, kept)`.
type Described = (&'static str, Severity, Vec<(&'static str, String)>, bool);

/// Kinds that are not kept as records are still counted.
fn describe(event: &Event) -> Option<Described> {
    Some(match *event {
        // High-volume byte accounting is not diagnostic information.
        Event::TransportBytes { .. } => return None,
        Event::SessionOpened => ("session.opened", Severity::Info, vec![], true),
        Event::SessionClosed => ("session.closed", Severity::Info, vec![], true),
        Event::StreamOpened => ("stream.opened", Severity::Debug, vec![], false),
        Event::StreamClosed { result, reason } => {
            let severity = match result {
                OperationResult::Ok | OperationResult::Cancelled => Severity::Debug,
                OperationResult::Denied | OperationResult::Timeout => Severity::Warn,
                OperationResult::Error => Severity::Error,
            };
            let kept = !matches!(result, OperationResult::Ok | OperationResult::Cancelled);
            (
                "stream.closed",
                severity,
                vec![
                    ("result", result_str(result).into()),
                    ("reason", reason.as_str().into()),
                ],
                kept,
            )
        }
        Event::StreamOpenDuration { seconds, result } => (
            "stream.open",
            if result == OperationResult::Ok {
                Severity::Debug
            } else {
                Severity::Warn
            },
            vec![
                ("result", result_str(result).into()),
                ("duration_ms", ms(seconds)),
            ],
            result != OperationResult::Ok,
        ),
        Event::TransportReconnect { reason } => (
            "transport.reconnect",
            Severity::Warn,
            vec![("reason", reason.as_str().into())],
            true,
        ),
        Event::HandshakeDuration { seconds, result } => (
            "handshake",
            if result == OperationResult::Ok {
                Severity::Info
            } else {
                Severity::Warn
            },
            vec![
                ("result", result_str(result).into()),
                ("duration_ms", ms(seconds)),
            ],
            true,
        ),
        Event::RouteDecision { action, class } => (
            "route.decision",
            Severity::Debug,
            vec![
                ("action", action.as_str().into()),
                ("class", class.as_str().into()),
            ],
            false,
        ),
        Event::ResourceThrottle { reason } => (
            "resource.throttle",
            Severity::Warn,
            vec![("reason", reason.as_str().into())],
            true,
        ),
        Event::ConfigActivation { result } => (
            "config.activation",
            if result == OperationResult::Ok {
                Severity::Info
            } else {
                Severity::Error
            },
            vec![("result", result_str(result).into())],
            true,
        ),
        Event::AuthFailure { reason } => (
            "auth.failure",
            Severity::Warn,
            vec![("reason", reason.as_str().into())],
            true,
        ),
    })
}

fn bounded(value: &str) -> String {
    if value.len() <= MAX_VALUE {
        return value.to_owned();
    }
    let mut end = MAX_VALUE;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

impl DiagnosticSink {
    pub fn new() -> Self {
        DiagnosticSink::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Session>> {
        let mut slot = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if slot
            .as_ref()
            .is_some_and(|s| Instant::now() >= s.discard_at)
        {
            *slot = None;
        }
        slot
    }

    /// Start (or restart) a recording, discarding any previous one. Callers
    /// must have verified the user's authorization; at most one hour.
    pub fn start(&self, duration: Duration) -> Result<(), &'static str> {
        if duration.is_zero() || duration > MAX_DURATION {
            return Err("diagnostic duration must be 1s..=60min");
        }
        let now = Instant::now();
        let unix = now_unix_ms();
        *self.lock() = Some(Session {
            expires: now + duration,
            discard_at: now + duration + RETAIN_AFTER,
            started_unix_ms: unix,
            ends_unix_ms: unix + duration.as_millis() as u64,
            stopped: false,
            records: VecDeque::new(),
            bytes: 0,
            counts: BTreeMap::new(),
            dropped: 0,
        });
        Ok(())
    }

    /// Stop recording now; what was recorded stays for review until
    /// [`RETAIN_AFTER`] from now or [`discard`](Self::discard).
    pub fn stop(&self) {
        if let Some(s) = self.lock().as_mut() {
            if s.recording() {
                s.stopped = true;
                s.ends_unix_ms = now_unix_ms();
                s.discard_at = Instant::now() + RETAIN_AFTER;
            }
        }
    }

    /// Drop everything recorded.
    pub fn discard(&self) {
        *self.lock() = None;
    }

    pub fn is_recording(&self) -> bool {
        match self.state.try_lock() {
            Ok(slot) => slot.as_ref().is_some_and(Session::recording),
            Err(_) => false,
        }
    }

    pub fn record(&self, event: Event) {
        let Ok(mut slot) = self.state.try_lock() else {
            return; // never block the data path
        };
        let Some(s) = slot.as_mut().filter(|s| s.recording()) else {
            return;
        };
        let Some((code, severity, attrs, kept)) = describe(&event) else {
            return;
        };
        if !kept {
            *s.counts.entry(code.into()).or_default() += 1;
            return;
        }
        s.push(Record {
            time_unix_ms: now_unix_ms(),
            severity,
            code: code.into(),
            attrs: attrs.into_iter().map(|(k, v)| (k.into(), v)).collect(),
            repeat: 1,
        });
    }

    /// Record a component event, for example a failed connection attempt
    /// with its error message. A no-op unless recording; values are
    /// truncated and at most eight attributes are kept.
    pub fn note(&self, severity: Severity, code: &str, attrs: &[(&str, &str)]) {
        let Ok(mut slot) = self.state.try_lock() else {
            return;
        };
        let Some(s) = slot.as_mut().filter(|s| s.recording()) else {
            return;
        };
        s.push(Record {
            time_unix_ms: now_unix_ms(),
            severity,
            code: bounded(code),
            attrs: attrs
                .iter()
                .take(MAX_ATTRS)
                .map(|(k, v)| (bounded(k), bounded(v)))
                .collect(),
            repeat: 1,
        });
    }

    /// Count an occurrence without keeping a record (routine successes).
    pub fn count(&self, code: &str) {
        if let Ok(mut slot) = self.state.try_lock() {
            if let Some(s) = slot.as_mut().filter(|s| s.recording()) {
                *s.counts.entry(bounded(code)).or_default() += 1;
            }
        }
    }

    /// A copy of the current or last recording, if any is held.
    pub fn recording(&self) -> Option<Recording> {
        let slot = self.lock();
        let s = slot.as_ref()?;
        Some(Recording {
            started_unix_ms: s.started_unix_ms,
            ended_unix_ms: if s.recording() {
                now_unix_ms()
            } else {
                s.ends_unix_ms.min(now_unix_ms())
            },
            records: s.records.iter().cloned().collect(),
            counts: s.counts.clone(),
            dropped: s.dropped,
        })
    }

    pub fn status(&self) -> DiagnosticStatus {
        let slot = self.lock();
        let now = Instant::now();
        let unix = now_unix_ms() / 1000;
        match slot.as_ref() {
            Some(s) => {
                let recording = s.recording();
                DiagnosticStatus {
                    active: recording,
                    state: if recording { "recording" } else { "stopped" },
                    started_unix: Some(s.started_unix_ms / 1000),
                    ends_unix: Some(if recording {
                        s.ends_unix_ms / 1000
                    } else {
                        (s.ends_unix_ms / 1000).min(unix)
                    }),
                    remaining_seconds: recording
                        .then(|| s.expires.saturating_duration_since(now).as_secs()),
                    discard_unix: Some(
                        unix + s.discard_at.saturating_duration_since(now).as_secs(),
                    ),
                    events: s.records.len(),
                    bytes: s.bytes,
                    dropped: s.dropped,
                }
            }
            None => DiagnosticStatus {
                active: false,
                state: "off",
                started_unix: None,
                ends_unix: None,
                remaining_seconds: None,
                discard_unix: None,
                events: 0,
                bytes: 0,
                dropped: 0,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_contracts::ReasonGroup;

    #[test]
    fn tc_priv05_duration_bounds_and_expiry() {
        let d = DiagnosticSink::new();
        assert!(d.start(Duration::from_secs(61 * 60)).is_err());
        assert!(d.start(Duration::ZERO).is_err());
        d.record(Event::SessionOpened);
        d.note(Severity::Warn, "client.connect.failed", &[("error", "x")]);
        assert_eq!(d.status().state, "off", "nothing recorded while off");
        assert!(d.recording().is_none());
        d.start(Duration::from_millis(50)).expect("start");
        d.record(Event::SessionOpened);
        assert_eq!(d.status().events, 1);
        std::thread::sleep(Duration::from_millis(80));
        let st = d.status();
        assert!(!st.active, "recording stops automatically");
        assert_eq!(st.state, "stopped");
        d.record(Event::SessionOpened);
        assert_eq!(d.status().events, 1, "nothing recorded after expiry");
        d.discard();
        assert_eq!(d.status().state, "off");
        // A fresh sink (process restart) is always off.
        assert!(!DiagnosticSink::new().status().active);
    }

    #[test]
    fn records_are_bounded_collapsed_and_counted() {
        let d = DiagnosticSink::new();
        d.start(Duration::from_secs(60)).expect("start");
        for _ in 0..5 {
            d.record(Event::TransportReconnect {
                reason: ReasonGroup::Tls,
            });
        }
        d.record(Event::StreamOpened);
        d.record(Event::TransportBytes {
            direction: aegis_contracts::observability::Direction::Up,
            bytes: 9,
        });
        let r = d.recording().expect("recording");
        assert_eq!(r.records.len(), 1, "identical records collapse");
        assert_eq!(r.records[0].repeat, 5);
        assert_eq!(r.records[0].attr("reason"), Some("tls"));
        assert_eq!(r.counts["transport.reconnect"], 5);
        assert_eq!(r.counts["stream.opened"], 1, "counted, not kept");
        assert!(!r.counts.contains_key("transport.io"));
        let filler = "y".repeat(250);
        for i in 0..40_000 {
            d.note(
                Severity::Info,
                "n",
                &[("i", &i.to_string()), ("f", &filler)],
            );
        }
        let st = d.status();
        assert!(st.bytes <= MAX_BYTES, "storage cap holds: {}", st.bytes);
        assert!(st.bytes > MAX_BYTES - 1024, "cap is used, not undershot");
        assert!(st.dropped > 0, "oldest records were deleted");
        let r = d.recording().expect("recording");
        assert_eq!(
            r.records.last().expect("record").attr("i"),
            Some("39999"),
            "newest kept"
        );
        assert_eq!(r.counts["n"], 40_000, "counts survive deletion");
        let long = "x".repeat(5000);
        d.note(Severity::Error, "big", &[("error", &long)]);
        let r = d.recording().expect("recording");
        assert!(r.records.last().expect("record").attrs["error"].len() <= MAX_VALUE + 4);
    }

    #[test]
    fn stop_keeps_data_for_review() {
        let d = DiagnosticSink::new();
        d.start(Duration::from_secs(600)).expect("start");
        d.record(Event::SessionOpened);
        d.stop();
        let st = d.status();
        assert_eq!(st.state, "stopped");
        assert_eq!(st.events, 1);
        assert!(st.discard_unix.is_some());
        d.record(Event::SessionClosed);
        assert_eq!(d.recording().expect("recording").records.len(), 1);
    }
}
