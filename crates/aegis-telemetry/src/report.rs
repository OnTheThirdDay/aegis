//! Diagnostic reports: one side's recording plus who recorded it, in
//! OpenTelemetry's OTLP/JSON logs encoding (`resourceLogs`). The same file
//! can be loaded into any OTLP-compatible tool, sent from a device to its
//! gateway, or imported into the console by hand.

use crate::diagnostic::{now_unix_ms, Record, Recording, Severity, RETAIN_AFTER};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::Mutex;

pub const SCOPE: &str = "aegis.diagnostics";
/// A report summary record carrying the per-kind counts.
const SUMMARY: &str = "diagnostic.summary";
/// Device reports a gateway holds at once.
pub const MAX_DEVICE_REPORTS: usize = 16;
/// Storage cap for all held device reports together.
pub const MAX_HELD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Gateway,
    Client,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Gateway => "gateway",
            Role::Client => "client",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub role: Role,
    /// Device or gateway name.
    pub name: String,
    pub version: String,
    #[serde(flatten)]
    pub recording: Recording,
}

fn s(v: &str) -> Value {
    json!({ "stringValue": v })
}

fn i(v: u64) -> Value {
    json!({ "intValue": v.to_string() })
}

fn kv(key: &str, value: Value) -> Value {
    json!({ "key": key, "value": value })
}

fn attrs(list: &[Value]) -> Option<Map<String, Value>> {
    let mut out = Map::new();
    for a in list {
        let key = a.get("key")?.as_str()?;
        let v = a.get("value")?;
        let value = if let Some(x) = v.get("stringValue") {
            x.clone()
        } else if let Some(x) = v.get("intValue") {
            // OTLP/JSON encodes 64-bit integers as strings; accept both.
            match x {
                Value::String(t) => Value::String(t.clone()),
                other => Value::String(other.to_string()),
            }
        } else if let Some(x) = v.get("boolValue") {
            Value::String(x.to_string())
        } else if let Some(x) = v.get("doubleValue") {
            Value::String(x.to_string())
        } else {
            continue;
        };
        out.insert(key.to_owned(), value);
    }
    Some(out)
}

fn text<'a>(m: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    m.get(key)?.as_str()
}

fn number(m: &Map<String, Value>, key: &str) -> u64 {
    text(m, key).and_then(|t| t.parse().ok()).unwrap_or(0)
}

fn nanos(ms: u64) -> String {
    (u128::from(ms) * 1_000_000).to_string()
}

fn log_record(rec: &Record) -> Value {
    let mut a = vec![kv("event.name", s(&rec.code))];
    a.extend(
        rec.attrs
            .iter()
            .map(|(k, v)| kv(&format!("aegis.{k}"), s(v))),
    );
    if rec.repeat > 1 {
        a.push(kv("aegis.repeat", i(rec.repeat)));
    }
    json!({
        "timeUnixNano": nanos(rec.time_unix_ms),
        "severityNumber": rec.severity.number(),
        "severityText": rec.severity.as_str(),
        "body": s(&rec.code),
        "attributes": a,
    })
}

impl Report {
    /// One `resourceLogs` entry.
    pub fn to_otlp_resource(&self) -> Value {
        let mut records: Vec<Value> = self.recording.records.iter().map(log_record).collect();
        records.push(self.summary_record());
        let mut resource = self.resource_head();
        resource["scopeLogs"][0]["logRecords"] = Value::Array(records);
        resource
    }

    /// The summary log record: counts per event kind and dropped records.
    fn summary_record(&self) -> Value {
        let r = &self.recording;
        let mut summary = vec![
            kv("event.name", s(SUMMARY)),
            kv("aegis.dropped", i(r.dropped)),
        ];
        summary.extend(
            r.counts
                .iter()
                .map(|(k, n)| kv(&format!("aegis.count.{k}"), i(*n))),
        );
        json!({
            "timeUnixNano": nanos(r.ended_unix_ms),
            "severityNumber": Severity::Info.number(),
            "severityText": Severity::Info.as_str(),
            "body": s(SUMMARY),
            "attributes": summary,
        })
    }

    /// The resource, with an empty `logRecords`.
    fn resource_head(&self) -> Value {
        let r = &self.recording;
        let service = match self.role {
            Role::Gateway => "aegisd",
            Role::Client => "aegis-client",
        };
        json!({
            "resource": { "attributes": [
                kv("service.name", s(service)),
                kv("service.version", s(&self.version)),
                kv("aegis.role", s(self.role.as_str())),
                kv("aegis.name", s(&self.name)),
                kv("aegis.diagnostic.started_unix_ms", i(r.started_unix_ms)),
                kv("aegis.diagnostic.ended_unix_ms", i(r.ended_unix_ms)),
            ]},
            "scopeLogs": [{
                "scope": { "name": SCOPE, "version": "1" },
                "logRecords": [],
            }],
        })
    }

    /// The OTLP/JSON document of [`to_otlp`](Self::to_otlp), written record
    /// by record (without building the whole document in memory).
    fn write_otlp(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        let head = self.resource_head().to_string();
        // The head ends with the empty array: `…"logRecords":[]}]}`.
        let open = head
            .rfind("[]")
            .ok_or_else(|| std::io::Error::other("unexpected resource layout"))?;
        out.write_all(b"{\"resourceLogs\":[")?;
        out.write_all(&head.as_bytes()[..=open])?;
        for rec in &self.recording.records {
            serde_json::to_writer(&mut *out, &log_record(rec))?;
            out.write_all(b",")?;
        }
        serde_json::to_writer(&mut *out, &self.summary_record())?;
        out.write_all(&head.as_bytes()[open + 1..])?;
        out.write_all(b"]}")
    }

    pub fn to_otlp(&self) -> Value {
        to_otlp(std::slice::from_ref(self))
    }

    /// Parse every AegisBorne report in an OTLP/JSON logs document. Records
    /// from other scopes are ignored.
    pub fn from_otlp(doc: &Value) -> Result<Vec<Report>, &'static str> {
        let resources = doc
            .get("resourceLogs")
            .and_then(Value::as_array)
            .ok_or("not an OTLP logs document (no resourceLogs)")?;
        let mut out = Vec::new();
        for res in resources {
            let ra = res
                .pointer("/resource/attributes")
                .and_then(Value::as_array)
                .and_then(|a| attrs(a))
                .ok_or("invalid resource attributes")?;
            let role = match text(&ra, "aegis.role") {
                Some("gateway") => Role::Gateway,
                Some("client") => Role::Client,
                _ => continue,
            };
            let mut recording = Recording {
                started_unix_ms: number(&ra, "aegis.diagnostic.started_unix_ms"),
                ended_unix_ms: number(&ra, "aegis.diagnostic.ended_unix_ms"),
                ..Recording::default()
            };
            let scopes = res.get("scopeLogs").and_then(Value::as_array);
            for scope in scopes.into_iter().flatten() {
                if scope.pointer("/scope/name").and_then(Value::as_str) != Some(SCOPE) {
                    continue;
                }
                let logs = scope.get("logRecords").and_then(Value::as_array);
                for log in logs.into_iter().flatten() {
                    let la = log
                        .get("attributes")
                        .and_then(Value::as_array)
                        .and_then(|a| attrs(a))
                        .unwrap_or_default();
                    let code = text(&la, "event.name")
                        .or_else(|| log.pointer("/body/stringValue").and_then(Value::as_str))
                        .unwrap_or("unknown")
                        .to_owned();
                    if code == SUMMARY {
                        recording.dropped = number(&la, "aegis.dropped");
                        for (k, v) in &la {
                            if let (Some(kind), Some(n)) = (
                                k.strip_prefix("aegis.count."),
                                v.as_str().and_then(|t| t.parse().ok()),
                            ) {
                                recording.counts.insert(kind.to_owned(), n);
                            }
                        }
                        continue;
                    }
                    let time = log
                        .get("timeUnixNano")
                        .and_then(|t| match t {
                            Value::String(x) => x.parse::<u128>().ok(),
                            Value::Number(x) => x.as_u64().map(u128::from),
                            _ => None,
                        })
                        .map(|n| (n / 1_000_000) as u64)
                        .unwrap_or(0);
                    let severity = Severity::from_text(
                        log.get("severityText")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    );
                    let repeat = number(&la, "aegis.repeat").max(1);
                    let attrs: BTreeMap<String, String> = la
                        .iter()
                        .filter_map(|(k, v)| {
                            let k = k.strip_prefix("aegis.").filter(|k| *k != "repeat")?;
                            Some((k.to_owned(), v.as_str()?.to_owned()))
                        })
                        .collect();
                    recording.records.push(Record {
                        time_unix_ms: time,
                        severity,
                        code,
                        attrs,
                        repeat,
                    });
                }
            }
            out.push(Report {
                role,
                name: text(&ra, "aegis.name").unwrap_or("unknown").to_owned(),
                version: text(&ra, "service.version").unwrap_or("").to_owned(),
                recording,
            });
        }
        if out.is_empty() {
            return Err("the file holds no AegisBorne diagnostic report");
        }
        Ok(out)
    }
}

/// Largest report a gateway decompresses (well above what the 5 MiB
/// recording cap encodes to).
pub const MAX_DECODED: usize = 16 * 1024 * 1024;

impl Report {
    /// Gzipped OTLP/JSON for upload, trimming the oldest records until the
    /// compressed size fits in `max`.
    pub fn to_gzip(&mut self, max: usize) -> Vec<u8> {
        use flate2::{write::GzEncoder, Compression};
        loop {
            let mut gz =
                std::io::BufWriter::new(GzEncoder::new(Vec::new(), Compression::default()));
            let out = self
                .write_otlp(&mut gz)
                .and_then(|()| gz.into_inner().map_err(|e| e.into_error()))
                .and_then(|gz| gz.finish())
                .unwrap_or_default();
            if out.len() <= max || self.recording.records.is_empty() {
                return out;
            }
            let cut = (self.recording.records.len() / 4).max(1);
            self.recording.records.drain(..cut);
            self.recording.dropped += cut as u64;
        }
    }

    /// Parse gzipped OTLP/JSON, refusing anything that inflates beyond
    /// [`MAX_DECODED`].
    pub fn from_gzip(data: &[u8]) -> Result<Vec<Report>, &'static str> {
        use std::io::Read;
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(data)
            .take(MAX_DECODED as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| "the report is not valid gzip")?;
        if out.len() > MAX_DECODED {
            return Err("the report is too large");
        }
        let doc: Value = serde_json::from_slice(&out).map_err(|_| "the report is not JSON")?;
        Report::from_otlp(&doc)
    }
}

pub fn to_otlp(reports: &[Report]) -> Value {
    json!({ "resourceLogs": reports.iter().map(Report::to_otlp_resource).collect::<Vec<_>>() })
}

#[derive(Clone, Debug, Serialize)]
pub struct HeldReport {
    pub received_unix_ms: u64,
    pub report: Report,
}

/// Device reports a gateway received, in memory only, dropped
/// [`RETAIN_AFTER`] after arrival or on [`clear`](Self::clear).
#[derive(Debug, Default)]
pub struct ReportStore {
    reports: Mutex<Vec<HeldReport>>,
}

impl ReportStore {
    fn prune(list: &mut Vec<HeldReport>) {
        let horizon = now_unix_ms().saturating_sub(RETAIN_AFTER.as_millis() as u64);
        list.retain(|h| h.received_unix_ms >= horizon);
    }

    /// Keep `report`, replacing an earlier one from the same device. The
    /// oldest reports are deleted to stay within [`MAX_DEVICE_REPORTS`] and
    /// [`MAX_HELD_BYTES`].
    pub fn put(&self, report: Report) {
        let size =
            |r: &Report| -> usize { r.recording.records.iter().map(Record::approx_bytes).sum() };
        let mut list = self.reports.lock().unwrap_or_else(|e| e.into_inner());
        Self::prune(&mut list);
        list.retain(|h| h.report.name != report.name);
        let incoming = size(&report);
        while !list.is_empty()
            && (list.len() >= MAX_DEVICE_REPORTS
                || list.iter().map(|h| size(&h.report)).sum::<usize>() + incoming > MAX_HELD_BYTES)
        {
            list.remove(0);
        }
        list.push(HeldReport {
            received_unix_ms: now_unix_ms(),
            report,
        });
    }

    pub fn list(&self) -> Vec<HeldReport> {
        let mut list = self.reports.lock().unwrap_or_else(|e| e.into_inner());
        Self::prune(&mut list);
        list.clone()
    }

    pub fn clear(&self) {
        self.reports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Report {
        let mut attrs = BTreeMap::new();
        attrs.insert("stage".to_owned(), "tls".to_owned());
        attrs.insert("error".to_owned(), "invalid peer certificate".to_owned());
        let mut counts = BTreeMap::new();
        counts.insert("client.connect.failed".to_owned(), 7);
        Report {
            role: Role::Client,
            name: "laptop".into(),
            version: "0.1.0".into(),
            recording: Recording {
                started_unix_ms: 1_700_000_000_000,
                ended_unix_ms: 1_700_000_600_000,
                records: vec![Record {
                    time_unix_ms: 1_700_000_001_234,
                    severity: Severity::Warn,
                    code: "client.connect.failed".into(),
                    attrs,
                    repeat: 7,
                }],
                counts,
                dropped: 2,
            },
        }
    }

    #[test]
    fn otlp_round_trip() {
        let r = sample();
        let doc = r.to_otlp();
        let rec = &doc["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["timeUnixNano"], "1700000001234000000");
        assert_eq!(rec["severityNumber"], 13);
        let back = Report::from_otlp(&doc).expect("parse");
        assert_eq!(back, vec![r]);
    }

    #[test]
    fn streamed_document_matches_the_built_one() {
        let mut r = sample();
        let mut out = Vec::new();
        r.write_otlp(&mut out).expect("write");
        let streamed: Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(streamed, r.to_otlp());
        r.recording.records.clear();
        let mut out = Vec::new();
        r.write_otlp(&mut out).expect("write");
        let streamed: Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(streamed, r.to_otlp());
        assert_eq!(
            Report::from_gzip(&r.to_gzip(usize::MAX)).expect("gzip"),
            vec![r]
        );
    }

    #[test]
    fn foreign_documents_are_rejected() {
        assert!(Report::from_otlp(&json!({})).is_err());
        assert!(Report::from_otlp(&json!({"resourceLogs": [
            {"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "x"}}]}}
        ]}))
        .is_err());
    }

    #[test]
    fn gzip_round_trip_and_bounds() {
        let mut r = sample();
        let one = r.recording.records[0].clone();
        r.recording.records = (0..2000)
            .map(|n| {
                let mut x = one.clone();
                x.attrs.insert("n".into(), format!("{n:x}{}", n * 7919));
                x
            })
            .collect();
        let gz = r.to_gzip(1 << 20);
        assert_eq!(Report::from_gzip(&gz).expect("parse"), vec![r.clone()]);
        let small = r.to_gzip(4_000);
        assert!(small.len() <= 4_000 && r.recording.records.len() < 2000);
        assert!(Report::from_gzip(b"not gzip").is_err());
        // A tiny bomb that inflates past the cap is refused.
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let mut gz = GzEncoder::new(Vec::new(), Compression::best());
        gz.write_all(&vec![b' '; MAX_DECODED + 10]).expect("write");
        let bomb = gz.finish().expect("finish");
        assert_eq!(Report::from_gzip(&bomb), Err("the report is too large"));
    }

    #[test]
    fn store_replaces_per_device_and_bounds() {
        let st = ReportStore::default();
        for n in 0..(MAX_DEVICE_REPORTS + 3) {
            let mut r = sample();
            r.name = format!("d{n}");
            st.put(r);
        }
        st.put(sample());
        st.put(sample());
        let list = st.list();
        assert_eq!(list.len(), MAX_DEVICE_REPORTS);
        assert_eq!(list.iter().filter(|h| h.report.name == "laptop").count(), 1);
        st.clear();
        assert!(st.list().is_empty());
    }
}
