//! Opt-in `coarse_export`: four allowlisted metrics over OTLP/HTTP JSON.
//!
//! The payload is built as a typed structure, checked against the exhaustive
//! allowlist (metric names, units, dimension keys and values, resource keys),
//! and only then serialized. Anything else is dropped and counted, never
//! sent. The exporter has a single in-flight request, short deadlines, no
//! redirects, no environment proxy and no spool: collector problems drop
//! telemetry, never traffic.

use crate::catalog::{self, ALLOWED_RESOURCE_ATTRIBUTES, PROHIBITED_PREFIXES};
use crate::local::{CoreGauges, LocalMetrics};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Truthful description of the encoder (a hand-written OTLP/JSON metrics
/// encoder, not the OTel SDK) without product-identifying names.
pub const SDK_NAME: &str = "coarse-otlp-json";
pub const SCOPE_NAME: &str = "runtime.coarse";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricKind {
    Gauge,
    MonotonicSum,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportPoint {
    pub attributes: Vec<(String, String)>,
    pub value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportMetric {
    pub name: String,
    pub unit: String,
    pub kind: MetricKind,
    pub points: Vec<ExportPoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportPayload {
    pub resource: Vec<(String, String)>,
    pub metrics: Vec<ExportMetric>,
}

fn sdk_resource(service_name: &str) -> Vec<(String, String)> {
    vec![
        ("service.name".into(), service_name.into()),
        ("telemetry.sdk.name".into(), SDK_NAME.into()),
        ("telemetry.sdk.language".into(), "rust".into()),
        (
            "telemetry.sdk.version".into(),
            env!("CARGO_PKG_VERSION").into(),
        ),
    ]
}

/// Map local counters to the four coarse instruments.
pub fn build_payload(
    service_name: &str,
    metrics: &LocalMetrics,
    gauges: CoreGauges,
) -> ExportPayload {
    let ops = metrics.operations_by_result();
    let dropped = metrics.telemetry_dropped_by_reason();
    ExportPayload {
        resource: sdk_resource(service_name),
        metrics: vec![
            ExportMetric {
                name: "runtime.work.active".into(),
                unit: "{item}".into(),
                kind: MetricKind::Gauge,
                points: vec![ExportPoint {
                    attributes: vec![],
                    value: gauges.streams_active,
                }],
            },
            ExportMetric {
                name: "runtime.operation.completed".into(),
                unit: "{operation}".into(),
                kind: MetricKind::MonotonicSum,
                points: catalog::RUNTIME_RESULT_VALUES
                    .iter()
                    .zip(ops)
                    .map(|(k, v)| ExportPoint {
                        attributes: vec![("runtime.result".into(), (*k).into())],
                        value: v,
                    })
                    .collect(),
            },
            ExportMetric {
                name: "runtime.buffer.in_use".into(),
                unit: "By".into(),
                kind: MetricKind::Gauge,
                points: vec![ExportPoint {
                    attributes: vec![],
                    value: gauges.buffer_total,
                }],
            },
            ExportMetric {
                name: "runtime.telemetry.dropped".into(),
                unit: "{item}".into(),
                kind: MetricKind::MonotonicSum,
                points: catalog::RUNTIME_REASON_VALUES
                    .iter()
                    .zip(dropped)
                    .map(|(k, v)| ExportPoint {
                        attributes: vec![("runtime.reason".into(), (*k).into())],
                        value: v,
                    })
                    .collect(),
            },
        ],
    }
}

/// Exhaustive pre-serialization allowlist (11 §3 rule 5).
pub fn enforce_allowlist(p: &ExportPayload) -> Result<(), String> {
    let mut seen_service = false;
    for (k, v) in &p.resource {
        if !ALLOWED_RESOURCE_ATTRIBUTES.contains(&k.as_str()) {
            return Err(format!("resource attribute {k} not allowed"));
        }
        if k == "service.name" {
            seen_service = true;
            crate::settings::validate_service_name(v)?;
        }
    }
    if !seen_service {
        return Err("service.name is required".into());
    }
    for m in &p.metrics {
        let (_, unit, dim) = catalog::coarse_metric(&m.name)
            .ok_or_else(|| format!("metric {} not in coarse_export allowlist", m.name))?;
        if *unit != m.unit {
            return Err(format!(
                "metric {} has unit {}, expected {unit}",
                m.name, m.unit
            ));
        }
        if m.points.len() > catalog::MAX_SERIES_PER_INSTRUMENT {
            return Err(format!("metric {} exceeds series cap", m.name));
        }
        for pt in &m.points {
            for (k, v) in &pt.attributes {
                if PROHIBITED_PREFIXES.iter().any(|pre| k.starts_with(pre)) {
                    return Err(format!("prohibited attribute {k}"));
                }
                if Some(k.as_str()) != *dim {
                    return Err(format!("attribute {k} not declared for {}", m.name));
                }
                let allowed = catalog::allowed_dimension_values(k).unwrap_or(&[]);
                if !allowed.contains(&v.as_str()) {
                    return Err(format!("value not allowed for {k}"));
                }
            }
        }
    }
    Ok(())
}

fn attr(k: &str, v: &str) -> Value {
    json!({"key": k, "value": {"stringValue": v}})
}

/// OTLP/HTTP JSON encoding. Call only after [`enforce_allowlist`].
pub fn to_otlp_json(p: &ExportPayload, start_ns: u64, now_ns: u64) -> Value {
    let metrics: Vec<Value> = p
        .metrics
        .iter()
        .map(|m| {
            let points: Vec<Value> = m
                .points
                .iter()
                .map(|pt| {
                    let mut o = json!({
                        "asInt": pt.value.to_string(),
                        "timeUnixNano": now_ns.to_string(),
                    });
                    if !pt.attributes.is_empty() {
                        o["attributes"] =
                            Value::Array(pt.attributes.iter().map(|(k, v)| attr(k, v)).collect());
                    }
                    if m.kind == MetricKind::MonotonicSum {
                        o["startTimeUnixNano"] = Value::String(start_ns.to_string());
                    }
                    o
                })
                .collect();
            match m.kind {
                MetricKind::Gauge => {
                    json!({"name": m.name, "unit": m.unit, "gauge": {"dataPoints": points}})
                }
                MetricKind::MonotonicSum => json!({
                    "name": m.name,
                    "unit": m.unit,
                    "sum": {"aggregationTemporality": 2, "isMonotonic": true, "dataPoints": points}
                }),
            }
        })
        .collect();
    json!({
        "resourceMetrics": [{
            "resource": {"attributes": p.resource.iter().map(|(k, v)| attr(k, v)).collect::<Vec<_>>()},
            "scopeMetrics": [{
                "scope": {"name": SCOPE_NAME, "version": env!("CARGO_PKG_VERSION")},
                "metrics": metrics
            }]
        }]
    })
}

/// The exact serialized payload that would be sent now, plus a digest of
/// its *shape* (values and timestamps zeroed). Enabling export requires the
/// operator to acknowledge this digest.
pub fn preview(
    service_name: &str,
    metrics: &LocalMetrics,
    gauges: CoreGauges,
) -> Result<(Value, String), String> {
    let payload = build_payload(service_name, metrics, gauges);
    enforce_allowlist(&payload)?;
    let now = now_ns();
    let body = to_otlp_json(&payload, now, now);
    let mut shape = payload.clone();
    for m in &mut shape.metrics {
        for p in &mut m.points {
            p.value = 0;
        }
    }
    let shape_json = to_otlp_json(&shape, 0, 0).to_string();
    Ok((body, hex::encode(Sha256::digest(shape_json.as_bytes()))))
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

pub type GaugeFn = Arc<dyn Fn() -> CoreGauges + Send + Sync>;

/// Background exporter; created only when export is explicitly enabled.
/// Dropping it stops the task.
pub struct CoarseExporter {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for CoarseExporter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl CoarseExporter {
    pub fn spawn(
        collector_url: String,
        service_name: String,
        credential: Option<String>,
        metrics: Arc<LocalMetrics>,
        gauges: GaugeFn,
        interval: Duration,
    ) -> Result<CoarseExporter, String> {
        Self::spawn_guarded(
            collector_url,
            service_name,
            credential,
            metrics,
            gauges,
            interval,
            Arc::new(|| true),
        )
    }

    pub fn spawn_guarded(
        collector_url: String,
        service_name: String,
        credential: Option<String>,
        metrics: Arc<LocalMetrics>,
        gauges: GaugeFn,
        interval: Duration,
        approved: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<CoarseExporter, String> {
        crate::settings::validate_collector_url(&collector_url)?;
        crate::settings::validate_service_name(&service_name)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(1)
            .build()
            .map_err(|e| e.to_string())?;
        let start = now_ns();
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                if !approved() {
                    break;
                }
                let payload = build_payload(&service_name, &metrics, gauges());
                if enforce_allowlist(&payload).is_err() {
                    metrics.telemetry_dropped("invalid");
                    continue;
                }
                let body = to_otlp_json(&payload, start, now_ns()).to_string();
                let mut req = client
                    .post(&collector_url)
                    .header("content-type", "application/json")
                    .body(body);
                if let Some(c) = &credential {
                    req = req.header("authorization", c.trim());
                }
                match req.send().await {
                    Ok(resp) if resp.status().is_success() => {}
                    Ok(_) => metrics.telemetry_dropped("other"),
                    Err(e) if e.is_timeout() => metrics.telemetry_dropped("deadline"),
                    Err(_) => metrics.telemetry_dropped("other"),
                }
            }
        });
        Ok(CoarseExporter { task })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_contracts::observability::{Event, Observability, OperationResult};
    use aegis_contracts::reason::ReasonGroup;
    use proptest::prelude::*;

    const FORBIDDEN_TERMS: &[&str] = &[
        "vpn",
        "proxy",
        "socks",
        "tunnel",
        "kill_switch",
        "cloudflare",
        "websocket",
        "aegis.",
        "process.",
        "host.name",
        "container",
        "k8s",
        "url.full",
        "server.address",
        "pid",
    ];

    fn metrics() -> LocalMetrics {
        let m = LocalMetrics::new(None);
        for _ in 0..3 {
            m.record(Event::StreamClosed {
                result: OperationResult::Ok,
                reason: ReasonGroup::Other,
            });
        }
        m.record(Event::StreamClosed {
            result: OperationResult::Denied,
            reason: ReasonGroup::Policy,
        });
        m
    }

    #[test]
    fn tc_priv03_04_serialized_payload_is_allowlisted() {
        let (body, digest) = preview(
            "network-runtime",
            &metrics(),
            CoreGauges {
                streams_active: 2,
                buffer_total: 1000,
                ..Default::default()
            },
        )
        .expect("preview");
        let text = body.to_string();
        for term in FORBIDDEN_TERMS {
            assert!(
                !text.to_lowercase().contains(term),
                "serialized payload contains {term}: {text}"
            );
        }
        let names: Vec<&str> = body["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .expect("metrics")
            .iter()
            .filter_map(|m| m["name"].as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "runtime.work.active",
                "runtime.operation.completed",
                "runtime.buffer.in_use",
                "runtime.telemetry.dropped"
            ]
        );
        let keys: Vec<&str> = body["resourceMetrics"][0]["resource"]["attributes"]
            .as_array()
            .expect("attrs")
            .iter()
            .filter_map(|a| a["key"].as_str())
            .collect();
        assert_eq!(keys, ALLOWED_RESOURCE_ATTRIBUTES);
        assert_eq!(digest.len(), 64);
        // Shape digest is stable while values change.
        let (_, d2) = preview(
            "network-runtime",
            &LocalMetrics::new(None),
            CoreGauges::default(),
        )
        .expect("p2");
        assert_eq!(digest, d2);
        let (_, d3) = preview(
            "other-name",
            &LocalMetrics::new(None),
            CoreGauges::default(),
        )
        .expect("p3");
        assert_ne!(digest, d3, "service name change requires a new preview");
    }

    #[test]
    fn tc_priv03_unknown_attributes_rejected_before_serialization() {
        let base = build_payload("svc", &metrics(), CoreGauges::default());
        let mut p = base.clone();
        p.resource.push(("host.name".into(), "box".into()));
        assert!(enforce_allowlist(&p).is_err());
        let mut p = base.clone();
        p.metrics[1].points[0]
            .attributes
            .push(("aegis.destination.host".into(), "example.com".into()));
        assert!(enforce_allowlist(&p).is_err());
        let mut p = base.clone();
        p.metrics[1].points[0].attributes[0].1 = "example.com".into();
        assert!(enforce_allowlist(&p).is_err());
        let mut p = base.clone();
        p.metrics.push(ExportMetric {
            name: "aegis.vpn.mode".into(),
            unit: "1".into(),
            kind: MetricKind::Gauge,
            points: vec![],
        });
        assert!(enforce_allowlist(&p).is_err());
        let mut p = base;
        p.metrics[2].unit = "s".into();
        assert!(enforce_allowlist(&p).is_err(), "units stay honest");
    }

    proptest! {
        #[test]
        fn tc_priv03_fuzzed_attributes_never_pass(key in "[a-z.]{1,24}", value in ".{0,40}") {
            let mut p = build_payload("svc", &LocalMetrics::new(None), CoreGauges::default());
            p.metrics[0].points[0].attributes.push((key.clone(), value));
            prop_assert!(enforce_allowlist(&p).is_err());
            let mut p = build_payload("svc", &LocalMetrics::new(None), CoreGauges::default());
            p.resource.push((key, "x".into()));
            let res = enforce_allowlist(&p);
            prop_assert!(res.is_err() || ALLOWED_RESOURCE_ATTRIBUTES.contains(&p.resource.last().map(|r| r.0.as_str()).unwrap_or("")));
        }
    }

    #[tokio::test]
    async fn tc_priv08_unreachable_collector_drops_without_growth() {
        let m = Arc::new(LocalMetrics::new(None));
        let exporter = CoarseExporter::spawn(
            "https://127.0.0.1:9/v1/metrics".into(),
            "network-runtime".into(),
            None,
            Arc::clone(&m),
            Arc::new(CoreGauges::default),
            Duration::from_millis(50),
        )
        .expect("spawn");
        tokio::time::sleep(Duration::from_millis(400)).await;
        drop(exporter);
        let dropped: u64 = m.telemetry_dropped_by_reason().iter().sum();
        assert!(dropped >= 1, "failed exports are counted as dropped");
        // A single in-flight request at a time: drops are bounded by ticks.
        assert!(dropped <= 10);
    }
}
