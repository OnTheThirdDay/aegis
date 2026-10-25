//! Compile-time mirror of `schemas/telemetry-catalog.yaml`. A test checks
//! these names against the spec file so the two cannot silently drift.

pub const SEMCONV_VERSION: &str = "1.44.0";
pub const MAX_SERIES_PER_INSTRUMENT: usize = 1024;

/// The only metrics `coarse_export` may emit: (name, unit, dimension key).
pub const COARSE_METRICS: &[(&str, &str, Option<&str>)] = &[
    ("runtime.work.active", "{item}", None),
    (
        "runtime.operation.completed",
        "{operation}",
        Some("runtime.result"),
    ),
    ("runtime.buffer.in_use", "By", None),
    (
        "runtime.telemetry.dropped",
        "{item}",
        Some("runtime.reason"),
    ),
];

pub const RUNTIME_RESULT_VALUES: &[&str] = &["ok", "failed", "cancelled", "other"];
pub const RUNTIME_REASON_VALUES: &[&str] =
    &["backpressure", "capacity", "deadline", "invalid", "other"];

/// Resource attributes allowed in coarse export.
pub const ALLOWED_RESOURCE_ATTRIBUTES: &[&str] = &[
    "service.name",
    "telemetry.sdk.name",
    "telemetry.sdk.language",
    "telemetry.sdk.version",
];

/// Internal, local-only instruments (never exported).
pub const INTERNAL_METRICS: &[&str] = &[
    "aegis.session.active",
    "aegis.stream.active",
    "aegis.stream.open.duration",
    "aegis.stream.closed",
    "aegis.transport.bytes",
    "aegis.transport.reconnects",
    "aegis.transport.handshake.duration",
    "aegis.route.decisions",
    "aegis.buffer.in_use",
    "aegis.resource.throttles",
    "aegis.config.activations",
    "aegis.auth.failures",
    "aegis.telemetry.dropped",
];

/// Attribute keys that must never appear in any export (subset of the
/// catalog's `prohibited_export_attributes`, plus prefixes).
pub const PROHIBITED_PREFIXES: &[&str] = &[
    "aegis.",
    "process.",
    "host.",
    "container.",
    "k8s.",
    "url.",
    "server.",
    "network.",
    "dns.",
    "user.",
    "client.",
    "cloud.",
    "os.",
    "device.",
];

/// `aegis.stream.open.duration` bucket boundaries (seconds).
pub const DURATION_BOUNDARIES: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

pub fn coarse_metric(
    name: &str,
) -> Option<&'static (&'static str, &'static str, Option<&'static str>)> {
    COARSE_METRICS.iter().find(|(n, _, _)| *n == name)
}

pub fn allowed_dimension_values(key: &str) -> Option<&'static [&'static str]> {
    match key {
        "runtime.result" => Some(RUNTIME_RESULT_VALUES),
        "runtime.reason" => Some(RUNTIME_REASON_VALUES),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CATALOG: &str = include_str!("telemetry-catalog.yaml");

    #[test]
    fn mirrors_spec_catalog() {
        assert!(CATALOG.contains(&format!("upstream_semconv: {SEMCONV_VERSION}")));
        assert!(CATALOG.contains("max_series_per_instrument: 1024"));
        for (name, unit, _) in COARSE_METRICS {
            assert!(
                CATALOG.contains(&format!("- name: {name}")),
                "{name} missing from catalog"
            );
            assert!(
                CATALOG.contains(&format!(
                    "unit: {}",
                    if unit.starts_with('{') {
                        format!("'{unit}'")
                    } else {
                        unit.to_string()
                    }
                )),
                "{unit}"
            );
        }
        for attr in ALLOWED_RESOURCE_ATTRIBUTES {
            assert!(CATALOG.contains(&format!("- {attr}")), "{attr}");
        }
        for m in INTERNAL_METRICS {
            assert!(
                CATALOG.contains(&format!("- name: {m}")),
                "{m} missing from catalog"
            );
        }
        for v in RUNTIME_RESULT_VALUES.iter().chain(RUNTIME_REASON_VALUES) {
            assert!(CATALOG.contains(&format!("- {v}")));
        }
    }
}
