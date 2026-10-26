//! Host-aware telemetry (05, 11, ADR-0004).
//!
//! * **Default `off`:** no OTel SDK, no exporter, no resource detectors, no
//!   console event logs. [`LocalMetrics`] keeps bounded in-memory counters
//!   served only through authenticated local status.
//! * **Opt-in `coarse_export`:** exactly four custom `runtime.*` metrics,
//!   enforced by an exhaustive allowlist *before* serialization; resource
//!   attributes limited to a truthful `service.name` and `telemetry.sdk.*`.
//! * **On-demand diagnostics:** started explicitly by an administrator or a
//!   device's user, at most one hour, in memory only with a 5 MiB cap,
//!   switched off by itself and by any restart. Reports export as OTLP/JSON
//!   logs and are explained by [`analyze`].
//!
//! Metadata minimization is not protection against a privileged host.
#![forbid(unsafe_code)]

pub mod analyze;
pub mod catalog;
pub mod diagnostic;
pub mod export;
pub mod local;
pub mod report;
pub mod settings;

pub use diagnostic::{DiagnosticSink, Severity};
pub use export::{CoarseExporter, ExportPayload};
pub use local::{CoreGauges, LocalMetrics, MetricsSnapshot};
pub use report::{Report, ReportStore};
pub use settings::{SettingsError, TelemetrySettings, TelemetrySettingsPatch};
