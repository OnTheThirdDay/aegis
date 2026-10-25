//! Host-aware telemetry (05, 11, ADR-0004).
//!
//! * **Default `off`:** no OTel SDK, no exporter, no resource detectors, no
//!   console event logs. [`LocalMetrics`] keeps bounded in-memory counters
//!   served only through authenticated local status.
//! * **Opt-in `coarse_export`:** exactly four custom `runtime.*` metrics,
//!   enforced by an exhaustive allowlist *before* serialization; resource
//!   attributes limited to a truthful `service.name` and `telemetry.sdk.*`.
//! * **`local_diagnostic`:** privileged, ≤15 minutes, in memory only, never
//!   exported, disabled again by any restart.
//!
//! Metadata minimization is not protection against a privileged host.
#![forbid(unsafe_code)]

pub mod catalog;
pub mod diagnostic;
pub mod export;
pub mod local;
pub mod settings;

pub use diagnostic::DiagnosticSink;
pub use export::{CoarseExporter, ExportPayload};
pub use local::{CoreGauges, LocalMetrics, MetricsSnapshot};
pub use settings::{SettingsError, TelemetrySettings, TelemetrySettingsPatch};
