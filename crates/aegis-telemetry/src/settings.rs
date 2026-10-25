//! Telemetry settings (OpenAPI `TelemetrySettings`) and validation.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    Strict,
    Restricted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportProfile {
    Off,
    CoarseExport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceDetectionMode {
    Off,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySettings {
    pub export_enabled: bool,
    pub local_metrics_enabled: bool,
    pub collector_url: Option<String>,
    pub privacy_mode: PrivacyMode,
    pub credential_ref: Option<String>,
    pub export_profile: ExportProfile,
    pub resource_detection_mode: ResourceDetectionMode,
    pub service_name: Option<String>,
}

impl Default for TelemetrySettings {
    fn default() -> Self {
        TelemetrySettings {
            export_enabled: false,
            local_metrics_enabled: true,
            collector_url: None,
            privacy_mode: PrivacyMode::Strict,
            credential_ref: None,
            export_profile: ExportProfile::Off,
            resource_detection_mode: ResourceDetectionMode::Off,
            service_name: None,
        }
    }
}

/// JSON merge patch body (validated against the known keys).
pub type TelemetrySettingsPatch = serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsError {
    InvalidPatch(String),
    Invalid(String),
}

impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettingsError::InvalidPatch(e) => write!(f, "invalid patch: {e}"),
            SettingsError::Invalid(e) => write!(f, "invalid settings: {e}"),
        }
    }
}

impl std::error::Error for SettingsError {}

const KEYS: &[&str] = &[
    "export_enabled",
    "local_metrics_enabled",
    "collector_url",
    "privacy_mode",
    "credential_ref",
    "export_profile",
    "resource_detection_mode",
    "service_name",
];

/// Validate a collector endpoint: HTTPS only, no embedded credentials, no
/// query/fragment.
pub fn validate_collector_url(url: &str) -> Result<(), String> {
    if url.len() > 2048 {
        return Err("collector_url too long".into());
    }
    let rest = url
        .strip_prefix("https://")
        .ok_or("collector_url must use https:// (validated TLS)")?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err("collector_url has no host".into());
    }
    if authority.contains('@') {
        return Err("collector_url must not embed credentials".into());
    }
    if url.contains('?') || url.contains('#') {
        return Err("collector_url must not carry a query or fragment".into());
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("collector_url contains invalid characters".into());
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| "collector_url is invalid")?;
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("collector_url is invalid".into());
    }
    Ok(())
}

pub fn canonical_collector_url(url: &str) -> Result<String, String> {
    validate_collector_url(url)?;
    Ok(reqwest::Url::parse(url)
        .map_err(|_| "collector_url is invalid")?
        .to_string())
}

pub fn validate_service_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 100 {
        return Err("service_name must be 1..=100 characters".into());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err("service_name must match ^[a-zA-Z0-9_.-]+$".into());
    }
    Ok(())
}

impl TelemetrySettings {
    pub fn validate(&self) -> Result<(), SettingsError> {
        let invalid = |m: String| Err(SettingsError::Invalid(m));
        if let Some(url) = &self.collector_url {
            if let Err(e) = validate_collector_url(url) {
                return invalid(e);
            }
        }
        if let Some(name) = &self.service_name {
            if let Err(e) = validate_service_name(name) {
                return invalid(e);
            }
        }
        if let Some(r) = &self.credential_ref {
            if !r.starts_with("secret://") || r.len() > 512 {
                return invalid("credential_ref must be a secret:// reference".into());
            }
        }
        if self.export_enabled {
            if self.export_profile != ExportProfile::CoarseExport {
                return invalid("export_enabled requires export_profile=coarse_export".into());
            }
            if self.collector_url.is_none() {
                return invalid("export requires an approved collector_url".into());
            }
            if self.service_name.is_none() {
                return invalid(
                    "export requires a truthful, operator-configured service_name".into(),
                );
            }
        }
        Ok(())
    }

    /// Apply a JSON merge patch and validate the effective result.
    pub fn apply_patch(
        &self,
        patch: &serde_json::Value,
    ) -> Result<TelemetrySettings, SettingsError> {
        let obj = patch
            .as_object()
            .ok_or_else(|| SettingsError::InvalidPatch("body must be an object".into()))?;
        if obj.is_empty() {
            return Err(SettingsError::InvalidPatch(
                "at least one field is required".into(),
            ));
        }
        for k in obj.keys() {
            if !KEYS.contains(&k.as_str()) {
                return Err(SettingsError::InvalidPatch(format!("unknown field {k}")));
            }
        }
        let mut current =
            serde_json::to_value(self).map_err(|e| SettingsError::InvalidPatch(e.to_string()))?;
        if let Some(cur) = current.as_object_mut() {
            for (k, v) in obj {
                cur.insert(k.clone(), v.clone());
            }
        }
        let merged: TelemetrySettings = serde_json::from_value(current)
            .map_err(|e| SettingsError::InvalidPatch(e.to_string()))?;
        merged.validate()?;
        Ok(merged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_are_private() {
        let s = TelemetrySettings::default();
        assert!(!s.export_enabled);
        assert_eq!(s.export_profile, ExportProfile::Off);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn export_requires_consent_fields() {
        let s = TelemetrySettings::default();
        assert!(s.apply_patch(&json!({"export_enabled": true})).is_err());
        assert!(s
            .apply_patch(&json!({"export_enabled": true, "export_profile": "coarse_export", "collector_url": "https://otel.example.org/v1/metrics"}))
            .is_err(), "service_name required");
        let ok = s
            .apply_patch(&json!({
                "export_enabled": true,
                "export_profile": "coarse_export",
                "collector_url": "https://otel.example.org/v1/metrics",
                "service_name": "network-runtime"
            }))
            .expect("valid");
        assert!(ok.export_enabled);
    }

    #[test]
    fn endpoint_policy() {
        for bad in [
            "http://otel.example.org/v1/metrics",
            "https://user:pw@otel.example.org/v1/metrics",
            "https://otel.example.org/v1/metrics?token=x",
            "https:///v1/metrics",
        ] {
            assert!(validate_collector_url(bad).is_err(), "{bad}");
        }
        let s = TelemetrySettings::default();
        assert!(s
            .apply_patch(&json!({"resource_detection_mode": "auto"}))
            .is_err());
        assert!(s.apply_patch(&json!({"surprise": 1})).is_err());
        assert!(s.apply_patch(&json!({})).is_err());
        assert!(s
            .apply_patch(&json!({"credential_ref": "plain-token"}))
            .is_err());
    }
}
