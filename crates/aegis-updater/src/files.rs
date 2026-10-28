//! The files the console and the updater exchange, in `<data>/updates/`:
//!
//! * `request.json`, written by the console, taken by the updater:
//!   `{"action": "check"}` or `{"action": "upgrade", "version": "X.Y.Z"}`;
//! * `settings.json`, written by the console: `{"auto": bool}`;
//! * `status.json`, written by the updater (see [`Status`] fields).
//!
//! Every write replaces the file atomically.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const DIR: &str = "updates";

pub fn dir(data: &Path) -> PathBuf {
    data.join(DIR)
}

fn read(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn write(path: &Path, v: &Value) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, v.to_string())?;
    std::fs::rename(&tmp, path)
}

/// What the console asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Check,
    /// Upgrade to this release version (validated), or the newest available.
    Upgrade(Option<crate::version::Version>),
}

pub fn write_request(data: &Path, request: &Request) -> std::io::Result<()> {
    std::fs::create_dir_all(dir(data))?;
    let v = match request {
        Request::Check => json!({"action": "check"}),
        Request::Upgrade(v) => json!({"action": "upgrade", "version": v.map(|v| v.to_string())}),
    };
    write(&dir(data).join("request.json"), &v)
}

/// Take the pending request, if any (it is removed). Anything malformed is
/// discarded.
pub fn take_request(data: &Path) -> Option<Request> {
    let path = dir(data).join("request.json");
    let v = read(&path);
    let _ = std::fs::remove_file(&path);
    let v = v?;
    match v["action"].as_str()? {
        "check" => Some(Request::Check),
        "upgrade" => match &v["version"] {
            Value::Null => Some(Request::Upgrade(None)),
            Value::String(s) => {
                crate::version::Version::parse(s).map(|v| Request::Upgrade(Some(v)))
            }
            _ => None,
        },
        _ => None,
    }
}

pub fn auto(data: &Path) -> bool {
    read(&dir(data).join("settings.json")).is_some_and(|v| v["auto"] == json!(true))
}

pub fn set_auto(data: &Path, on: bool) -> std::io::Result<()> {
    std::fs::create_dir_all(dir(data))?;
    write(&dir(data).join("settings.json"), &json!({ "auto": on }))
}

/// The updater's last report, as written.
pub fn status(data: &Path) -> Option<Value> {
    read(&dir(data).join("status.json"))
}

pub fn write_status(data: &Path, status: &Value) -> std::io::Result<()> {
    std::fs::create_dir_all(dir(data))?;
    write(&dir(data).join("status.json"), status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::Version;

    #[test]
    fn requests_round_trip_and_bad_ones_are_dropped() {
        let tmp = tempfile::tempdir().expect("tmp");
        let data = tmp.path();
        assert_eq!(take_request(data), None);
        write_request(data, &Request::Upgrade(Some(Version(0, 8, 0)))).expect("write");
        assert_eq!(
            take_request(data),
            Some(Request::Upgrade(Some(Version(0, 8, 0))))
        );
        assert_eq!(take_request(data), None, "taken once");
        write_request(data, &Request::Check).expect("write");
        assert_eq!(take_request(data), Some(Request::Check));
        // Only a plain release version is ever accepted.
        for bad in [
            json!({"action": "upgrade", "version": "latest"}),
            json!({"action": "upgrade", "version": "0.8.0;rm -rf /"}),
            json!({"action": "run", "image": "evil:1"}),
        ] {
            std::fs::write(dir(data).join("request.json"), bad.to_string()).expect("write");
            assert_eq!(take_request(data), None, "{bad}");
        }
        assert!(!auto(data));
        set_auto(data, true).expect("auto");
        assert!(auto(data));
    }
}
