//! Canonical JSON (RFC 8785 subset sufficient for the typed schema: objects
//! with lexicographically sorted keys, no insignificant whitespace, integers
//! only). Keys are sorted explicitly so the result does not depend on
//! serde_json's map feature flags.

use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write(v, &mut out);
    out
}

fn write(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            // RFC 8785 sorts by UTF-16 code units; our keys are ASCII so
            // byte order is equivalent.
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                if let Some(child) = map.get(*k) {
                    write(child, out);
                }
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

pub fn digest_value(v: &Value) -> String {
    hex::encode(Sha256::digest(canonical_json(v).as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_and_whitespace_independent() {
        let a = json!({"b": 1, "a": {"y": [1, 2], "x": "s"}});
        let b: Value =
            serde_json::from_str(r#"{ "a" : { "x":"s", "y":[1,2] }, "b":1 }"#).expect("json");
        assert_eq!(canonical_json(&a), r#"{"a":{"x":"s","y":[1,2]},"b":1}"#);
        assert_eq!(digest_value(&a), digest_value(&b));
    }
}
