//! Opaque, HMAC-bound pagination cursors. The listing kind, actor and
//! position are bound into the cursor, so cursors cannot be replayed across
//! endpoints or actors; authorization is re-checked on every page.

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
struct Payload {
    k: String,
    a: String,
    p: serde_json::Value,
}

fn hmac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(msg)
        .finalize();
    Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into()
}

pub fn encode(key: &[u8; 32], kind: &str, actor: &str, position: serde_json::Value) -> String {
    let payload = serde_json::to_vec(&Payload {
        k: kind.into(),
        a: actor.into(),
        p: position,
    })
    .unwrap_or_default();
    let mac = hmac(key, &payload);
    let mut out = payload;
    out.extend_from_slice(&mac);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)
}

/// Decode and verify; `None` for tampered, foreign or malformed cursors.
pub fn decode(key: &[u8; 32], kind: &str, actor: &str, cursor: &str) -> Option<serde_json::Value> {
    if cursor.is_empty() || cursor.len() > 1024 {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .ok()?;
    if raw.len() < 33 {
        return None;
    }
    let (payload, mac) = raw.split_at(raw.len() - 32);
    let expected = hmac(key, payload);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&expected[..], mac)) {
        return None;
    }
    let p: Payload = serde_json::from_slice(payload).ok()?;
    (p.k == kind && p.a == actor).then_some(p.p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_are_bound() {
        let key = [7u8; 32];
        let c = encode(&key, "profiles", "alice", serde_json::json!([1, "x"]));
        assert_eq!(
            decode(&key, "profiles", "alice", &c),
            Some(serde_json::json!([1, "x"]))
        );
        assert_eq!(decode(&key, "profiles", "bob", &c), None, "cross-actor");
        assert_eq!(decode(&key, "audit", "alice", &c), None, "cross-endpoint");
        assert_eq!(
            decode(&[8u8; 32], "profiles", "alice", &c),
            None,
            "other key"
        );
        let mut t = c.clone();
        t.replace_range(0..1, if t.starts_with('A') { "B" } else { "A" });
        assert_eq!(decode(&key, "profiles", "alice", &t), None, "tampered");
    }
}
