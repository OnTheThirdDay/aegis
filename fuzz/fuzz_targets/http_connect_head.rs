#![no_main]
//! HTTP CONNECT request heads, with and without required credentials.

use aegis_inbound_http::{parse_head, Credentials};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_head(data, None);
    let creds = Credentials {
        username: "u".into(),
        password: "p".into(),
    };
    if let Ok(dest) = parse_head(data, Some(&creds)) {
        assert!(dest.port != 0);
    }
});
