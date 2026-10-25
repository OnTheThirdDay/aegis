#![no_main]
//! Untrusted configuration text: parsing never panics, and anything that
//! parses has a stable digest across a JSON round trip.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(cfg) = aegis_config::parse_toml(text) {
        let json = aegis_config::to_json(&cfg);
        let again = aegis_config::parse_json(&json).expect("typed JSON re-parses");
        assert_eq!(aegis_config::config_digest(&cfg), aegis_config::config_digest(&again));
    }
});
