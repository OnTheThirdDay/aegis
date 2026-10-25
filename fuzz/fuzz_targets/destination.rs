#![no_main]
//! Destination/authority parsing shared by SOCKS, HTTP CONNECT and AGP OPEN.

use aegis_contracts::Destination;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(d) = Destination::parse_authority(s) {
        // Display form re-parses to the same normalized destination.
        let again = Destination::parse_authority(&d.to_string()).expect("canonical form parses");
        assert_eq!(d, again);
    }
});
