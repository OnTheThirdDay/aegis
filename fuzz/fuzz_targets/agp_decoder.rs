#![no_main]
//! Untrusted AGP byte stream: arbitrary chunking, no panic, buffer bounded
//! by one maximal frame.

use aegis_agp::{Decoder, HEADER_LEN};
use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&cap_sel, rest)) = data.split_first() else { return };
    let cap = [8_192u32, 16_384, 65_536][usize::from(cap_sel) % 3];
    let mut decoder = Decoder::new(cap);
    let mut buf = BytesMut::new();
    // Feed in variable-size chunks derived from the input itself.
    let mut i = 0;
    while i < rest.len() {
        let step = 1 + usize::from(rest[i]) % 97;
        let end = (i + step).min(rest.len());
        buf.extend_from_slice(&rest[i..end]);
        i = end;
        loop {
            match decoder.decode(&mut buf) {
                Ok(Some(frame)) => assert!(frame.payload.len() <= cap as usize),
                Ok(None) => break,
                Err(_) => return,
            }
        }
        assert!(decoder.bytes_needed(buf.len()) <= HEADER_LEN + cap as usize);
    }
});
