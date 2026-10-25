#![no_main]
//! Control-message decoders: strict, canonical, no panic. Anything that
//! decodes must re-encode to the identical bytes (one valid encoding).

use aegis_agp::{decode_reset, decode_window_update, GoAway, Hello, OpenAck, OpenRequest};
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let b = Bytes::copy_from_slice(data);
    if let Ok(h) = Hello::decode(b.clone()) {
        assert_eq!(h.encode().expect("re-encode"), b);
    }
    if let Ok(o) = OpenRequest::decode(b.clone()) {
        assert_eq!(o.encode().expect("re-encode"), b);
    }
    if let Ok(g) = GoAway::decode(b.clone()) {
        assert_eq!(g.encode(), b);
    }
    if let Ok(a) = OpenAck::decode(data) {
        assert_eq!(&a.encode()[..], data);
    }
    let _ = decode_window_update(data);
    let _ = decode_reset(data);
});
