//! TC-P01 / TC-U03: generated frame round trips and arbitrary-input decoding.

use aegis_agp::{encode_frame, Decoder, Frame, FrameType, MAX_PAYLOAD};
use bytes::{Bytes, BytesMut};
use proptest::prelude::*;

fn legal_frame() -> impl Strategy<Value = Frame> {
    prop_oneof![
        (
            1u32..u32::MAX,
            proptest::collection::vec(any::<u8>(), 1..2048)
        )
            .prop_map(|(sid, p)| Frame::new(FrameType::Data, sid, Bytes::from(p))),
        (1u32..u32::MAX, 1u32..(1 << 31)).prop_map(|(sid, inc)| Frame::new(
            FrameType::WindowUpdate,
            sid,
            aegis_agp::encode_window_update(inc).expect("valid increment")
        )),
        any::<[u8; 8]>().prop_map(|p| Frame::new(FrameType::Ping, 0, Bytes::copy_from_slice(&p))),
        (1u32..u32::MAX).prop_map(|sid| Frame::new(FrameType::HalfClose, sid, Bytes::new())),
        (1u32..u32::MAX, any::<bool>()).prop_map(|(sid, ack)| {
            let f = Frame::new(
                FrameType::Reset,
                sid,
                aegis_agp::encode_reset(aegis_contracts::ResetReason::Cancelled),
            );
            if ack {
                f.with_flags(aegis_agp::FLAG_RESET_ACK)
            } else {
                f
            }
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2_000, .. ProptestConfig::default() })]

    /// Streams of frames round-trip regardless of how the bytes are chunked.
    #[test]
    fn frame_streams_roundtrip(frames in proptest::collection::vec(legal_frame(), 1..50), chunk in 1usize..4096) {
        let mut wire = BytesMut::new();
        for f in &frames {
            encode_frame(&mut wire, f).expect("encode");
        }
        let mut decoder = Decoder::new(MAX_PAYLOAD);
        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        for piece in wire.chunks(chunk) {
            buf.extend_from_slice(piece);
            while let Some(f) = decoder.decode(&mut buf).expect("legal stream decodes") {
                out.push(f);
            }
        }
        prop_assert_eq!(out, frames);
        prop_assert!(buf.is_empty());
    }

    /// Arbitrary bytes never panic, and the buffer the caller must hold stays
    /// bounded by one maximal frame.
    #[test]
    fn arbitrary_input_is_bounded(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let mut decoder = Decoder::new(16_384);
        let mut buf = BytesMut::from(&data[..]);
        loop {
            match decoder.decode(&mut buf) {
                Ok(Some(_)) => continue,
                Ok(None) => {
                    prop_assert!(decoder.bytes_needed(buf.len()) <= 16 + 16_384);
                    break;
                }
                Err(_) => break,
            }
        }
    }
}

/// TC-P01: every legal DATA size from 1 to 65,536 at stride boundaries.
#[test]
fn tc_p01_payload_size_boundaries() {
    for len in [1usize, 2, 255, 256, 8191, 8192, 16_384, 65_535, 65_536] {
        let f = Frame::new(FrameType::Data, 1, Bytes::from(vec![0xAB; len]));
        let mut wire = BytesMut::new();
        encode_frame(&mut wire, &f).expect("encode");
        let mut d = Decoder::new(MAX_PAYLOAD);
        assert_eq!(d.decode(&mut wire).expect("decode"), Some(f));
    }
    let too_big = Frame::new(FrameType::Data, 1, Bytes::from(vec![0; 65_537]));
    assert!(encode_frame(&mut BytesMut::new(), &too_big).is_err());
}
