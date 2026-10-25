//! 16-byte fixed header framing.

use crate::ProtocolError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const MAGIC: [u8; 4] = *b"AGN1";
pub const VERSION_MAJOR: u8 = 1;
pub const HEADER_LEN: usize = 16;
/// Absolute payload ceiling for AGP/1.
pub const MAX_PAYLOAD: u32 = 65_536;
/// Smallest frame cap an endpoint may advertise; a bounded HELLO always fits.
pub const MIN_ADVERTISED_PAYLOAD: u32 = 8_192;
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_PAYLOAD as usize;
/// Windows are directional unsigned integers in `0..2^31-1`.
pub const MAX_WINDOW: u32 = (1 << 31) - 1;
/// The only v1 flag: RESET acknowledgement.
pub const FLAG_RESET_ACK: u16 = 0x0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    Hello = 1,
    HelloAck = 2,
    Open = 3,
    OpenAck = 4,
    Data = 5,
    HalfClose = 6,
    Reset = 7,
    Ping = 8,
    Pong = 9,
    GoAway = 10,
    WindowUpdate = 11,
    Datagram = 12,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => FrameType::Hello,
            2 => FrameType::HelloAck,
            3 => FrameType::Open,
            4 => FrameType::OpenAck,
            5 => FrameType::Data,
            6 => FrameType::HalfClose,
            7 => FrameType::Reset,
            8 => FrameType::Ping,
            9 => FrameType::Pong,
            10 => FrameType::GoAway,
            11 => FrameType::WindowUpdate,
            12 => FrameType::Datagram,
            _ => return None,
        })
    }

    /// Frames that must use the session-control stream id 0.
    fn requires_stream_zero(self) -> bool {
        matches!(
            self,
            FrameType::Hello
                | FrameType::HelloAck
                | FrameType::Ping
                | FrameType::Pong
                | FrameType::GoAway
        )
    }

    /// Frames that must target a logical stream.
    fn requires_stream_nonzero(self) -> bool {
        matches!(
            self,
            FrameType::Open
                | FrameType::OpenAck
                | FrameType::Data
                | FrameType::HalfClose
                | FrameType::Reset
        )
    }

    /// Exact payload length for fixed-size control frames.
    fn fixed_len(self) -> Option<u32> {
        match self {
            FrameType::OpenAck => Some(1),
            FrameType::HalfClose => Some(0),
            FrameType::Reset => Some(1),
            FrameType::Ping | FrameType::Pong => Some(8),
            FrameType::GoAway => Some(5),
            FrameType::WindowUpdate => Some(4),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub frame_type: FrameType,
    pub flags: u16,
    pub stream_id: u32,
    pub length: u32,
}

impl Header {
    /// Parse and fully validate a header against `cap` without touching any
    /// payload bytes.
    pub fn parse(raw: &[u8; HEADER_LEN], cap: u32) -> Result<Header, ProtocolError> {
        if raw[0..4] != MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        if raw[4] != VERSION_MAJOR {
            return Err(ProtocolError::UnsupportedVersion(raw[4]));
        }
        let frame_type =
            FrameType::from_u8(raw[5]).ok_or(ProtocolError::UnknownFrameType(raw[5]))?;
        if frame_type == FrameType::Datagram {
            return Err(ProtocolError::UnsupportedFrameType(frame_type));
        }
        let flags = u16::from_be_bytes([raw[6], raw[7]]);
        let allowed_flags = if frame_type == FrameType::Reset {
            FLAG_RESET_ACK
        } else {
            0
        };
        if flags & !allowed_flags != 0 {
            return Err(ProtocolError::ReservedFlags { frame_type, flags });
        }
        let stream_id = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let length = u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]);
        if length > cap.min(MAX_PAYLOAD) {
            return Err(ProtocolError::PayloadTooLarge {
                length,
                cap: cap.min(MAX_PAYLOAD),
            });
        }
        if frame_type.requires_stream_zero() && stream_id != 0 {
            return Err(ProtocolError::BadStreamId {
                frame_type,
                stream_id,
            });
        }
        if frame_type.requires_stream_nonzero() && stream_id == 0 {
            return Err(ProtocolError::BadStreamId {
                frame_type,
                stream_id,
            });
        }
        if let Some(fixed) = frame_type.fixed_len() {
            if length != fixed {
                return Err(ProtocolError::BadLength { frame_type, length });
            }
        }
        if frame_type == FrameType::Data && length == 0 {
            // Zero-length DATA carries nothing and only enables spin attacks.
            return Err(ProtocolError::BadLength { frame_type, length });
        }
        if matches!(frame_type, FrameType::Hello | FrameType::HelloAck)
            && length > crate::control::MAX_HELLO_LEN as u32
        {
            return Err(ProtocolError::BadLength { frame_type, length });
        }
        Ok(Header {
            frame_type,
            flags,
            stream_id,
            length,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: u16,
    pub stream_id: u32,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(frame_type: FrameType, stream_id: u32, payload: Bytes) -> Self {
        Frame {
            frame_type,
            flags: 0,
            stream_id,
            payload,
        }
    }

    pub fn with_flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.payload.len()
    }
}

pub fn encode_header(
    dst: &mut BytesMut,
    frame_type: FrameType,
    flags: u16,
    stream_id: u32,
    len: u32,
) {
    dst.reserve(HEADER_LEN);
    dst.put_slice(&MAGIC);
    dst.put_u8(VERSION_MAJOR);
    dst.put_u8(frame_type as u8);
    dst.put_u16(flags);
    dst.put_u32(stream_id);
    dst.put_u32(len);
}

/// Encode a frame. Panics are impossible: oversize payloads are rejected.
pub fn encode_frame(dst: &mut BytesMut, frame: &Frame) -> Result<(), ProtocolError> {
    let len = u32::try_from(frame.payload.len()).map_err(|_| ProtocolError::PayloadTooLarge {
        length: u32::MAX,
        cap: MAX_PAYLOAD,
    })?;
    if len > MAX_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge {
            length: len,
            cap: MAX_PAYLOAD,
        });
    }
    let mut header = BytesMut::with_capacity(HEADER_LEN);
    encode_header(
        &mut header,
        frame.frame_type,
        frame.flags,
        frame.stream_id,
        len,
    );
    let raw: &[u8; HEADER_LEN] = header
        .as_ref()
        .try_into()
        .map_err(|_| ProtocolError::BadMagic)?;
    Header::parse(raw, MAX_PAYLOAD)?;
    // Encoders must not emit noncanonical controls that decoders reject.
    match frame.frame_type {
        FrameType::Hello | FrameType::HelloAck => {
            crate::control::Hello::decode(frame.payload.clone())?;
        }
        FrameType::Open => {
            crate::control::OpenRequest::decode(frame.payload.clone())?;
        }
        FrameType::OpenAck => {
            crate::control::OpenAck::decode(&frame.payload)?;
        }
        FrameType::Reset => {
            crate::control::decode_reset(&frame.payload)?;
        }
        FrameType::WindowUpdate => {
            crate::control::decode_window_update(&frame.payload)?;
        }
        FrameType::GoAway => {
            crate::control::GoAway::decode(frame.payload.clone())?;
        }
        _ => {}
    }
    dst.extend_from_slice(&header);
    dst.extend_from_slice(&frame.payload);
    Ok(())
}

/// Incremental decoder tolerant of arbitrary chunking.
#[derive(Debug)]
pub struct Decoder {
    cap: u32,
    pending: Option<Header>,
}

impl Decoder {
    pub fn new(cap: u32) -> Self {
        Decoder {
            cap: cap.min(MAX_PAYLOAD),
            pending: None,
        }
    }

    /// Lower (never raise) the payload cap after negotiation.
    pub fn set_cap(&mut self, cap: u32) {
        self.cap = cap.min(MAX_PAYLOAD);
    }

    pub fn cap(&self) -> u32 {
        self.cap
    }

    /// Bytes the caller must still buffer to complete the current frame.
    pub fn bytes_needed(&self, buffered: usize) -> usize {
        match self.pending {
            Some(h) => (h.length as usize).saturating_sub(buffered),
            None => HEADER_LEN.saturating_sub(buffered),
        }
    }

    /// Try to decode one frame from `buf`. Returns `Ok(None)` when more input
    /// is required. A buffer never needs to grow beyond `HEADER_LEN + cap`.
    pub fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Frame>, ProtocolError> {
        let header = match self.pending {
            Some(h) => h,
            None => {
                if buf.len() < HEADER_LEN {
                    return Ok(None);
                }
                let mut raw = [0u8; HEADER_LEN];
                raw.copy_from_slice(&buf[..HEADER_LEN]);
                let h = Header::parse(&raw, self.cap)?;
                buf.advance(HEADER_LEN);
                self.pending = Some(h);
                h
            }
        };
        let len = header.length as usize;
        if buf.len() < len {
            return Ok(None);
        }
        self.pending = None;
        let payload = buf.split_to(len).freeze();
        Ok(Some(Frame {
            frame_type: header.frame_type,
            flags: header.flags,
            stream_id: header.stream_id,
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_header(ty: u8, flags: u16, sid: u32, len: u32) -> BytesMut {
        let mut b = BytesMut::new();
        b.put_slice(&MAGIC);
        b.put_u8(1);
        b.put_u8(ty);
        b.put_u16(flags);
        b.put_u32(sid);
        b.put_u32(len);
        b
    }

    #[test]
    fn tc_p02_oversize_rejected_before_payload() {
        let mut d = Decoder::new(MAX_PAYLOAD);
        let mut b = raw_header(5, 0, 1, MAX_PAYLOAD + 1);
        assert!(matches!(
            d.decode(&mut b),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));
        let mut d = Decoder::new(16_384);
        let mut b = raw_header(5, 0, 1, 16_385);
        assert!(d.decode(&mut b).is_err(), "negotiated smaller cap enforced");
    }

    #[test]
    fn tc_p03_unknown_type_and_flags() {
        let mut d = Decoder::new(MAX_PAYLOAD);
        assert_eq!(
            d.decode(&mut raw_header(99, 0, 0, 0)),
            Err(ProtocolError::UnknownFrameType(99))
        );
        let mut d = Decoder::new(MAX_PAYLOAD);
        assert!(matches!(
            d.decode(&mut raw_header(5, 0x0001, 1, 1)),
            Err(ProtocolError::ReservedFlags { .. })
        ));
        let mut d = Decoder::new(MAX_PAYLOAD);
        assert!(matches!(
            d.decode(&mut raw_header(7, 0x0002, 1, 1)),
            Err(ProtocolError::ReservedFlags { .. })
        ));
        let mut d = Decoder::new(MAX_PAYLOAD);
        assert!(matches!(
            d.decode(&mut raw_header(12, 0, 1, 1)),
            Err(ProtocolError::UnsupportedFrameType(FrameType::Datagram))
        ));
        let mut bad = raw_header(5, 0, 1, 1);
        bad[0] = b'X';
        assert_eq!(
            Decoder::new(MAX_PAYLOAD).decode(&mut bad),
            Err(ProtocolError::BadMagic)
        );
        let mut v2 = raw_header(5, 0, 1, 1);
        v2[4] = 2;
        assert_eq!(
            Decoder::new(MAX_PAYLOAD).decode(&mut v2),
            Err(ProtocolError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn stream_id_and_fixed_length_rules() {
        let cases: &[(u8, u32, u32)] = &[
            (1, 1, 10),   // HELLO on stream 1
            (3, 0, 10),   // OPEN on stream 0
            (5, 0, 1),    // DATA on stream 0
            (11, 0, 3),   // WINDOW_UPDATE wrong length
            (8, 0, 7),    // PING wrong length
            (6, 1, 1),    // HALF_CLOSE with payload
            (5, 1, 0),    // zero-length DATA
            (1, 0, 9000), // oversized HELLO
        ];
        for &(ty, sid, len) in cases {
            let mut b = raw_header(ty, 0, sid, len);
            b.resize(HEADER_LEN + len as usize, 0);
            assert!(
                Decoder::new(MAX_PAYLOAD).decode(&mut b).is_err(),
                "type {ty} sid {sid} len {len} must be rejected"
            );
        }
    }

    #[test]
    fn split_header_and_payload() {
        let frame = Frame::new(FrameType::Data, 3, Bytes::from_static(b"hello world"));
        let mut enc = BytesMut::new();
        encode_frame(&mut enc, &frame).expect("encode");
        let mut d = Decoder::new(MAX_PAYLOAD);
        let mut buf = BytesMut::new();
        let mut out = None;
        for byte in enc.iter() {
            buf.put_u8(*byte);
            if let Some(f) = d.decode(&mut buf).expect("decode") {
                out = Some(f);
            }
        }
        assert_eq!(out, Some(frame));
        assert!(buf.is_empty());
    }
}
