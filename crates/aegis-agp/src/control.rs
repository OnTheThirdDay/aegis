//! Strict deterministic control-message encodings (OQ-02 decision for this
//! build: hand-written fixed binary layouts, no general-purpose codec).
//!
//! Every decoder consumes the whole payload and rejects trailing bytes,
//! out-of-range values and non-canonical encodings so that each message has
//! exactly one valid byte representation.

use crate::frame::{MAX_PAYLOAD, MAX_WINDOW, MIN_ADVERTISED_PAYLOAD, VERSION_MAJOR};
use crate::ProtocolError;
use aegis_contracts::destination::{canonical_ip, normalize_domain};
use aegis_contracts::reason::{OpenFailure, ResetReason};
use aegis_contracts::{Destination, Host};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const MAX_HELLO_LEN: usize = 8 * 1024;
pub const MAX_NODE_ID_LEN: usize = 64;
pub const MAX_FEATURES: usize = 64;
/// Feature IDs with this bit set are critical: an endpoint that does not
/// understand one MUST reject the session.
pub const CRITICAL_FEATURE_BIT: u16 = 0x8000;

/// Features understood by this build. None are defined for AGP/1.0 yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feature(pub u16);

impl Feature {
    pub fn is_critical(self) -> bool {
        self.0 & CRITICAL_FEATURE_BIT != 0
    }
}

fn need(buf: &impl Buf, n: usize, what: &'static str) -> Result<(), ProtocolError> {
    if buf.remaining() < n {
        Err(ProtocolError::Malformed(what))
    } else {
        Ok(())
    }
}

fn finish(buf: &impl Buf) -> Result<(), ProtocolError> {
    if buf.has_remaining() {
        Err(ProtocolError::Malformed("trailing bytes"))
    } else {
        Ok(())
    }
}

pub(crate) fn valid_node_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_NODE_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// HELLO / HELLO_ACK body. In HELLO_ACK `protocol_min == protocol_max` is the
/// selected version and `features` is the selected subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub protocol_min: u8,
    pub protocol_max: u8,
    pub node_id: String,
    pub max_streams: u32,
    pub initial_stream_window: u32,
    pub initial_session_window: u32,
    pub max_frame_payload: u32,
    pub features: Vec<u16>,
}

impl Hello {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        self.check()?;
        let mut b = BytesMut::with_capacity(32 + self.node_id.len() + self.features.len() * 2);
        b.put_u8(self.protocol_min);
        b.put_u8(self.protocol_max);
        b.put_u8(self.node_id.len() as u8);
        b.put_slice(self.node_id.as_bytes());
        b.put_u32(self.max_streams);
        b.put_u32(self.initial_stream_window);
        b.put_u32(self.initial_session_window);
        b.put_u32(self.max_frame_payload);
        b.put_u16(self.features.len() as u16);
        for f in &self.features {
            b.put_u16(*f);
        }
        Ok(b.freeze())
    }

    fn check(&self) -> Result<(), ProtocolError> {
        if self.protocol_min == 0 || self.protocol_min > self.protocol_max {
            return Err(ProtocolError::Malformed("protocol range"));
        }
        if !valid_node_id(&self.node_id) {
            return Err(ProtocolError::Malformed("node_id"));
        }
        if self.initial_stream_window > MAX_WINDOW || self.initial_session_window > MAX_WINDOW {
            return Err(ProtocolError::Malformed("window range"));
        }
        if !(MIN_ADVERTISED_PAYLOAD..=MAX_PAYLOAD).contains(&self.max_frame_payload) {
            return Err(ProtocolError::Malformed("max_frame_payload range"));
        }
        if self.features.len() > MAX_FEATURES {
            return Err(ProtocolError::Malformed("too many features"));
        }
        if self.features.windows(2).any(|w| w[0] >= w[1]) {
            return Err(ProtocolError::Malformed(
                "features must be strictly ascending",
            ));
        }
        Ok(())
    }

    pub fn decode(mut payload: Bytes) -> Result<Hello, ProtocolError> {
        if payload.len() > MAX_HELLO_LEN {
            return Err(ProtocolError::Malformed("hello too large"));
        }
        let b = &mut payload;
        need(b, 3, "hello header")?;
        let protocol_min = b.get_u8();
        let protocol_max = b.get_u8();
        let id_len = b.get_u8() as usize;
        need(b, id_len, "node_id")?;
        let id_bytes = b.copy_to_bytes(id_len);
        let node_id = std::str::from_utf8(&id_bytes)
            .map_err(|_| ProtocolError::Malformed("node_id utf8"))?
            .to_owned();
        need(b, 18, "hello body")?;
        let max_streams = b.get_u32();
        let initial_stream_window = b.get_u32();
        let initial_session_window = b.get_u32();
        let max_frame_payload = b.get_u32();
        let count = b.get_u16() as usize;
        if count > MAX_FEATURES {
            return Err(ProtocolError::Malformed("too many features"));
        }
        need(b, count * 2, "features")?;
        let features: Vec<u16> = (0..count).map(|_| b.get_u16()).collect();
        finish(b)?;
        let hello = Hello {
            protocol_min,
            protocol_max,
            node_id,
            max_streams,
            initial_stream_window,
            initial_session_window,
            max_frame_payload,
            features,
        };
        hello.check()?;
        Ok(hello)
    }

    /// Select the version and features for a HELLO_ACK. Unknown critical
    /// features cause rejection; unknown optional features are ignored.
    pub fn negotiate(&self, supported: &[u16]) -> Result<(u8, Vec<u16>), ProtocolError> {
        self.check()?;
        if self.protocol_min > VERSION_MAJOR || self.protocol_max < VERSION_MAJOR {
            return Err(ProtocolError::UnsupportedVersion(self.protocol_max));
        }
        let mut selected = Vec::new();
        for f in &self.features {
            if supported.contains(f) {
                selected.push(*f);
            } else if Feature(*f).is_critical() {
                return Err(ProtocolError::UnknownCriticalFeature(*f));
            }
        }
        Ok((VERSION_MAJOR, selected))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Tcp = 1,
}

/// OPEN body: requested network, bounded destination and requested timeout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRequest {
    pub network: Network,
    pub destination: Destination,
    pub timeout_ms: u32,
}

const ATYP_V4: u8 = 1;
const ATYP_V6: u8 = 2;
const ATYP_DOMAIN: u8 = 3;
pub const MAX_OPEN_TIMEOUT_MS: u32 = 120_000;

impl OpenRequest {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        if self.timeout_ms == 0 || self.timeout_ms > MAX_OPEN_TIMEOUT_MS {
            return Err(ProtocolError::Malformed("open timeout range"));
        }
        let mut b = BytesMut::with_capacity(270);
        b.put_u8(self.network as u8);
        match &self.destination.host {
            Host::Ip(IpAddr::V4(v4)) => {
                b.put_u8(ATYP_V4);
                b.put_slice(&v4.octets());
            }
            Host::Ip(IpAddr::V6(v6)) => {
                if canonical_ip(IpAddr::V6(*v6)) != IpAddr::V6(*v6) {
                    return Err(ProtocolError::Malformed("non-canonical mapped address"));
                }
                b.put_u8(ATYP_V6);
                b.put_slice(&v6.octets());
            }
            Host::Domain(d) => {
                if d.is_empty() || d.len() > 253 {
                    return Err(ProtocolError::Malformed("domain length"));
                }
                if normalize_domain(d).as_ref() != Ok(d) {
                    return Err(ProtocolError::Malformed("non-canonical domain"));
                }
                b.put_u8(ATYP_DOMAIN);
                b.put_u8(d.len() as u8);
                b.put_slice(d.as_bytes());
            }
        }
        if self.destination.port == 0 {
            return Err(ProtocolError::Malformed("port"));
        }
        b.put_u16(self.destination.port);
        b.put_u32(self.timeout_ms);
        Ok(b.freeze())
    }

    pub fn decode(mut payload: Bytes) -> Result<OpenRequest, ProtocolError> {
        let b = &mut payload;
        need(b, 2, "open header")?;
        let network = match b.get_u8() {
            1 => Network::Tcp,
            _ => return Err(ProtocolError::Malformed("unsupported network")),
        };
        let host = match b.get_u8() {
            ATYP_V4 => {
                need(b, 4, "ipv4")?;
                let mut o = [0u8; 4];
                b.copy_to_slice(&mut o);
                Host::Ip(IpAddr::V4(Ipv4Addr::from(o)))
            }
            ATYP_V6 => {
                need(b, 16, "ipv6")?;
                let mut o = [0u8; 16];
                b.copy_to_slice(&mut o);
                let ip = IpAddr::V6(Ipv6Addr::from(o));
                if canonical_ip(ip) != ip {
                    // Mapped IPv4 must be sent as ATYP_V4 (canonical form).
                    return Err(ProtocolError::Malformed("non-canonical mapped address"));
                }
                Host::Ip(ip)
            }
            ATYP_DOMAIN => {
                need(b, 1, "domain length")?;
                let len = b.get_u8() as usize;
                if len == 0 {
                    return Err(ProtocolError::Malformed("empty domain"));
                }
                need(b, len, "domain")?;
                let raw = b.copy_to_bytes(len);
                let s = std::str::from_utf8(&raw)
                    .map_err(|_| ProtocolError::Malformed("domain utf8"))?;
                let normalized =
                    normalize_domain(s).map_err(|_| ProtocolError::Malformed("domain"))?;
                if normalized != s {
                    return Err(ProtocolError::Malformed("non-canonical domain"));
                }
                Host::Domain(normalized)
            }
            _ => return Err(ProtocolError::Malformed("address type")),
        };
        need(b, 6, "port/timeout")?;
        let port = b.get_u16();
        let timeout_ms = b.get_u32();
        finish(b)?;
        if port == 0 {
            return Err(ProtocolError::Malformed("port"));
        }
        if timeout_ms == 0 || timeout_ms > MAX_OPEN_TIMEOUT_MS {
            return Err(ProtocolError::Malformed("open timeout range"));
        }
        Ok(OpenRequest {
            network,
            destination: Destination { host, port },
            timeout_ms,
        })
    }
}

/// OPEN_ACK status: success only once the destination TCP connection exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenAck {
    Success,
    Failure(OpenFailure),
}

impl OpenAck {
    pub fn encode(self) -> Bytes {
        let code = match self {
            OpenAck::Success => 0,
            OpenAck::Failure(f) => f.code(),
        };
        Bytes::copy_from_slice(&[code])
    }

    pub fn decode(payload: &[u8]) -> Result<OpenAck, ProtocolError> {
        match payload {
            [0] => Ok(OpenAck::Success),
            [c] => OpenFailure::from_code(*c)
                .map(OpenAck::Failure)
                .ok_or(ProtocolError::Malformed("open_ack code")),
            _ => Err(ProtocolError::Malformed("open_ack length")),
        }
    }
}

pub fn encode_reset(reason: ResetReason) -> Bytes {
    Bytes::copy_from_slice(&[reason.code()])
}

pub fn decode_reset(payload: &[u8]) -> Result<ResetReason, ProtocolError> {
    match payload {
        [c] => ResetReason::from_code(*c).ok_or(ProtocolError::Malformed("reset reason")),
        _ => Err(ProtocolError::Malformed("reset length")),
    }
}

/// WINDOW_UPDATE: exactly one 4-byte increment in `1..=2^31-1`.
pub fn encode_window_update(increment: u32) -> Result<Bytes, ProtocolError> {
    if increment == 0 || increment > MAX_WINDOW {
        return Err(ProtocolError::Malformed("window increment"));
    }
    Ok(Bytes::copy_from_slice(&increment.to_be_bytes()))
}

pub fn decode_window_update(payload: &[u8]) -> Result<u32, ProtocolError> {
    let raw: [u8; 4] = payload
        .try_into()
        .map_err(|_| ProtocolError::Malformed("window_update length"))?;
    let inc = u32::from_be_bytes(raw);
    if inc == 0 || inc > MAX_WINDOW {
        return Err(ProtocolError::Malformed("window increment"));
    }
    Ok(inc)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoAway {
    pub last_stream_id: u32,
    pub reason: ResetReason,
}

impl GoAway {
    pub fn encode(self) -> Bytes {
        let mut b = BytesMut::with_capacity(5);
        b.put_u32(self.last_stream_id);
        b.put_u8(self.reason.code());
        b.freeze()
    }

    pub fn decode(mut payload: Bytes) -> Result<GoAway, ProtocolError> {
        need(&payload, 5, "goaway")?;
        let last_stream_id = payload.get_u32();
        let reason = ResetReason::from_code(payload.get_u8())
            .ok_or(ProtocolError::Malformed("goaway reason"))?;
        finish(&payload)?;
        Ok(GoAway {
            last_stream_id,
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hello() -> Hello {
        Hello {
            protocol_min: 1,
            protocol_max: 1,
            node_id: "pi-gateway-01".into(),
            max_streams: 64,
            initial_stream_window: 65_536,
            initial_session_window: 1 << 21,
            max_frame_payload: 16_384,
            features: vec![1, 7, 0x8001],
        }
    }

    #[test]
    fn hello_roundtrip_and_strictness() {
        let h = hello();
        let enc = h.encode().expect("encode");
        assert_eq!(Hello::decode(enc.clone()).expect("decode"), h);
        let mut trailing = BytesMut::from(&enc[..]);
        trailing.put_u8(0);
        assert!(Hello::decode(trailing.freeze()).is_err());
        let mut bad = h.clone();
        bad.features = vec![7, 1];
        assert!(bad.encode().is_err(), "non-canonical feature order");
        let mut bad = h.clone();
        bad.max_frame_payload = 4096;
        assert!(bad.encode().is_err());
        let mut bad = h.clone();
        bad.node_id = "has space".into();
        assert!(bad.encode().is_err());
        let mut bad = h;
        bad.initial_session_window = MAX_WINDOW + 1;
        assert!(bad.encode().is_err());
    }

    #[test]
    fn negotiation() {
        let h = hello();
        assert_eq!(h.negotiate(&[1, 0x8001]).expect("ok"), (1, vec![1, 0x8001]));
        assert_eq!(
            h.negotiate(&[1]),
            Err(ProtocolError::UnknownCriticalFeature(0x8001))
        );
        let mut v2 = hello();
        v2.protocol_min = 2;
        v2.protocol_max = 3;
        assert!(
            v2.negotiate(&[]).is_err(),
            "downgrade/upgrade mismatch rejected"
        );
    }

    #[test]
    fn open_roundtrip_and_rejections() {
        for authority in ["93.184.216.34:443", "[2001:db8::1]:22", "example.com:80"] {
            let req = OpenRequest {
                network: Network::Tcp,
                destination: Destination::parse_authority(authority).expect("dest"),
                timeout_ms: 10_000,
            };
            let enc = req.encode().expect("encode");
            assert_eq!(OpenRequest::decode(enc).expect("decode"), req);
        }
        // Uppercase domain is non-canonical.
        let raw = [1u8, 3, 3, b'A', b'.', b'b', 0, 80, 0, 0, 0, 10];
        assert!(OpenRequest::decode(Bytes::copy_from_slice(&raw)).is_err());
        // Mapped IPv4 in v6 form is non-canonical.
        let mut raw = vec![1u8, 2];
        raw.extend_from_slice(&"::ffff:10.0.0.1".parse::<Ipv6Addr>().expect("v6").octets());
        raw.extend_from_slice(&[0, 80, 0, 0, 0, 10]);
        assert!(OpenRequest::decode(Bytes::from(raw)).is_err());
        // UDP network not supported.
        assert!(
            OpenRequest::decode(Bytes::from_static(&[2, 1, 1, 2, 3, 4, 0, 80, 0, 0, 0, 10]))
                .is_err()
        );
        // Timeout zero.
        assert!(
            OpenRequest::decode(Bytes::from_static(&[1, 1, 1, 2, 3, 4, 0, 80, 0, 0, 0, 0]))
                .is_err()
        );
    }

    #[test]
    fn window_update_bounds() {
        assert!(encode_window_update(0).is_err());
        assert!(encode_window_update(MAX_WINDOW + 1).is_err());
        assert_eq!(decode_window_update(&[0, 0, 0, 1]), Ok(1));
        assert!(decode_window_update(&[0, 0, 0, 0]).is_err());
        assert!(decode_window_update(&[0x80, 0, 0, 0]).is_err());
        assert!(decode_window_update(&[0, 0, 1]).is_err());
    }

    #[test]
    fn small_messages() {
        assert_eq!(
            OpenAck::decode(&OpenAck::Success.encode()),
            Ok(OpenAck::Success)
        );
        assert!(OpenAck::decode(&[200]).is_err());
        assert_eq!(
            decode_reset(&encode_reset(ResetReason::Timeout)),
            Ok(ResetReason::Timeout)
        );
        assert!(decode_reset(&[0]).is_err());
        let g = GoAway {
            last_stream_id: 41,
            reason: ResetReason::Shutdown,
        };
        assert_eq!(GoAway::decode(g.encode()), Ok(g));
    }

    proptest! {
        #[test]
        fn decoders_never_panic(data in proptest::collection::vec(any::<u8>(), 0..600)) {
            let b = Bytes::from(data);
            let _ = Hello::decode(b.clone());
            let _ = OpenRequest::decode(b.clone());
            let _ = GoAway::decode(b.clone());
            let _ = OpenAck::decode(&b);
            let _ = decode_window_update(&b);
            let _ = decode_reset(&b);
        }
    }
}
