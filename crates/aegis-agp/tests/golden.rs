use aegis_agp::{encode_frame, Decoder};
use bytes::BytesMut;

#[test]
fn independent_agp10_golden_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/protocol/agp-1.0-vectors.json"))
            .expect("fixtures");
    for v in vectors.as_array().expect("vectors") {
        let input = hex::decode(v["hex"].as_str().expect("hex")).expect("decode hex");
        let mut source = BytesMut::from(input.as_slice());
        let mut decoder = Decoder::new(65536);
        let result = decoder.decode(&mut source);
        if v["valid"] == true {
            let frame = result.expect("valid header").expect("complete frame");
            assert!(source.is_empty());
            let mut encoded = BytesMut::new();
            encode_frame(&mut encoded, &frame).expect("canonical control");
            assert_eq!(encoded.as_ref(), input.as_slice(), "{}", v["name"]);
        } else if let Ok(Some(frame)) = result {
            let mut encoded = BytesMut::new();
            assert!(
                encode_frame(&mut encoded, &frame).is_err(),
                "{} must fail semantic validation",
                v["name"]
            );
            assert!(
                encoded.is_empty(),
                "invalid encoders have no partial output"
            );
        } else {
            assert!(result.is_err(), "negative fixture cannot be incomplete");
        }
    }
}

#[test]
fn encoder_rejects_noncanonical_host_and_mapped_ipv4() {
    use aegis_agp::{Network, OpenRequest};
    use aegis_contracts::{Destination, Host};
    for host in [
        Host::Domain("EXAMPLE.com".into()),
        Host::Ip("::ffff:192.0.2.1".parse().expect("mapped")),
    ] {
        assert!(OpenRequest {
            network: Network::Tcp,
            destination: Destination { host, port: 443 },
            timeout_ms: 10000
        }
        .encode()
        .is_err());
    }
}
