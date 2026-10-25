# AGP/1.0 wire contract

Authoritative implementation contract for the existing codec. All integers are
unsigned, big endian. Outer WS messages carry ordered TLS bytes; inner TLS 1.3
mTLS completes before these frames. WS fragmentation has no AGP meaning.

| Header field | Offset | Bytes | Value |
|---|---:|---:|---|
| magic | 0 | 4 | ASCII AGN1 |
| major | 4 | 1 | 1; other values fail closed |
| type | 5 | 1 | table below |
| flags | 6 | 2 | RESET ACK=1; all other bits/types zero |
| stream | 8 | 4 | session=0; logical streams nonzero |
| length | 12 | 4 | payload bytes, <=65536 and negotiated cap |

Validate the complete header before allocating/reading the body. Total frame
size <=65552. HELLO bodies <=8192. Fixed controls must have the exact length.
No control permits trailing bytes. No padding, alternative integer widths,
compressed fields or implicit extensions exist.

| Type | ID | Stream | Body |
|---|---:|---|---|
| HELLO | 1 | 0 | min:u8, max:u8, id_len:u8, id:ASCII[id_len], streams:u32, stream_window:u32, session_window:u32, frame_cap:u32, feature_count:u16, features:u16[count] |
| HELLO_ACK | 2 | 0 | same layout, min=max=selected major, selected features only |
| OPEN | 3 | nonzero | network:u8=1(TCP), address type:u8, address, port:u16, timeout_ms:u32 |
| OPEN_ACK | 4 | nonzero | status:u8 (0 success; 1..10 failure) |
| DATA | 5 | nonzero | 1..negotiated-cap raw bytes |
| HALF_CLOSE | 6 | nonzero | empty; ordered close of sender's DATA direction |
| RESET | 7 | nonzero | reason:u8 (1..8); flags 0=request, 1=ACK |
| PING/PONG | 8/9 | 0 | exactly eight opaque bytes echoed unchanged |
| GOAWAY | 10 | 0 | last_stream:u32, reason:u8 (1..8) |
| WINDOW_UPDATE | 11 | any | increment:u32, 1..2147483647 |
| DATAGRAM | 12 | — | reserved, always rejected; UDP unavailable |

Node ID is 1..64 ASCII `[A-Za-z0-9._-]`, exactly the authenticated certificate
identity. Windows are 0..2147483647. Frame cap is 8192..65536. Features are <=64
strictly ascending unique u16s. Bit 0x8000 marks a critical feature: unknown
critical features reject negotiation; unknown optional offers are ignored.
No features are defined in 1.0. ACK cannot invent a feature or a version; new
versions cannot reinterpret this layout. No OPEN/DATA before HELLO/ACK.

OPEN addresses: type 1=four IPv4 octets, 2=sixteen IPv6 octets, 3=len:u8 plus
1..253 UTF-8 bytes of canonical lower-case ASCII DNS/IDNA A-label. Mapped IPv4
must use type 1. Domains reject uppercase, trailing dots, invalid labels and
Unicode/noncanonical alternatives (normalize before encoding). Port 1..65535;
timeout 1..120000 ms. Unsupported networks fail. Every resolved egress address
is checked independently; the dialer uses the checked IP without re-resolution.

OPEN_ACK failures: 1 denied, 2 unauthorized, 3 DNS, 4 refused, 5 unreachable,
6 timeout, 7 quota, 8 unavailable, 9 unsupported, 10 internal. Success is sent
only after the destination connects. RESET reasons: 1 cancelled, 2 destination
reset, 3 timeout, 4 policy revoked, 5 resource limit, 6 protocol, 7 shutdown,
8 internal. Errors never include target names or raw provider/TLS failures.

Client streams start at 1 and increase by exactly 2, including rejected OPENs;
even reverse streams are reserved. IDs never repeat. Exhaustion requires a new
session. States: Opening -> Established -> either half closed -> Closed; RESET
is terminal. DATA before ACK/after peer FIN or reset boundary is a protocol
error. GOAWAY stops new OPENs and drains existing streams to a bounded deadline.

DATA debits both directional stream/session credit, backed by reserved storage.
WINDOW_UPDATE uses checked arithmetic, cannot overflow 2^31-1, and never revives
closed streams. Unknown IDs reject; late updates for previously closed IDs are
ignored. Slow readers cannot stop the shared control parser. RESET stops unsent
DATA; in-flight DATA is charged/discarded until the ordered peer RESET/ACK.
ACKs are never ACKed. Closing records and drain deadlines remain bounded.
The normative accounting and simultaneous-reset rules remain SPEC-03 section 3.

Every new OPEN rechecks current device authorization, expiry, revocation and
policy, including on reused sessions. Existing TCP streams fail on transport
loss; reconnect creates fresh mTLS/AGP sessions and never replays unknown OPENs
or application bytes. Inner resumption/tickets/0-RTT are disabled.

Machine-readable positive and negative fixtures are in agp-1.0-vectors.json.
`aegis-agp/tests/golden.rs` validates both directions. Fuzz targets agp_decoder
and agp_control exercise all controls; corpus and resource budgets accompany
the test evidence. The handwritten, runtime-free trusted surface is frame.rs
and control.rs. Consider a schema generator only after an interoperable major
extension justifies its parser/dependency cost; never replace AGP/1 in place.
