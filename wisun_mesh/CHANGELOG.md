# Changelog

## v0.0.5
- lowpan: 6LoWPAN IPHC decode (contexts, multicast, NHC extension headers kept raw).
- Verified on all 27 reference frames: DIO/DAO/DAO-ACK, ping request/reply.

## v0.0.4
- mac154: IEEE 802.15.4 frame decode/encode (2006, no security), {error, malformed} on bad input.
- Verified on all 27 frames in the reference capture.

## v0.0.3
- slip_link: gen_server TCP link to slip-radio (?M on connect, reconnect, owner messages).
- sim/br_cooja.csc: Cooja sim without the C border router.
- Verified against live Cooja: MAC 00:01:00:01:00:01:00:01, RPL DIS frames from node 2.

## v0.0.2
- slip_codec: SLIP framing (encode/decode, split-safe).
- slip_cmd: slip-radio commands (!S, !R, ?M/!M, ?V/!V) decode/encode.
- Tests against the reference capture (br_cooja_ref.pcap): 10 tests.

## v0.0.1
- Initial rebar3 skeleton and reference capture.
