# Changelog

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
