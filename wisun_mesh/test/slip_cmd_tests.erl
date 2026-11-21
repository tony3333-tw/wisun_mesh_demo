-module(slip_cmd_tests).

-include_lib("eunit/include/eunit.hrl").

-define(REF, "test/captures/br_cooja_ref.pcap").

%% Examples taken from the reference capture
send_example_test() ->
    Bin = <<16#21, 16#53, 0, 3,
            6, 16#00, 16#e5,
            7, 16#00, 16#01,
            11, 16#00, 16#01,
            16#41, 16#d8, 16#e5>>,
    ?assertEqual({send, 0, [{6, 16#e5}, {7, 1}, {11, 1}], <<16#41, 16#d8, 16#e5>>},
                 slip_cmd:decode(Bin)).

sent_example_test() ->
    ?assertEqual({sent, 0, 0, 1},
                 slip_cmd:decode(<<"!R", 0, 0, 1>>)).

mac_example_test() ->
    ?assertEqual({mac, <<0, 1, 0, 1, 0, 1, 0, 1>>},
                 slip_cmd:decode(<<"!M", 0, 1, 0, 1, 0, 1, 0, 1>>)).

%% Every real frame decodes and encodes back to the same bytes
ref_roundtrip_test() ->
    Frames = ref_frames(),
    ?assertEqual(Frames,
                 [slip_cmd:encode(slip_cmd:decode(F)) || F <- Frames]).

%% Every !S got exactly one !R with the same id
ref_send_ids_match_test() ->
    Cmds = [slip_cmd:decode(F) || F <- ref_frames()],
    SendIds = lists:sort([Id || {send, Id, _, _} <- Cmds]),
    SentIds = lists:sort([Id || {sent, Id, _, _} <- Cmds]),
    ?assertEqual(12, length(SendIds)),
    ?assertEqual(SendIds, SentIds).

ref_frames() ->
    #{to_radio := ToRadio,
      from_radio := FromRadio} = pcap_ref:streams(?REF),
    {Sent, _} = slip_codec:decode(ToRadio, slip_codec:new()),
    {Recv, _} = slip_codec:decode(FromRadio, slip_codec:new()),
    Sent ++ Recv.
