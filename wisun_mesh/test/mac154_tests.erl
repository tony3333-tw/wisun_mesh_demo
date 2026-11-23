-module(mac154_tests).

-include_lib("eunit/include/eunit.hrl").

-define(REF, "test/captures/br_cooja_ref.pcap").
-define(NODE1, <<0, 1, 0, 1, 0, 1, 0, 1>>).
-define(NODE2, <<0, 2, 0, 2, 0, 2, 0, 2>>).

%% RPL DIS from node 2, received live from Cooja (v0.0.3)
dis_from_node2_test() ->
    Bin = <<65, 216, 30, 205, 171, 255, 255,
            2, 0, 2, 0, 2, 0, 2, 0,
            122, 59, 58, 26, 155, 0, 101, 25, 0, 0>>,
    {ok, F} = mac154:decode(Bin),
    ?assertMatch(#{type := data,
                   security := false,
                   ack_req := false,
                   pan_comp := true,
                   version := 1,
                   seq := 30,
                   dst_pan := 16#abcd,
                   dst := {short, 16#ffff},
                   src_pan := undefined,
                   src := {long, ?NODE2},
                   payload := <<122, 59, 58, 26, 155, 0, 101, 25, 0, 0>>},
                 F),
    ?assertEqual(Bin, mac154:encode(F)).

%% Unicast node 2 -> node 1 (header from the reference capture)
unicast_test() ->
    Bin = <<16#61, 16#dc, 5, 16#cd, 16#ab,
            1, 0, 1, 0, 1, 0, 1, 0,
            2, 0, 2, 0, 2, 0, 2, 0,
            16#7a, 16#33>>,
    {ok, F} = mac154:decode(Bin),
    ?assertMatch(#{type := data,
                   ack_req := true,
                   seq := 5,
                   dst_pan := 16#abcd,
                   dst := {long, ?NODE1},
                   src := {long, ?NODE2},
                   payload := <<16#7a, 16#33>>},
                 F),
    ?assertEqual(Bin, mac154:encode(F)).

malformed_test() ->
    ?assertEqual({error, malformed}, mac154:decode(<<1>>)),
    %% address mode 1 is reserved
    ?assertEqual({error, malformed}, mac154:decode(<<16#41, 16#04, 0, 0, 0, 0>>)).

%% All 27 frames in the capture decode and encode back to the same bytes
ref_all_frames_test() ->
    Frames = ref_mac_frames(),
    ?assertEqual(27, length(Frames)),
    Decoded = [F || {ok, F} <- [mac154:decode(B) || B <- Frames]],
    ?assertEqual(27, length(Decoded)),
    ?assertEqual(Frames, [mac154:encode(F) || F <- Decoded]),
    ?assert(lists:all(fun(#{type := T, dst_pan := P}) ->
                              T =:= data andalso P =:= 16#abcd
                      end,
                      Decoded)).

%% 802.15.4 frames sent (inside !S) and received (raw) in the capture
ref_mac_frames() ->
    #{to_radio := ToRadio,
      from_radio := FromRadio} = pcap_ref:streams(?REF),
    {Sent, _} = slip_codec:decode(ToRadio, slip_codec:new()),
    {Recv, _} = slip_codec:decode(FromRadio, slip_codec:new()),
    Cmds = [slip_cmd:decode(F) || F <- Sent ++ Recv],
    [Frame || {send, _Id, _Attrs, Frame} <- Cmds]
        ++ [Frame || {frame, Frame} <- Cmds].
