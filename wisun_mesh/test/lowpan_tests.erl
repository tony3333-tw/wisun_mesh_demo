-module(lowpan_tests).

-include_lib("eunit/include/eunit.hrl").

-define(REF, "test/captures/br_cooja_ref.pcap").
-define(NODE2, <<0, 2, 0, 2, 0, 2, 0, 2>>).

%% RPL DIS from node 2, received live from Cooja
dis_live_test() ->
    Payload = <<122, 59, 58, 26, 155, 0, 101, 25, 0, 0>>,
    {ok, P} = lowpan:decode(Payload, {long, ?NODE2}, {short, 16#ffff}),
    ?assertEqual(ip("fe80::202:2:2:2"), maps:get(src, P)),
    ?assertEqual(ip("ff02::1a"), maps:get(dst, P)),
    ?assertEqual(64, maps:get(hop_limit, P)),
    ?assertEqual(58, maps:get(next_header, P)),
    ?assertEqual([], maps:get(ext, P)),
    ?assertEqual(<<155, 0, 101, 25, 0, 0>>, maps:get(payload, P)).

unsupported_dispatch_test() ->
    ?assertEqual({error, {unsupported_dispatch, 16#41}},
                 lowpan:decode(<<16#41, 0>>, {short, 1}, {short, 2})).

%% All 27 frames decode; ICMPv6 types match the prototype
ref_icmp_types_test() ->
    Packets = ref_packets(),
    ?assertEqual(27, length(Packets)),
    ?assert(lists:all(fun(#{next_header := N}) -> N =:= 58 end, Packets)),
    Counts = lists:foldl(fun(#{payload := <<T, C, _/binary>>}, M) ->
                                 maps:update_with({T, C},
                                                  fun(N) -> N + 1 end,
                                                  1,
                                                  M)
                         end,
                         #{},
                         Packets),
    ?assertEqual(#{{155, 1} => 11,
                   {155, 2} => 3,
                   {155, 3} => 3,
                   {128, 0} => 5,
                   {129, 0} => 5},
                 Counts).

%% Ping replies: node 4 -> fd00::1, two hops, RPL option in hop-by-hop
ref_echo_reply_test() ->
    Replies = [P || #{payload := <<129, _/binary>>} = P <- ref_packets()],
    ?assertEqual(5, length(Replies)),
    lists:foreach(fun(P) ->
                          ?assertEqual(ip("fd00::204:4:4:4"), maps:get(src, P)),
                          ?assertEqual(ip("fd00::1"), maps:get(dst, P)),
                          ?assertEqual(62, maps:get(hop_limit, P)),
                          ?assertMatch([{hop_by_hop, <<16#63, 4, _/binary>>}],
                                       maps:get(ext, P))
                  end,
                  Replies).

%% Ping requests: fd00::1 -> first hop node 2, with a routing header
ref_echo_request_test() ->
    Requests = [P || #{payload := <<128, _/binary>>} = P <- ref_packets()],
    ?assertEqual(5, length(Requests)),
    lists:foreach(fun(P) ->
                          ?assertEqual(ip("fd00::1"), maps:get(src, P)),
                          ?assertEqual(ip("fd00::202:2:2:2"), maps:get(dst, P)),
                          ?assertMatch([{routing, <<3, 2, _/binary>>}],
                                       maps:get(ext, P))
                  end,
                  Requests).

%%% helpers

ip(Str) ->
    {ok, T} = inet:parse_address(Str),
    << <<W:16>> || W <- tuple_to_list(T) >>.

ref_packets() ->
    [P || {ok, P} <- [lowpan:decode(Payload, Src, Dst)
                      || #{payload := Payload,
                           src := Src,
                           dst := Dst} <- ref_mac()]].

ref_mac() ->
    #{to_radio := ToRadio,
      from_radio := FromRadio} = pcap_ref:streams(?REF),
    {Sent, _} = slip_codec:decode(ToRadio, slip_codec:new()),
    {Recv, _} = slip_codec:decode(FromRadio, slip_codec:new()),
    Cmds = [slip_cmd:decode(F) || F <- Sent ++ Recv],
    Frames = [F || {send, _Id, _Attrs, F} <- Cmds]
        ++ [F || {frame, F} <- Cmds],
    [M || {ok, M} <- [mac154:decode(F) || F <- Frames]].
