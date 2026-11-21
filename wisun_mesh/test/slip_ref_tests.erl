%%% slip_codec against real traffic captured from
%%% Contiki-NG's native border router talking to Cooja.
-module(slip_ref_tests).

-include_lib("eunit/include/eunit.hrl").

-define(REF, "test/captures/br_cooja_ref.pcap").

ref_capture_test() ->
    #{to_radio := ToRadio,
      from_radio := FromRadio} = pcap_ref:streams(?REF),
    {Sent, _} = slip_codec:decode(ToRadio, slip_codec:new()),
    {Recv, _} = slip_codec:decode(FromRadio, slip_codec:new()),
    ?assertEqual(#{send => 12,
                   ask_mac => 1},
                 kinds(Sent)),
    ?assertEqual(#{send_result => 12,
                   mac => 1,
                   radio_frame => 15},
                 kinds(Recv)),
    ?assert(lists:member(<<"!M", 0, 1, 0, 1, 0, 1, 0, 1>>, Recv)).

kinds(Frames) ->
    lists:foldl(fun(F, M) ->
                        maps:update_with(kind(F),
                                         fun(N) -> N + 1 end,
                                         1,
                                         M)
                end,
                #{},
                Frames).

kind(<<"!S", _/binary>>) ->
    send;
kind(<<"!R", _/binary>>) ->
    send_result;
kind(<<"?M", _/binary>>) ->
    ask_mac;
kind(<<"!M", _/binary>>) ->
    mac;
kind(_) ->
    radio_frame.
