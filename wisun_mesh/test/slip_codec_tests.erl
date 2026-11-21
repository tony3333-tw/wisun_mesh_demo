-module(slip_codec_tests).

-include_lib("eunit/include/eunit.hrl").

%% Frames seen in test/captures/br_cooja_ref.pcap
-define(ASK_MAC, <<"?M">>).
-define(MAC_REPLY, <<"!M", 0, 1, 0, 1, 0, 1, 0, 1>>).
-define(SEND_OK, <<"!R", 0, 0, 1>>).
%% A frame that needs escaping
-define(NEEDS_ESC, <<1, 16#C0, 2, 16#DB, 3>>).

encode_plain_test() ->
    ?assertEqual(<<16#C0, "?M", 16#C0>>,
                 slip_codec:encode(?ASK_MAC)).

encode_escape_test() ->
    ?assertEqual(<<16#C0, 1, 16#DB, 16#DC, 2, 16#DB, 16#DD, 3, 16#C0>>,
                 slip_codec:encode(?NEEDS_ESC)).

roundtrip_test() ->
    Frames = [?ASK_MAC, ?MAC_REPLY, ?SEND_OK, ?NEEDS_ESC],
    Wire = << <<(slip_codec:encode(F))/binary>> || F <- Frames >>,
    {Got, _State} = slip_codec:decode(Wire, slip_codec:new()),
    ?assertEqual(Frames, Got).

one_byte_at_a_time_test() ->
    %% TCP can split anywhere, even between ESC and the next byte
    Frames = [?MAC_REPLY, ?NEEDS_ESC],
    Wire = << <<(slip_codec:encode(F))/binary>> || F <- Frames >>,
    Feed = fun(B, {Acc, S}) ->
                   {New, S1} = slip_codec:decode(<<B>>, S),
                   {Acc ++ New, S1}
           end,
    {Got, _State} = lists:foldl(Feed,
                                {[], slip_codec:new()},
                                binary_to_list(Wire)),
    ?assertEqual(Frames, Got).
