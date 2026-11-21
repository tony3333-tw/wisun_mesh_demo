%%% slip_link against a fake radio (plain TCP listener); no Cooja needed.
-module(slip_link_tests).

-include_lib("eunit/include/eunit.hrl").

-define(MAC, <<0, 1, 0, 1, 0, 1, 0, 1>>).

fake_radio_test() ->
    {ok, Listen} = gen_tcp:listen(0, [binary,
                                      {active, false},
                                      {reuseaddr, true}]),
    {ok, Port} = inet:port(Listen),
    {ok, Link} = slip_link:start_link({127, 0, 0, 1}, Port, self()),
    {ok, Radio} = gen_tcp:accept(Listen, 2000),

    %% 1. the link asks for the MAC first
    {ok, Asked} = gen_tcp:recv(Radio, 0, 2000),
    ?assertEqual(slip_codec:encode(<<"?M">>), Asked),

    %% 2. the radio answers, split across two TCP sends
    Reply = slip_codec:encode(<<"!M", ?MAC/binary>>),
    {Part1, Part2} = split_binary(Reply, 4),
    ok = gen_tcp:send(Radio, Part1),
    ok = gen_tcp:send(Radio, Part2),
    receive
        {slip_link, Link, {mac, Mac}} ->
            ?assertEqual(?MAC, Mac)
    after 2000 ->
            ?assert(false)
    end,
    ?assertEqual(?MAC, slip_link:mac(Link)),

    %% 3. sending a command puts the right bytes on the wire
    ok = slip_link:send(Link, {send, 7, [{6, 1}], <<1, 2, 3>>}),
    {ok, Sent} = gen_tcp:recv(Radio, 0, 2000),
    ?assertEqual(slip_codec:encode(<<"!S", 7, 1, 6, 0, 1, 1, 2, 3>>), Sent),

    ok = slip_link:stop(Link),
    ok = gen_tcp:close(Radio),
    ok = gen_tcp:close(Listen).
