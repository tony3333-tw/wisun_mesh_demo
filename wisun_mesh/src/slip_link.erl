%%% TCP link to a Contiki-NG slip-radio (Cooja serial socket or a board).
%%% Sends ?M on connect; forwards every decoded command to Owner as
%%% {slip_link, Pid, Cmd}. Reconnects if the connection drops.
-module(slip_link).

-behaviour(gen_server).

-export([start_link/3,
         send/2,
         mac/1,
         stop/1]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2]).

-define(RETRY_MS, 2000).
-define(CONNECT_TIMEOUT_MS, 2000).

-record(st,
        {host,
         port,
         owner,
         sock = undefined,
         dec = slip_codec:new(),
         mac = undefined}).

%%% API

start_link(Host, Port, Owner) ->
    gen_server:start_link(?MODULE, {Host, Port, Owner}, []).

send(Pid, Cmd) ->
    gen_server:cast(Pid, {send, Cmd}).

mac(Pid) ->
    gen_server:call(Pid, mac).

stop(Pid) ->
    gen_server:stop(Pid).

%%% gen_server

init({Host, Port, Owner}) ->
    self() ! connect,
    {ok, #st{host = Host,
             port = Port,
             owner = Owner}}.

handle_call(mac, _From, St) ->
    {reply, St#st.mac, St}.

handle_cast({send, _Cmd}, #st{sock = undefined} = St) ->
    %% not connected: drop it
    {noreply, St};
handle_cast({send, Cmd}, #st{sock = Sock} = St) ->
    _ = gen_tcp:send(Sock, frame(Cmd)),
    {noreply, St}.

handle_info(connect, #st{host = Host, port = Port} = St) ->
    Opts = [binary,
            {packet, raw},
            {active, once}],
    case gen_tcp:connect(Host, Port, Opts, ?CONNECT_TIMEOUT_MS) of
        {ok, Sock} ->
            _ = gen_tcp:send(Sock, frame(ask_mac)),
            {noreply, St#st{sock = Sock,
                            dec = slip_codec:new()}};
        {error, _Reason} ->
            retry(St)
    end;
handle_info({tcp, Sock, Data}, #st{sock = Sock, dec = Dec} = St) ->
    {Frames, Dec1} = slip_codec:decode(Data, Dec),
    St1 = lists:foldl(fun(F, S) ->
                              handle_cmd(slip_cmd:decode(F), S)
                      end,
                      St#st{dec = Dec1},
                      Frames),
    ok = inet:setopts(Sock, [{active, once}]),
    {noreply, St1};
handle_info({tcp_closed, Sock}, #st{sock = Sock} = St) ->
    retry(St);
handle_info({tcp_error, Sock, _Reason}, #st{sock = Sock} = St) ->
    _ = gen_tcp:close(Sock),
    retry(St);
handle_info(_Other, St) ->
    {noreply, St}.

%%% internal

handle_cmd({mac, Mac} = Cmd, St) ->
    notify(Cmd, St),
    St#st{mac = Mac};
handle_cmd(Cmd, St) ->
    notify(Cmd, St),
    St.

notify(Cmd, #st{owner = Owner}) ->
    Owner ! {slip_link, self(), Cmd}.

frame(Cmd) ->
    slip_codec:encode(slip_cmd:encode(Cmd)).

retry(St) ->
    erlang:send_after(?RETRY_MS, self(), connect),
    {noreply, St#st{sock = undefined}}.
