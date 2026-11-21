%%% Contiki-NG slip-radio command protocol, inside one SLIP frame.
%%% See examples/slip-radio/slip-radio.c and
%%% os/services/slip-cmd/packetutils.c in contiki-ng.
-module(slip_cmd).

-export([decode/1,
         encode/1]).

-export_type([cmd/0]).

%% {Id, Value}: Id is a packetbuf attribute number (build-dependent;
%% without TSCH: 6 = MAC_SEQNO, 7 = MAC_ACK, 11 = FRAME_TYPE).
-type attr() :: {byte(), char()}.

-type cmd() :: ask_mac
             | {mac, binary()}
             | {send, byte(), [attr()], binary()}
             | {sent, byte(), byte(), byte()}
             | {get_param, char()}
             | {param, char(), char()}
             | {frame, binary()}.

-spec decode(binary()) -> cmd().
decode(<<"?M">>) ->
    ask_mac;
decode(<<"!M", Mac:8/binary>>) ->
    {mac, Mac};
decode(<<"!S", Id, Rest/binary>>) ->
    {Attrs, Frame} = attrs(Rest),
    {send, Id, Attrs, Frame};
decode(<<"!R", Id, Status, Tx>>) ->
    {sent, Id, Status, Tx};
decode(<<"?V", Type:16>>) ->
    {get_param, Type};
decode(<<"!V", Type:16, Value:16>>) ->
    {param, Type, Value};
decode(Frame) ->
    %% anything else is a received 802.15.4 frame
    {frame, Frame}.

-spec encode(cmd()) -> binary().
encode(ask_mac) ->
    <<"?M">>;
encode({mac, Mac}) ->
    <<"!M", Mac/binary>>;
encode({send, Id, Attrs, Frame}) ->
    AttrBin = << <<A, V:16>> || {A, V} <- Attrs >>,
    <<"!S", Id, (length(Attrs)), AttrBin/binary, Frame/binary>>;
encode({sent, Id, Status, Tx}) ->
    <<"!R", Id, Status, Tx>>;
encode({get_param, Type}) ->
    <<"?V", Type:16>>;
encode({param, Type, Value}) ->
    <<"!V", Type:16, Value:16>>;
encode({frame, Frame}) ->
    Frame.

attrs(<<Count, Rest/binary>>) ->
    attrs(Count, Rest, []).

attrs(0, Frame, Acc) ->
    {lists:reverse(Acc), Frame};
attrs(N, <<A, V:16, Rest/binary>>, Acc) ->
    attrs(N - 1, Rest, [{A, V} | Acc]).
