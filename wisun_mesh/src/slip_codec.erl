%%% SLIP framing (RFC 1055) as used by Contiki-NG slip-radio.
%%% Pure functions: no processes, no sockets.
-module(slip_codec).

-export([new/0,
         encode/1,
         decode/2]).

-export_type([state/0]).

-define(END, 16#C0).
-define(ESC, 16#DB).
-define(ESC_END, 16#DC).
-define(ESC_ESC, 16#DD).

-record(dec,
        {acc = <<>> :: binary(),
         esc = false :: boolean()}).

-opaque state() :: #dec{}.

%% Fresh decoder state.
-spec new() -> state().
new() ->
    #dec{}.

%% Frame one packet: END + escaped bytes + END.
-spec encode(binary()) -> binary().
encode(Frame)
  when is_binary(Frame) ->
    Body = << <<(escape(B))/binary>> || <<B>> <= Frame >>,
    <<?END, Body/binary, ?END>>.

%% Feed any chunk of bytes from the stream.
%% Returns the complete frames found, and the state to use next time.
-spec decode(binary(), state()) -> {[binary()], state()}.
decode(Bin, State) ->
    decode(Bin, State, []).

decode(<<>>, State, Frames) ->
    {lists:reverse(Frames), State};
decode(<<?END, Rest/binary>>, #dec{acc = <<>>}, Frames) ->
    %% empty frame (leading END): skip
    decode(Rest, #dec{}, Frames);
decode(<<?END, Rest/binary>>, #dec{acc = Acc}, Frames) ->
    decode(Rest, #dec{}, [Acc | Frames]);
decode(<<B, Rest/binary>>, #dec{esc = true, acc = Acc}, Frames) ->
    decode(Rest, #dec{acc = <<Acc/binary, (unescape(B))>>}, Frames);
decode(<<?ESC, Rest/binary>>, State, Frames) ->
    decode(Rest, State#dec{esc = true}, Frames);
decode(<<B, Rest/binary>>, #dec{acc = Acc}, Frames) ->
    decode(Rest, #dec{acc = <<Acc/binary, B>>}, Frames).

escape(?END) ->
    <<?ESC, ?ESC_END>>;
escape(?ESC) ->
    <<?ESC, ?ESC_ESC>>;
escape(B) ->
    <<B>>.

unescape(?ESC_END) ->
    ?END;
unescape(?ESC_ESC) ->
    ?ESC;
unescape(B) ->
    B.
