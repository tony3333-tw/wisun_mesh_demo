%%% IEEE 802.15.4 MAC frames (2003/2006 format, no security decoding).
%%% Frames from slip-radio carry no FCS.
-module(mac154).

-export([decode/1,
         encode/1]).

-export_type([frame/0,
              addr/0]).

-type addr() :: none
              | {short, 0..16#ffff}
              | {long, <<_:64>>}.

%% src_pan is undefined when pan_comp is true (it equals dst_pan).
%% Long addresses are in normal order (the frame carries them reversed).
-type frame() :: #{type := beacon | data | ack | cmd | {reserved, 0..7},
                   security := boolean(),
                   pending := boolean(),
                   ack_req := boolean(),
                   pan_comp := boolean(),
                   version := 0..3,
                   seq := byte(),
                   dst_pan := undefined | 0..16#ffff,
                   dst := addr(),
                   src_pan := undefined | 0..16#ffff,
                   src := addr(),
                   payload := binary()}.

-spec decode(binary()) -> {ok, frame()} | {error, malformed}.
decode(Bin) ->
    try
        {ok, do_decode(Bin)}
    catch
        error:_ ->
            {error, malformed}
    end.

-spec encode(frame()) -> binary().
encode(#{type := Type,
         security := Sec,
         pending := Pend,
         ack_req := AckReq,
         pan_comp := PanComp,
         version := Version,
         seq := Seq,
         dst_pan := DstPan,
         dst := Dst,
         src_pan := SrcPan,
         src := Src,
         payload := Payload}) ->
    Fcf = type_num(Type)
        bor (bit(Sec) bsl 3)
        bor (bit(Pend) bsl 4)
        bor (bit(AckReq) bsl 5)
        bor (bit(PanComp) bsl 6)
        bor (mode(Dst) bsl 10)
        bor (Version bsl 12)
        bor (mode(Src) bsl 14),
    <<Fcf:16/little,
      Seq,
      (pan_bin(DstPan))/binary,
      (addr_bin(Dst))/binary,
      (pan_bin(SrcPan))/binary,
      (addr_bin(Src))/binary,
      Payload/binary>>.

%%% internal

do_decode(<<Fcf:16/little, Seq, Rest0/binary>>) ->
    DstMode = (Fcf bsr 10) band 3,
    SrcMode = (Fcf bsr 14) band 3,
    PanComp = (Fcf bsr 6) band 1 =:= 1,
    {DstPan, Rest1} = pan(DstMode =/= 0, Rest0),
    {Dst, Rest2} = addr(DstMode, Rest1),
    SrcPanHere = SrcMode =/= 0
        andalso not (PanComp andalso DstMode =/= 0),
    {SrcPan, Rest3} = pan(SrcPanHere, Rest2),
    {Src, Payload} = addr(SrcMode, Rest3),
    #{type => type_atom(Fcf band 7),
      security => (Fcf bsr 3) band 1 =:= 1,
      pending => (Fcf bsr 4) band 1 =:= 1,
      ack_req => (Fcf bsr 5) band 1 =:= 1,
      pan_comp => PanComp,
      version => (Fcf bsr 12) band 3,
      seq => Seq,
      dst_pan => DstPan,
      dst => Dst,
      src_pan => SrcPan,
      src => Src,
      payload => Payload}.

pan(false, Bin) ->
    {undefined, Bin};
pan(true, <<Pan:16/little, Rest/binary>>) ->
    {Pan, Rest}.

%% mode 1 is reserved: no clause, so decode/1 returns {error, malformed}
addr(0, Bin) ->
    {none, Bin};
addr(2, <<A:16/little, Rest/binary>>) ->
    {{short, A}, Rest};
addr(3, <<A:8/binary, Rest/binary>>) ->
    {{long, reverse(A)}, Rest}.

pan_bin(undefined) ->
    <<>>;
pan_bin(Pan) ->
    <<Pan:16/little>>.

addr_bin(none) ->
    <<>>;
addr_bin({short, A}) ->
    <<A:16/little>>;
addr_bin({long, A}) ->
    reverse(A).

mode(none) ->
    0;
mode({short, _}) ->
    2;
mode({long, _}) ->
    3.

type_atom(0) ->
    beacon;
type_atom(1) ->
    data;
type_atom(2) ->
    ack;
type_atom(3) ->
    cmd;
type_atom(N) ->
    {reserved, N}.

type_num(beacon) ->
    0;
type_num(data) ->
    1;
type_num(ack) ->
    2;
type_num(cmd) ->
    3;
type_num({reserved, N}) ->
    N.

bit(true) ->
    1;
bit(false) ->
    0.

reverse(Bin) ->
    list_to_binary(lists:reverse(binary_to_list(Bin))).
