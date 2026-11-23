%%% 6LoWPAN IPHC (RFC 6282) decode, step 1:
%%% IPHC header + extension header NHC. No fragments, no UDP NHC yet.
-module(lowpan).

-export([decode/3,
         decode/4,
         default_contexts/0]).

-export_type([packet/0]).

-type ext_name() :: hop_by_hop
                  | routing
                  | fragment
                  | dest_opts
                  | mobility
                  | ipv6
                  | {ext, 0..7}.

%% Addresses are 16-byte binaries. Extension headers are returned raw.
-type packet() :: #{traffic_class := byte(),
                    flow_label := 0..16#fffff,
                    hop_limit := byte(),
                    src := <<_:128>>,
                    dst := <<_:128>>,
                    ext := [{ext_name(), binary()}],
                    next_header := byte(),
                    payload := binary()}.

%% Context 0 = fd00::/64 (Contiki-NG UIP_DS6_DEFAULT_PREFIX)
default_contexts() ->
    #{0 => <<16#fd00:16, 0:48>>}.

-spec decode(binary(), mac154:addr(), mac154:addr()) ->
          {ok, packet()} | {error, term()}.
decode(Payload, MacSrc, MacDst) ->
    decode(Payload, MacSrc, MacDst, default_contexts()).

decode(<<2#011:3, _/bitstring>> = Payload, MacSrc, MacDst, Ctx) ->
    try
        {ok, iphc(Payload, MacSrc, MacDst, Ctx)}
    catch
        error:_ ->
            {error, malformed}
    end;
decode(<<Dispatch, _/binary>>, _MacSrc, _MacDst, _Ctx) ->
    {error, {unsupported_dispatch, Dispatch}};
decode(<<>>, _MacSrc, _MacDst, _Ctx) ->
    {error, malformed}.

%%% IPHC header

iphc(<<2#011:3, TF:2, NH:1, HLIM:2,
       CID:1, SAC:1, SAM:2, M:1, DAC:1, DAM:2,
       R0/binary>>,
     MacSrc,
     MacDst,
     Ctx) ->
    {SCI, DCI, R1} = cid(CID, R0),
    {TC, FL, R2} = tf(TF, R1),
    {Next0, R3} = inline_nh(NH, R2),
    {Hop, R4} = hlim(HLIM, R3),
    {Src, R5} = src_addr(SAC, SAM, prefix(SAC, SCI, Ctx), MacSrc, R4),
    {Dst, R6} = dst_addr(M, DAC, DAM, prefix(DAC, DCI, Ctx), MacDst, R5),
    {Ext, Next, Payload} = nhc(Next0, R6, []),
    #{traffic_class => TC,
      flow_label => FL,
      hop_limit => Hop,
      src => Src,
      dst => Dst,
      ext => Ext,
      next_header => Next,
      payload => Payload}.

cid(0, R) ->
    {0, 0, R};
cid(1, <<S:4, D:4, R/binary>>) ->
    {S, D, R}.

%% inline order is ECN then DSCP; traffic class is DSCP then ECN
tf(0, <<ECN:2, DSCP:6, _:4, FL:20, R/binary>>) ->
    {(DSCP bsl 2) bor ECN, FL, R};
tf(1, <<ECN:2, _:2, FL:20, R/binary>>) ->
    {ECN, FL, R};
tf(2, <<ECN:2, DSCP:6, R/binary>>) ->
    {(DSCP bsl 2) bor ECN, 0, R};
tf(3, R) ->
    {0, 0, R}.

inline_nh(0, <<N, R/binary>>) ->
    {N, R};
inline_nh(1, R) ->
    {compressed, R}.

hlim(0, <<H, R/binary>>) ->
    {H, R};
hlim(1, R) ->
    {1, R};
hlim(2, R) ->
    {64, R};
hlim(3, R) ->
    {255, R}.

prefix(0, _N, _Ctx) ->
    <<16#fe80:16, 0:48>>;
prefix(1, N, Ctx) ->
    maps:get(N, Ctx).

%%% addresses

src_addr(0, 0, _P, _Mac, <<A:16/binary, R/binary>>) ->
    {A, R};
src_addr(1, 0, _P, _Mac, R) ->
    %% unspecified address ::
    {<<0:128>>, R};
src_addr(_AC, AM, P, Mac, R) ->
    unicast(AM, P, Mac, R).

dst_addr(0, 0, 0, _P, _Mac, <<A:16/binary, R/binary>>) ->
    {A, R};
dst_addr(0, 1, 0, _P, _Mac, _R) ->
    error(reserved);
dst_addr(0, _DAC, AM, P, Mac, R) ->
    unicast(AM, P, Mac, R);
dst_addr(1, 0, 0, _P, _Mac, <<A:16/binary, R/binary>>) ->
    {A, R};
dst_addr(1, 0, 1, _P, _Mac, <<F, B:5/binary, R/binary>>) ->
    %% ffXX::00XX:XXXX:XXXX
    {<<16#ff, F, 0:72, B/binary>>, R};
dst_addr(1, 0, 2, _P, _Mac, <<F, B:3/binary, R/binary>>) ->
    %% ffXX::00XX:XXXX
    {<<16#ff, F, 0:88, B/binary>>, R};
dst_addr(1, 0, 3, _P, _Mac, <<B, R/binary>>) ->
    %% ff02::00XX
    {<<16#ff02:16, 0:104, B>>, R}.

unicast(1, P, _Mac, <<I:8/binary, R/binary>>) ->
    {<<P/binary, I/binary>>, R};
unicast(2, P, _Mac, <<S:16, R/binary>>) ->
    {<<P/binary, 0, 0, 0, 16#ff, 16#fe, 0, S:16>>, R};
unicast(3, P, Mac, R) ->
    {<<P/binary, (iid(Mac))/binary>>, R}.

%% interface id from the MAC address (flip the U/L bit for long ones)
iid({long, <<B0, Rest:7/binary>>}) ->
    <<(B0 bxor 2), Rest/binary>>;
iid({short, S}) ->
    <<0, 0, 0, 16#ff, 16#fe, 0, S:16>>.

%%% extension header NHC (kept raw)

nhc(compressed, <<2#1110:4, EID:3, NH:1, R0/binary>>, Acc) ->
    {Next, R1} = inline_nh(NH, R0),
    <<Len, Data:Len/binary, R2/binary>> = R1,
    nhc(Next, R2, [{ext_name(EID), Data} | Acc]);
nhc(Next, R, Acc)
  when is_integer(Next) ->
    {lists:reverse(Acc), Next, R}.

ext_name(0) ->
    hop_by_hop;
ext_name(1) ->
    routing;
ext_name(2) ->
    fragment;
ext_name(3) ->
    dest_opts;
ext_name(4) ->
    mobility;
ext_name(7) ->
    ipv6;
ext_name(N) ->
    {ext, N}.
