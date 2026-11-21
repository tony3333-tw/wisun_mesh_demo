%%% Test helper: rebuild the two TCP byte streams on port 60001
%%% from a tcpdump capture. Test-only; not part of the app.
-module(pcap_ref).

-export([streams/1]).

-define(PORT, 60001).

%% Returns #{to_radio => binary(), from_radio => binary()}.
streams(File) ->
    {ok, Bin} = file:read_file(File),
    <<16#a1b2c3d4:32/little,
      _VerMaj:16/little,
      _VerMin:16/little,
      _Zone:32/little,
      _SigFigs:32/little,
      _SnapLen:32/little,
      LinkType:32/little,
      Records/binary>> = Bin,
    Segs = records(Records, LinkType, #{}),
    maps:map(fun(_Dir, BySeq) ->
                     join(BySeq)
             end,
             Segs).

records(<<>>, _LinkType, Acc) ->
    Acc;
records(<<_Sec:32/little,
          _USec:32/little,
          Len:32/little,
          _OrigLen:32/little,
          Data:Len/binary,
          Rest/binary>>,
        LinkType,
        Acc) ->
    records(Rest, LinkType, ipv4(strip_link(LinkType, Data), Acc)).

%% 276 = LINUX_SLL2 (-i any), 113 = LINUX_SLL, 1 = Ethernet (-i lo)
strip_link(276, <<_:20/binary, IP/binary>>) ->
    IP;
strip_link(113, <<_:16/binary, IP/binary>>) ->
    IP;
strip_link(1, <<_:14/binary, IP/binary>>) ->
    IP.

ipv4(<<4:4,
       IHL:4,
       _Tos:8,
       TotLen:16,
       _Id:16,
       _Frag:16,
       _Ttl:8,
       6:8,
       _Csum:16,
       _/binary>> = IP,
     Acc) ->
    HdrLen = IHL * 4,
    TcpLen = TotLen - HdrLen,
    <<_:HdrLen/binary, TCP:TcpLen/binary, _/binary>> = IP,
    tcp(TCP, Acc);
ipv4(_NotTcpV4, Acc) ->
    Acc.

tcp(<<SPort:16,
      DPort:16,
      Seq:32,
      _Ack:32,
      DOff:4,
      _:4,
      _/binary>> = TCP,
    Acc) ->
    HLen = DOff * 4,
    <<_:HLen/binary, Payload/binary>> = TCP,
    add(dir(SPort, DPort), Seq, Payload, Acc).

%% -i any records each loopback packet twice: same seq, same bytes.
add(_Dir, _Seq, <<>>, Acc) ->
    Acc;
add(other, _Seq, _Payload, Acc) ->
    Acc;
add(Dir, Seq, Payload, Acc) ->
    BySeq = maps:get(Dir, Acc, #{}),
    Acc#{Dir => BySeq#{Seq => Payload}}.

dir(_SPort, ?PORT) ->
    to_radio;
dir(?PORT, _DPort) ->
    from_radio;
dir(_SPort, _DPort) ->
    other.

join(BySeq) ->
    << <<(maps:get(S, BySeq))/binary>> || S <- lists:sort(maps:keys(BySeq)) >>.
