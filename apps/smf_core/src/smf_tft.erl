%% Copyright 2024, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(smf_tft).

-export([encode/1, decode/1,
	 flow_info_to_tft/1, tft_to_flow_info/1,
	 parse_flow_description/1, format_flow_description/1]).
-ignore_xref([encode/1, decode/1,
	      flow_info_to_tft/1, tft_to_flow_info/1,
	      parse_flow_description/1, format_flow_description/1]).

%%%===================================================================
%%% API
%%%===================================================================

%% decode/1 — binary() -> map()
decode(<<OpCode:3, EBit:1, NumFilters:4, Rest/binary>>) ->
    Operation = decode_operation(OpCode),
    {Filters, ParamsData} = decode_filters(Operation, NumFilters, Rest),
    Parameters = decode_parameters(EBit, ParamsData),
    #{operation => Operation,
      filters => Filters,
      parameters => Parameters}.

%% encode/1 — map() -> binary()
encode(#{operation := Operation, filters := Filters, parameters := Parameters}) ->
    OpCode = encode_operation(Operation),
    NumFilters = length(Filters),
    EBit = case Parameters of [] -> 0; _ -> 1 end,
    Header = <<OpCode:3, EBit:1, NumFilters:4>>,
    FiltersBin = encode_filters(Operation, Filters),
    ParamsBin = encode_parameters(Parameters),
    <<Header/binary, FiltersBin/binary, ParamsBin/binary>>.

%% flow_info_to_tft/1 — [map()] -> binary()
flow_info_to_tft(FlowInfoList) ->
    Filters = flow_info_list_to_filters(FlowInfoList, 0, 255),
    encode(#{operation => create_new_tft, filters => Filters, parameters => []}).

%% tft_to_flow_info/1 — binary() -> [map()]
tft_to_flow_info(Bin) ->
    #{filters := Filters} = decode(Bin),
    [filter_to_flow_info(F) || F <- Filters].

%% parse_flow_description/1 — binary() -> {Direction, [component()]}
parse_flow_description(Desc) when is_binary(Desc) ->
    Tokens = binary:split(Desc, <<" ">>, [global, trim_all]),
    parse_flow_desc_tokens(Tokens).

%% format_flow_description/1 — {Direction, [component()]} -> binary()
format_flow_description({Direction, Components}) ->
    DirStr = case Direction of
		 out -> <<"out">>;
		 in  -> <<"in">>
	     end,
    {Proto, RemoteAddr, RemotePorts, _LocalAddr, LocalPorts, Extras} =
	extract_components(Components),
    ProtoStr = format_protocol(Proto),
    %% For "out" (downlink): from=remote, to=local(UE=assigned)
    %% For "in" (uplink): from=local(UE=assigned), to=remote
    {FromAddr, FromPorts, ToAddr, ToPorts} =
	case Direction of
	    out -> {RemoteAddr, RemotePorts, <<"assigned">>, LocalPorts};
	    in  -> {<<"assigned">>, LocalPorts, RemoteAddr, RemotePorts}
	end,
    FromStr = format_addr_ports(FromAddr, FromPorts),
    ToStr = format_addr_ports(ToAddr, ToPorts),
    ExtraStr = format_extras(Extras),
    Parts = [<<"permit">>, DirStr, ProtoStr, <<"from">>, FromStr, <<"to">>, ToStr | ExtraStr],
    iolist_to_binary(lists:join(<<" ">>, Parts)).

%%%===================================================================
%%% Internal — operation encoding/decoding
%%%===================================================================

decode_operation(1) -> create_new_tft;
decode_operation(2) -> delete_existing_tft;
decode_operation(3) -> add_packet_filters;
decode_operation(4) -> replace_packet_filters;
decode_operation(5) -> delete_packet_filters;
decode_operation(6) -> no_tft_operation;
decode_operation(_) -> spare.

encode_operation(create_new_tft)      -> 1;
encode_operation(delete_existing_tft) -> 2;
encode_operation(add_packet_filters)  -> 3;
encode_operation(replace_packet_filters) -> 4;
encode_operation(delete_packet_filters)  -> 5;
encode_operation(no_tft_operation)    -> 6;
encode_operation(spare)               -> 0.

%%%===================================================================
%%% Internal — filter decoding
%%%===================================================================

decode_filters(delete_packet_filters, NumFilters, Data) ->
    decode_delete_filter_ids(NumFilters, Data, []);
decode_filters(_, NumFilters, Data) ->
    decode_full_filters(NumFilters, Data, []).

decode_delete_filter_ids(0, Rest, Acc) ->
    {lists:reverse(Acc), Rest};
decode_delete_filter_ids(N, <<Id:4, _:4, Rest/binary>>, Acc) ->
    decode_delete_filter_ids(N - 1, Rest, [#{id => Id, direction => bidirectional,
					     precedence => 0, components => []} | Acc]).

decode_full_filters(0, Rest, Acc) ->
    {lists:reverse(Acc), Rest};
decode_full_filters(N, <<Id:4, Dir:2, _:2, Precedence:8, Len:8, Content:Len/binary, Rest/binary>>, Acc) ->
    Direction = decode_direction(Dir),
    Components = decode_components(Content),
    Filter = #{id => Id, direction => Direction,
	       precedence => Precedence, components => Components},
    decode_full_filters(N - 1, Rest, [Filter | Acc]).

decode_direction(0) -> pre_rel7;
decode_direction(1) -> downlink;
decode_direction(2) -> uplink;
decode_direction(3) -> bidirectional.

encode_direction(pre_rel7)     -> 0;
encode_direction(downlink)     -> 1;
encode_direction(uplink)       -> 2;
encode_direction(bidirectional) -> 3.

%%%===================================================================
%%% Internal — filter encoding
%%%===================================================================

encode_filters(delete_packet_filters, Filters) ->
    << <<Id:4, 0:4>> || #{id := Id} <- Filters >>;
encode_filters(_, Filters) ->
    iolist_to_binary([encode_full_filter(F) || F <- Filters]).

encode_full_filter(#{id := Id, direction := Direction,
		     precedence := Precedence, components := Components}) ->
    Dir = encode_direction(Direction),
    Content = encode_components(Components),
    Len = byte_size(Content),
    <<Id:4, Dir:2, 0:2, Precedence:8, Len:8, Content/binary>>.

%%%===================================================================
%%% Internal — component decoding
%%%===================================================================

decode_components(<<>>) -> [];
decode_components(<<16#10, A1, A2, A3, A4, M1, M2, M3, M4, Rest/binary>>) ->
    [{ipv4_remote, <<A1, A2, A3, A4>>, <<M1, M2, M3, M4>>} | decode_components(Rest)];
decode_components(<<16#11, A1, A2, A3, A4, M1, M2, M3, M4, Rest/binary>>) ->
    [{ipv4_local, <<A1, A2, A3, A4>>, <<M1, M2, M3, M4>>} | decode_components(Rest)];
decode_components(<<16#20, Addr:16/binary, PrefixLen:8, Rest/binary>>) ->
    [{ipv6_remote, Addr, PrefixLen} | decode_components(Rest)];
decode_components(<<16#21, Addr:16/binary, PrefixLen:8, Rest/binary>>) ->
    [{ipv6_local, Addr, PrefixLen} | decode_components(Rest)];
decode_components(<<16#23, Addr:16/binary, PrefixLen:8, Rest/binary>>) ->
    [{ipv6_remote, Addr, PrefixLen} | decode_components(Rest)];
decode_components(<<16#24, Addr:16/binary, PrefixLen:8, Rest/binary>>) ->
    [{ipv6_local, Addr, PrefixLen} | decode_components(Rest)];
decode_components(<<16#30, ProtoId:8, Rest/binary>>) ->
    [{protocol, ProtoId} | decode_components(Rest)];
decode_components(<<16#40, Port:16, Rest/binary>>) ->
    [{local_port, Port} | decode_components(Rest)];
decode_components(<<16#41, Low:16, High:16, Rest/binary>>) ->
    [{local_port_range, Low, High} | decode_components(Rest)];
decode_components(<<16#50, Port:16, Rest/binary>>) ->
    [{remote_port, Port} | decode_components(Rest)];
decode_components(<<16#51, Low:16, High:16, Rest/binary>>) ->
    [{remote_port_range, Low, High} | decode_components(Rest)];
decode_components(<<16#60, SPI:32, Rest/binary>>) ->
    [{security_parameter_index, SPI} | decode_components(Rest)];
decode_components(<<16#70, TOS:8, Mask:8, Rest/binary>>) ->
    [{tos_traffic_class, TOS, Mask} | decode_components(Rest)];
decode_components(<<16#80, _:4, Label:20, Rest/binary>>) ->
    [{flow_label, Label} | decode_components(Rest)].

%%%===================================================================
%%% Internal — component encoding
%%%===================================================================

encode_components(Components) ->
    iolist_to_binary([encode_component(C) || C <- Components]).

encode_component({ipv4_remote, Addr, Mask}) ->
    <<16#10, Addr/binary, Mask/binary>>;
encode_component({ipv4_local, Addr, Mask}) ->
    <<16#11, Addr/binary, Mask/binary>>;
encode_component({ipv6_remote, Addr, PrefixLen}) ->
    <<16#20, Addr/binary, PrefixLen:8>>;
encode_component({ipv6_local, Addr, PrefixLen}) ->
    <<16#21, Addr/binary, PrefixLen:8>>;
encode_component({protocol, ProtoId}) ->
    <<16#30, ProtoId:8>>;
encode_component({local_port, Port}) ->
    <<16#40, Port:16>>;
encode_component({local_port_range, Low, High}) ->
    <<16#41, Low:16, High:16>>;
encode_component({remote_port, Port}) ->
    <<16#50, Port:16>>;
encode_component({remote_port_range, Low, High}) ->
    <<16#51, Low:16, High:16>>;
encode_component({security_parameter_index, SPI}) ->
    <<16#60, SPI:32>>;
encode_component({tos_traffic_class, TOS, Mask}) ->
    <<16#70, TOS:8, Mask:8>>;
encode_component({flow_label, Label}) ->
    <<16#80, 0:4, Label:20>>.

%%%===================================================================
%%% Internal — parameters decoding/encoding
%%%===================================================================

decode_parameters(0, _) -> [];
decode_parameters(1, Data) -> decode_params(Data, []).

decode_params(<<>>, Acc) -> lists:reverse(Acc);
decode_params(<<Id:8, Len:8, Content:Len/binary, Rest/binary>>, Acc) ->
    decode_params(Rest, [{Id, Content} | Acc]).

encode_parameters([]) -> <<>>;
encode_parameters(Params) ->
    iolist_to_binary([<<Id:8, (byte_size(Content)):8, Content/binary>> || {Id, Content} <- Params]).

%%%===================================================================
%%% Internal — flow info conversion
%%%===================================================================

flow_info_list_to_filters([], _, _) -> [];
flow_info_list_to_filters([FlowInfo | Rest], Index, Precedence) ->
    Filter = flow_info_to_filter(FlowInfo, Index, Precedence),
    [Filter | flow_info_list_to_filters(Rest, Index + 1, Precedence - 1)].

flow_info_to_filter(FlowInfo, Index, Precedence) ->
    Id = get_filter_id(FlowInfo, Index),
    Direction = get_flow_direction(FlowInfo),
    BaseComponents = get_flow_components(FlowInfo),
    ExtraComponents = get_extra_components(FlowInfo),
    Components = BaseComponents ++ ExtraComponents,
    #{id => Id, direction => Direction, precedence => Precedence, components => Components}.

get_filter_id(#{'Packet-Filter-Identifier' := [IdBin | _]}, _Index) when is_binary(IdBin) ->
    case IdBin of
	<<Id:8>> -> Id band 16#0F;
	_        -> 0
    end;
get_filter_id(_, Index) ->
    Index band 16#0F.

get_flow_direction(#{'Flow-Direction' := [Dir | _]}) ->
    case Dir of
	0 -> bidirectional;
	1 -> downlink;
	2 -> uplink;
	3 -> bidirectional;
	_ -> bidirectional
    end;
get_flow_direction(_) ->
    bidirectional.

get_flow_components(#{'Flow-Description' := [Desc | _]}) ->
    {_Dir, Components} = parse_flow_description(Desc),
    Components;
get_flow_components(_) ->
    [].

get_extra_components(FlowInfo) ->
    TOS = case FlowInfo of
	      #{'ToS-Traffic-Class' := [<<T:8, M:8>> | _]} ->
		  [{tos_traffic_class, T, M}];
	      _ -> []
	  end,
    SPI = case FlowInfo of
	      #{'Security-Parameter-Index' := [<<S:32>> | _]} ->
		  [{security_parameter_index, S}];
	      _ -> []
	  end,
    FL = case FlowInfo of
	     #{'Flow-Label' := [<<_:4, L:20>> | _]} ->
		 [{flow_label, L}];
	     _ -> []
	 end,
    TOS ++ SPI ++ FL.

filter_to_flow_info(#{id := Id, direction := Direction,
		      precedence := _Precedence, components := Components}) ->
    FlowDir = case Direction of
		  downlink      -> 1;
		  uplink        -> 2;
		  bidirectional -> 3;
		  pre_rel7      -> 3
	      end,
    Desc = format_flow_description({direction_to_flow_dir(Direction), Components}),
    Base = #{'Flow-Description' => [Desc],
	     'Flow-Direction' => [FlowDir],
	     'Packet-Filter-Identifier' => [<<Id:8>>]},
    add_optional_avps(Components, Base).

direction_to_flow_dir(downlink)      -> out;
direction_to_flow_dir(uplink)        -> in;
direction_to_flow_dir(bidirectional) -> out;
direction_to_flow_dir(pre_rel7)      -> out.

add_optional_avps([], Map) -> Map;
add_optional_avps([{tos_traffic_class, T, M} | Rest], Map) ->
    add_optional_avps(Rest, Map#{'ToS-Traffic-Class' => [<<T:8, M:8>>]});
add_optional_avps([{security_parameter_index, SPI} | Rest], Map) ->
    add_optional_avps(Rest, Map#{'Security-Parameter-Index' => [<<SPI:32>>]});
add_optional_avps([{flow_label, L} | Rest], Map) ->
    add_optional_avps(Rest, Map#{'Flow-Label' => [<<0:4, L:20>>]});
add_optional_avps([_ | Rest], Map) ->
    add_optional_avps(Rest, Map).

%%%===================================================================
%%% Internal — flow description parsing
%%%===================================================================

parse_flow_desc_tokens([_Permit, DirBin | Rest]) ->
    Direction = case DirBin of
		    <<"in">>  -> in;
		    <<"out">> -> out;
		    _         -> out
		end,
    Components = parse_proto_and_addrs(Rest, Direction),
    {Direction, Components}.

parse_proto_and_addrs([ProtoBin, <<"from">>, FromAddr | Rest], Direction) ->
    Proto = parse_protocol(ProtoBin),
    {FromPorts, AfterFromPorts} = parse_optional_ports(Rest),
    {ToAddr, ToPorts} = parse_to_clause(AfterFromPorts),
    ProtoComponents = case Proto of
			  any -> [];
			  N   -> [{protocol, N}]
		      end,
    %% Direction semantics:
    %% "out" (downlink): from=remote, to=local(UE)
    %% "in" (uplink): from=local(UE), to=remote
    AddrComponents = case Direction of
			 out ->
			     remote_addr_components(FromAddr) ++
				 local_addr_components(ToAddr) ++
				 remote_port_components(FromPorts) ++
				 local_port_components(ToPorts);
			 in ->
			     local_addr_components(FromAddr) ++
				 remote_addr_components(ToAddr) ++
				 local_port_components(FromPorts) ++
				 remote_port_components(ToPorts)
		     end,
    ProtoComponents ++ AddrComponents.

parse_optional_ports([<<"to">> | _] = Tokens) ->
    {[], Tokens};
parse_optional_ports([PortStr | Rest] = Tokens) ->
    case parse_port_spec(PortStr) of
	{ok, PortSpec} -> {PortSpec, Rest};
	error          -> {[], Tokens}
    end;
parse_optional_ports([]) ->
    {[], []}.

parse_to_clause([<<"to">>, ToAddr | Rest]) ->
    {PortSpec, _} = parse_optional_ports(Rest),
    {ToAddr, PortSpec};
parse_to_clause([<<"to">> | []]) ->
    {<<"any">>, []};
parse_to_clause(_) ->
    {<<"any">>, []}.

parse_port_spec(Bin) ->
    case binary:split(Bin, <<"-">>) of
	[Low, High] ->
	    case {catch binary_to_integer(Low), catch binary_to_integer(High)} of
		{L, H} when is_integer(L), is_integer(H) -> {ok, {range, L, H}};
		_ -> error
	    end;
	[Single] ->
	    case catch binary_to_integer(Single) of
		N when is_integer(N) -> {ok, {single, N}};
		_ -> error
	    end
    end.

remote_addr_components(<<"any">>)      -> [];
remote_addr_components(<<"assigned">>) -> [];
remote_addr_components(AddrBin) ->
    case parse_ip_prefix(AddrBin) of
	{ipv4, Addr, Mask}         -> [{ipv4_remote, Addr, Mask}];
	{ipv6, Addr, PrefixLen}    -> [{ipv6_remote, Addr, PrefixLen}];
	error                      -> []
    end.

local_addr_components(<<"any">>)      -> [];
local_addr_components(<<"assigned">>) -> [];
local_addr_components(AddrBin) ->
    case parse_ip_prefix(AddrBin) of
	{ipv4, Addr, Mask}         -> [{ipv4_local, Addr, Mask}];
	{ipv6, Addr, PrefixLen}    -> [{ipv6_local, Addr, PrefixLen}];
	error                      -> []
    end.

remote_port_components([]) -> [];
remote_port_components({single, P}) -> [{remote_port, P}];
remote_port_components({range, L, H}) -> [{remote_port_range, L, H}].

local_port_components([]) -> [];
local_port_components({single, P}) -> [{local_port, P}];
local_port_components({range, L, H}) -> [{local_port_range, L, H}].

parse_ip_prefix(Bin) ->
    case binary:split(Bin, <<"/">>) of
	[AddrBin, PrefixBin] ->
	    Prefix = binary_to_integer(PrefixBin),
	    parse_ip_with_prefix(AddrBin, Prefix);
	[AddrBin] ->
	    parse_ip_with_prefix(AddrBin, undefined)
    end.

parse_ip_with_prefix(AddrBin, Prefix) ->
    Str = binary_to_list(AddrBin),
    case inet:parse_address(Str) of
	{ok, {A, B, C, D}} ->
	    Addr = <<A, B, C, D>>,
	    Mask = prefix_to_mask4(case Prefix of undefined -> 32; P -> P end),
	    {ipv4, Addr, Mask};
	{ok, {A, B, C, D, E, F, G, H}} ->
	    Addr = <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>,
	    PLen = case Prefix of undefined -> 128; P -> P end,
	    {ipv6, Addr, PLen};
	_ ->
	    error
    end.

prefix_to_mask4(Prefix) when Prefix >= 0, Prefix =< 32 ->
    Shift = 32 - Prefix,
    Mask = ((16#FFFFFFFF bsr Shift) bsl Shift) band 16#FFFFFFFF,
    <<Mask:32>>.

parse_protocol(<<"ip">>)  -> any;
parse_protocol(<<"tcp">>) -> 6;
parse_protocol(<<"udp">>) -> 17;
parse_protocol(Bin) ->
    case catch binary_to_integer(Bin) of
	N when is_integer(N), N >= 0 -> N;
	_ -> any
    end.

%%%===================================================================
%%% Internal — flow description formatting
%%%===================================================================

extract_components(Components) ->
    extract_components(Components, undefined, undefined, undefined, undefined, undefined, []).

extract_components([], Proto, RemAddr, RemPorts, LocAddr, LocPorts, Extras) ->
    {Proto, RemAddr, RemPorts, LocAddr, LocPorts, lists:reverse(Extras)};
extract_components([{protocol, P} | Rest], _, RemAddr, RemPorts, LocAddr, LocPorts, Extras) ->
    extract_components(Rest, P, RemAddr, RemPorts, LocAddr, LocPorts, Extras);
extract_components([{ipv4_remote, Addr, Mask} | Rest], Proto, _, RemPorts, LocAddr, LocPorts, Extras) ->
    extract_components(Rest, Proto, {ipv4, Addr, Mask}, RemPorts, LocAddr, LocPorts, Extras);
extract_components([{ipv6_remote, Addr, PLen} | Rest], Proto, _, RemPorts, LocAddr, LocPorts, Extras) ->
    extract_components(Rest, Proto, {ipv6, Addr, PLen}, RemPorts, LocAddr, LocPorts, Extras);
extract_components([{ipv4_local, Addr, Mask} | Rest], Proto, RemAddr, RemPorts, _, LocPorts, Extras) ->
    extract_components(Rest, Proto, RemAddr, RemPorts, {ipv4, Addr, Mask}, LocPorts, Extras);
extract_components([{ipv6_local, Addr, PLen} | Rest], Proto, RemAddr, RemPorts, _, LocPorts, Extras) ->
    extract_components(Rest, Proto, RemAddr, RemPorts, {ipv6, Addr, PLen}, LocPorts, Extras);
extract_components([{remote_port, P} | Rest], Proto, RemAddr, _, LocAddr, LocPorts, Extras) ->
    extract_components(Rest, Proto, RemAddr, {single, P}, LocAddr, LocPorts, Extras);
extract_components([{remote_port_range, L, H} | Rest], Proto, RemAddr, _, LocAddr, LocPorts, Extras) ->
    extract_components(Rest, Proto, RemAddr, {range, L, H}, LocAddr, LocPorts, Extras);
extract_components([{local_port, P} | Rest], Proto, RemAddr, RemPorts, LocAddr, _, Extras) ->
    extract_components(Rest, Proto, RemAddr, RemPorts, LocAddr, {single, P}, Extras);
extract_components([{local_port_range, L, H} | Rest], Proto, RemAddr, RemPorts, LocAddr, _, Extras) ->
    extract_components(Rest, Proto, RemAddr, RemPorts, LocAddr, {range, L, H}, Extras);
extract_components([C | Rest], Proto, RemAddr, RemPorts, LocAddr, LocPorts, Extras) ->
    extract_components(Rest, Proto, RemAddr, RemPorts, LocAddr, LocPorts, [C | Extras]).

format_protocol(undefined) -> <<"ip">>;
format_protocol(any)       -> <<"ip">>;
format_protocol(6)         -> <<"tcp">>;
format_protocol(17)        -> <<"udp">>;
format_protocol(N) when is_integer(N) -> integer_to_binary(N).

format_addr(undefined)        -> <<"any">>;
format_addr({ipv4, Addr, Mask}) ->
    PrefixLen = mask4_to_prefix(Mask),
    AddrStr = inet:ntoa(binary_to_tuple4(Addr)),
    iolist_to_binary([AddrStr, <<"/">>, integer_to_binary(PrefixLen)]);
format_addr({ipv6, Addr, PLen}) ->
    AddrStr = inet:ntoa(binary_to_tuple6(Addr)),
    iolist_to_binary([AddrStr, <<"/">>, integer_to_binary(PLen)]).

format_addr_ports(Addr, Ports) ->
    AddrStr = case Addr of
		  <<"assigned">> -> <<"assigned">>;
		  <<"any">>      -> <<"any">>;
		  _              -> format_addr(Addr)
	      end,
    case Ports of
	undefined     -> AddrStr;
	{single, P}   -> <<AddrStr/binary, " ", (integer_to_binary(P))/binary>>;
	{range, L, H} -> <<AddrStr/binary, " ",
			   (integer_to_binary(L))/binary, "-",
			   (integer_to_binary(H))/binary>>
    end.

format_extras([]) -> [];
format_extras(Extras) ->
    [format_extra(E) || E <- Extras].

format_extra({tos_traffic_class, TOS, Mask}) ->
    iolist_to_binary([<<"tos ">>, integer_to_binary(TOS), <<" ">>, integer_to_binary(Mask)]);
format_extra({security_parameter_index, SPI}) ->
    iolist_to_binary([<<"spi ">>, integer_to_binary(SPI)]);
format_extra({flow_label, L}) ->
    iolist_to_binary([<<"flow-label ">>, integer_to_binary(L)]);
format_extra(_) ->
    <<>>.

mask4_to_prefix(<<Mask:32>>) ->
    popcount32(Mask).

popcount32(0) -> 0;
popcount32(N) -> (N band 1) + popcount32(N bsr 1).

binary_to_tuple4(<<A, B, C, D>>) -> {A, B, C, D}.

binary_to_tuple6(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {A, B, C, D, E, F, G, H}.
