%% Copyright 2024, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(smf_tft_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [encode_decode_empty,
     encode_decode_single_filter,
     encode_decode_multi_filter,
     encode_decode_ipv6,
     encode_decode_port_ranges,
     encode_decode_all_components,
     encode_decode_delete_filters,
     encode_decode_parameters,
     parse_flow_description_simple,
     parse_flow_description_ipv4,
     parse_flow_description_ipv6,
     parse_flow_description_port_range,
     parse_flow_description_assigned,
     format_flow_description_roundtrip,
     flow_info_to_tft_single,
     flow_info_to_tft_multi,
     flow_info_to_tft_downlink_only_adds_uplink,
     flow_info_to_tft_uplink_present_unchanged,
     flow_info_to_tft_unique_ids,
     tft_to_flow_info_roundtrip,
     decode_tad_operations,
     flow_info_to_tft_map_no_sdf,
     flow_info_to_tft_map_captures_sdf,
     flow_info_to_tft_map_bare_binary_sdf].

init_per_suite(Config) -> Config.
end_per_suite(_Config) -> ok.

%%%===================================================================
%%% Test cases
%%%===================================================================

%%--------------------------------------------------------------------
encode_decode_empty() ->
    [{doc, "Empty TFT with delete_existing_tft operation"}].
encode_decode_empty(_Config) ->
    TFT = #{operation => delete_existing_tft, filters => [], parameters => []},
    Bin = smf_tft:encode(TFT),
    Decoded = smf_tft:decode(Bin),
    ?assertEqual(TFT, Decoded).

%%--------------------------------------------------------------------
encode_decode_single_filter() ->
    [{doc, "Single filter with IPv4 remote, TCP protocol, and remote port"}].
encode_decode_single_filter(_Config) ->
    Filter = #{id => 1,
	       direction => downlink,
	       precedence => 100,
	       components => [
		   {ipv4_remote, <<10, 0, 0, 1>>, <<255, 255, 255, 255>>},
		   {protocol, 6},
		   {remote_port, 80}
	       ]},
    TFT = #{operation => create_new_tft, filters => [Filter], parameters => []},
    Bin = smf_tft:encode(TFT),
    Decoded = smf_tft:decode(Bin),
    ?assertEqual(TFT, Decoded).

%%--------------------------------------------------------------------
encode_decode_multi_filter() ->
    [{doc, "Multiple filters with various component types"}].
encode_decode_multi_filter(_Config) ->
    Filter1 = #{id => 0,
		direction => downlink,
		precedence => 255,
		components => [
		    {ipv4_remote, <<10, 0, 0, 1>>, <<255, 255, 255, 255>>},
		    {protocol, 6},
		    {remote_port, 80}
		]},
    Filter2 = #{id => 1,
		direction => uplink,
		precedence => 200,
		components => [
		    {ipv4_remote, <<192, 168, 1, 0>>, <<255, 255, 255, 0>>},
		    {protocol, 17},
		    {remote_port, 443}
		]},
    TFT = #{operation => create_new_tft, filters => [Filter1, Filter2], parameters => []},
    Bin = smf_tft:encode(TFT),
    Decoded = smf_tft:decode(Bin),
    ?assertEqual(TFT, Decoded).

%%--------------------------------------------------------------------
encode_decode_ipv6() ->
    [{doc, "IPv6 address components"}].
encode_decode_ipv6(_Config) ->
    Addr = <<32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
    Filter = #{id => 2,
	       direction => bidirectional,
	       precedence => 150,
	       components => [
		   {ipv6_remote, Addr, 64},
		   {protocol, 6}
	       ]},
    TFT = #{operation => add_packet_filters, filters => [Filter], parameters => []},
    Bin = smf_tft:encode(TFT),
    Decoded = smf_tft:decode(Bin),
    ?assertEqual(TFT, Decoded).

%%--------------------------------------------------------------------
encode_decode_port_ranges() ->
    [{doc, "Local and remote port ranges"}].
encode_decode_port_ranges(_Config) ->
    Filter = #{id => 3,
	       direction => downlink,
	       precedence => 50,
	       components => [
		   {local_port_range, 1024, 65535},
		   {remote_port_range, 80, 443}
	       ]},
    TFT = #{operation => replace_packet_filters, filters => [Filter], parameters => []},
    Bin = smf_tft:encode(TFT),
    Decoded = smf_tft:decode(Bin),
    ?assertEqual(TFT, Decoded).

%%--------------------------------------------------------------------
encode_decode_all_components() ->
    [{doc, "One filter with every component type"}].
encode_decode_all_components(_Config) ->
    Addr4 = <<10, 0, 0, 1>>,
    Mask4 = <<255, 255, 255, 255>>,
    Addr6 = <<32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
    Filter = #{id => 0,
	       direction => bidirectional,
	       precedence => 128,
	       components => [
		   {ipv4_remote, Addr4, Mask4},
		   {ipv4_local, <<192, 168, 1, 1>>, <<255, 255, 255, 255>>},
		   {ipv6_remote, Addr6, 128},
		   {ipv6_local, <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>, 128},
		   {protocol, 6},
		   {local_port, 12345},
		   {local_port_range, 10000, 20000},
		   {remote_port, 80},
		   {remote_port_range, 443, 8443},
		   {security_parameter_index, 16#DEADBEEF},
		   {tos_traffic_class, 16#B8, 16#FC},
		   {flow_label, 16#12345}
	       ]},
    TFT = #{operation => create_new_tft, filters => [Filter], parameters => []},
    Bin = smf_tft:encode(TFT),
    Decoded = smf_tft:decode(Bin),
    ?assertEqual(TFT, Decoded).

%%--------------------------------------------------------------------
encode_decode_delete_filters() ->
    [{doc, "Operation 5: delete filters by ID only"}].
encode_decode_delete_filters(_Config) ->
    Filters = [#{id => 0, direction => bidirectional, precedence => 0, components => []},
	       #{id => 3, direction => bidirectional, precedence => 0, components => []},
	       #{id => 7, direction => bidirectional, precedence => 0, components => []}],
    TFT = #{operation => delete_packet_filters, filters => Filters, parameters => []},
    Bin = smf_tft:encode(TFT),
    Decoded = smf_tft:decode(Bin),
    ?assertEqual(TFT, Decoded).

%%--------------------------------------------------------------------
encode_decode_parameters() ->
    [{doc, "TFT with E bit set and parameters"}].
encode_decode_parameters(_Config) ->
    Filter = #{id => 0,
	       direction => downlink,
	       precedence => 100,
	       components => [{protocol, 6}]},
    Params = [{1, <<1, 2, 3>>}, {2, <<4, 5>>}],
    TFT = #{operation => create_new_tft, filters => [Filter], parameters => Params},
    Bin = smf_tft:encode(TFT),
    Decoded = smf_tft:decode(Bin),
    ?assertEqual(TFT, Decoded).

%%--------------------------------------------------------------------
parse_flow_description_simple() ->
    [{doc, "permit out ip from any to any — no components"}].
parse_flow_description_simple(_Config) ->
    {Dir, Components} = smf_tft:parse_flow_description(<<"permit out ip from any to any">>),
    ?assertEqual(out, Dir),
    ?assertEqual([], Components).

%%--------------------------------------------------------------------
parse_flow_description_ipv4() ->
    [{doc, "permit out 6 from 10.0.0.1 to 192.168.1.0/24 80"}].
parse_flow_description_ipv4(_Config) ->
    {Dir, Components} =
	smf_tft:parse_flow_description(<<"permit out 6 from 10.0.0.1 to 192.168.1.0/24 80">>),
    ?assertEqual(out, Dir),
    %% For "out": from=remote, to=local(UE)
    %% protocol 6 = TCP
    %% from 10.0.0.1 = ipv4_remote (with /32 mask)
    %% to 192.168.1.0/24 = ipv4_local
    %% 80 after "to" address = local_port
    ?assert(lists:member({protocol, 6}, Components)),
    ?assert(lists:member({ipv4_remote, <<10, 0, 0, 1>>, <<255, 255, 255, 255>>}, Components)),
    ?assert(lists:member({ipv4_local, <<192, 168, 1, 0>>, <<255, 255, 255, 0>>}, Components)),
    ?assert(lists:member({local_port, 80}, Components)).

%%--------------------------------------------------------------------
parse_flow_description_ipv6() ->
    [{doc, "IPv6 addresses in flow description"}].
parse_flow_description_ipv6(_Config) ->
    {Dir, Components} =
	smf_tft:parse_flow_description(<<"permit out 6 from 2001:db8::1 to any">>),
    ?assertEqual(out, Dir),
    %% For "out": from=remote
    ?assert(lists:member({protocol, 6}, Components)),
    %% 2001:db8::1 with /128 (no prefix given)
    ExpAddr = <<32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
    ?assert(lists:member({ipv6_remote, ExpAddr, 128}, Components)).

%%--------------------------------------------------------------------
parse_flow_description_port_range() ->
    [{doc, "permit in 17 from any 1000-2000 to any — local_port_range since 'in' = uplink"}].
parse_flow_description_port_range(_Config) ->
    {Dir, Components} =
	smf_tft:parse_flow_description(<<"permit in 17 from any 1000-2000 to any">>),
    ?assertEqual(in, Dir),
    %% For "in" (uplink): from=local(UE), so port after from = local_port_range
    ?assert(lists:member({protocol, 17}, Components)),
    ?assert(lists:member({local_port_range, 1000, 2000}, Components)).

%%--------------------------------------------------------------------
parse_flow_description_assigned() ->
    [{doc, "permit out ip from 10.0.0.1 to assigned — only ipv4_remote, no local addr"}].
parse_flow_description_assigned(_Config) ->
    {Dir, Components} =
	smf_tft:parse_flow_description(<<"permit out ip from 10.0.0.1 to assigned">>),
    ?assertEqual(out, Dir),
    %% "assigned" = UE IP, omitted
    ?assert(lists:member({ipv4_remote, <<10, 0, 0, 1>>, <<255, 255, 255, 255>>}, Components)),
    %% no ipv4_local component
    ?assertNot(lists:any(fun({ipv4_local, _, _}) -> true; (_) -> false end, Components)).

%%--------------------------------------------------------------------
format_flow_description_roundtrip() ->
    [{doc, "parse then format produces equivalent result"}].
format_flow_description_roundtrip(_Config) ->
    Desc = <<"permit out 6 from 10.0.0.1/32 to assigned 80">>,
    Parsed = smf_tft:parse_flow_description(Desc),
    Formatted = smf_tft:format_flow_description(Parsed),
    %% Re-parse the formatted version and compare components
    ReParsed = smf_tft:parse_flow_description(Formatted),
    {Dir1, Comp1} = Parsed,
    {Dir2, Comp2} = ReParsed,
    ?assertEqual(Dir1, Dir2),
    ?assertEqual(lists:sort(Comp1), lists:sort(Comp2)).

%%--------------------------------------------------------------------
flow_info_to_tft_single() ->
    [{doc, "Single Flow-Information map produces valid TFT binary"}].
flow_info_to_tft_single(_Config) ->
    FlowInfo = #{'Flow-Description' =>
		     [<<"permit out 6 from 10.0.0.1 to assigned 80">>],
		 'Flow-Direction' => [1],
		 'Packet-Filter-Identifier' => [<<1>>]},
    Bin = smf_tft:flow_info_to_tft([FlowInfo]),
    ?assert(is_binary(Bin)),
    %% Decode and verify structure
    #{operation := Op, filters := Filters} = smf_tft:decode(Bin),
    ?assertEqual(create_new_tft, Op),
    %% Downlink-only input gains an appended uplink disallow filter
    ?assertEqual(2, length(Filters)),
    [#{components := Comps}] = [F || #{direction := downlink} = F <- Filters],
    ?assert(lists:member({protocol, 6}, Comps)),
    ?assert(lists:member({ipv4_remote, <<10, 0, 0, 1>>, <<255, 255, 255, 255>>}, Comps)).

%%--------------------------------------------------------------------
flow_info_to_tft_multi() ->
    [{doc, "Multiple Flow-Information maps produce multi-filter TFT"}].
flow_info_to_tft_multi(_Config) ->
    FlowInfo1 = #{'Flow-Description' =>
		      [<<"permit out 6 from 10.0.0.1 to assigned 80">>],
		  'Flow-Direction' => [1]},
    FlowInfo2 = #{'Flow-Description' =>
		      [<<"permit out 17 from 10.0.0.2 to assigned 53">>],
		  'Flow-Direction' => [1]},
    Bin = smf_tft:flow_info_to_tft([FlowInfo1, FlowInfo2]),
    #{operation := Op, filters := Filters} = smf_tft:decode(Bin),
    ?assertEqual(create_new_tft, Op),
    %% Two downlink filters plus the appended uplink disallow filter
    ?assertEqual(3, length(Filters)),
    [F1, F2, _Uplink] = Filters,
    %% Precedence decrements: first = 255, second = 254
    ?assertEqual(255, maps:get(precedence, F1)),
    ?assertEqual(254, maps:get(precedence, F2)).

%%--------------------------------------------------------------------
flow_info_to_tft_downlink_only_adds_uplink() ->
    [{doc, "Downlink-only flow info gets an uplink disallow filter appended "
      "(TS 23.401 5.4.5 / TS 23.060 15.3.3.4)"}].
flow_info_to_tft_downlink_only_adds_uplink(_Config) ->
    FlowInfo1 = #{'Flow-Description' =>
		      [<<"permit out 6 from 10.0.0.1 to assigned 80">>],
		  'Flow-Direction' => [1]},
    FlowInfo2 = #{'Flow-Description' =>
		      [<<"permit out 17 from 10.0.0.2 to assigned 53">>],
		  'Flow-Direction' => [1]},
    Bin = smf_tft:flow_info_to_tft([FlowInfo1, FlowInfo2]),
    #{operation := Op, filters := Filters} = smf_tft:decode(Bin),
    ?assertEqual(create_new_tft, Op),
    %% Two downlink filters plus the appended uplink disallow filter
    ?assertEqual(3, length(Filters)),
    UplinkFilters = [F || #{direction := D} = F <- Filters,
			  D =:= uplink orelse D =:= bidirectional],
    ?assertEqual(1, length(UplinkFilters)),
    [Uplink] = UplinkFilters,
    ?assertEqual(uplink, maps:get(direction, Uplink)),
    %% remote port 9 (discard) — TS 23.060 §15.3.3.4, independent of IP version
    ?assertEqual([{remote_port, 9}], maps:get(components, Uplink)),
    %% id must not collide with the two downlink filters (ids 0 and 1)
    Ids = [maps:get(id, F) || F <- Filters],
    ?assertEqual(lists:usort(Ids), lists:sort(Ids)).

%%--------------------------------------------------------------------
flow_info_to_tft_uplink_present_unchanged() ->
    [{doc, "A TFT already containing an uplink/bidirectional filter gets no "
      "spurious extra filter"}].
flow_info_to_tft_uplink_present_unchanged(_Config) ->
    %% One downlink, one uplink flow — already uplink-applicable
    FlowInfoDl = #{'Flow-Description' =>
		       [<<"permit out 6 from 10.0.0.1 to assigned 80">>],
		   'Flow-Direction' => [1]},
    FlowInfoUl = #{'Flow-Description' =>
		       [<<"permit in 17 from assigned to 10.0.0.2 53">>],
		   'Flow-Direction' => [2]},
    Bin = smf_tft:flow_info_to_tft([FlowInfoDl, FlowInfoUl]),
    #{filters := Filters} = smf_tft:decode(Bin),
    ?assertEqual(2, length(Filters)),
    %% no disallow filter (remote port 9) was added
    ?assertNot(lists:any(
		 fun(#{components := Comps}) ->
			 lists:member({remote_port, 9}, Comps)
		 end, Filters)),
    %% a bidirectional-only flow is also uplink-applicable — no extra filter
    FlowInfoBi = #{'Flow-Description' =>
		       [<<"permit out 6 from 10.0.0.3 to assigned 22">>],
		   'Flow-Direction' => [3]},
    BinBi = smf_tft:flow_info_to_tft([FlowInfoBi]),
    #{filters := FiltersBi} = smf_tft:decode(BinBi),
    ?assertEqual(1, length(FiltersBi)).

%%--------------------------------------------------------------------
flow_info_to_tft_unique_ids() ->
    [{doc, "The PGW assigns the TFT packet filter ids itself, unique within "
      "the TFT (TS 23.401 5.4.5), ignoring any Gx Packet-Filter-Identifier in "
      "the flow info (TS 29.212 5.3.55 — a separate per-UE SDF handle). Ensures "
      "no duplicate ids, which a UE would reject with #45 (TS 24.301 6.4.2.4)"}].
flow_info_to_tft_unique_ids(_Config) ->
    %% Flows carry assorted (and colliding/malformed) Gx Packet-Filter-Identifier
    %% values; the PGW must ignore them and assign its own unique 4-bit ids.
    Dl = fun(Dst) ->
		 <<"permit out 6 from ", Dst/binary, " to assigned 80">>
	 end,
    FlowA = #{'Flow-Description' => [Dl(<<"10.0.0.1">>)],
	      'Flow-Direction' => [1],
	      'Packet-Filter-Identifier' => [<<3>>]},
    FlowB = #{'Flow-Description' => [Dl(<<"10.0.0.2">>)],
	      'Flow-Direction' => [1]},
    FlowC = #{'Flow-Description' => [Dl(<<"10.0.0.3">>)],
	      'Flow-Direction' => [1]},
    FlowD = #{'Flow-Description' => [Dl(<<"10.0.0.4">>)],
	      'Flow-Direction' => [1]},
    FlowE = #{'Flow-Description' => [Dl(<<"10.0.0.5">>)],
	      'Flow-Direction' => [1],
	      'Packet-Filter-Identifier' => [<<17>>]},
    FlowF = #{'Flow-Description' => [Dl(<<"10.0.0.6">>)],
	      'Flow-Direction' => [1],
	      'Packet-Filter-Identifier' => [<<1, 2>>]},
    %% One uplink flow so no disallow filter is appended (deterministic count)
    FlowG = #{'Flow-Description' =>
		  [<<"permit in 17 from assigned to 10.0.0.7 53">>],
	      'Flow-Direction' => [2]},
    FlowInfo = [FlowA, FlowB, FlowC, FlowD, FlowE, FlowF, FlowG],
    Bin = smf_tft:flow_info_to_tft(FlowInfo),
    #{filters := Filters} = smf_tft:decode(Bin),
    ?assertEqual(7, length(Filters)),
    Ids = [maps:get(id, F) || F <- Filters],
    %% every id is a valid 4-bit value
    ?assert(lists:all(fun(N) -> N >= 0 andalso N =< 15 end, Ids)),
    %% all ids distinct — the core conformance property
    ?assertEqual(lists:usort(Ids), lists:sort(Ids)),
    %% PGW-assigned in order, ignoring the Gx Packet-Filter-Identifier values
    %% (<<3>>, out-of-range <<17>>, malformed <<1,2>>) present in the input
    ?assertEqual([0, 1, 2, 3, 4, 5, 6], Ids).

%%--------------------------------------------------------------------
tft_to_flow_info_roundtrip() ->
    [{doc, "flow_info_to_tft then tft_to_flow_info preserves essential data"}].
tft_to_flow_info_roundtrip(_Config) ->
    FlowInfoIn = [
	#{'Flow-Description' =>
	      [<<"permit out 6 from 10.0.0.1 to assigned 80">>],
	  'Flow-Direction' => [1],
	  'Packet-Filter-Identifier' => [<<1>>]},
	#{'Flow-Description' =>
	      [<<"permit out 17 from 10.0.0.2 to assigned 53">>],
	  'Flow-Direction' => [1],
	  'Packet-Filter-Identifier' => [<<2>>]}
    ],
    Bin = smf_tft:flow_info_to_tft(FlowInfoIn),
    FlowInfoOut = smf_tft:tft_to_flow_info(Bin),
    %% Two downlink inputs plus the appended uplink disallow filter
    ?assertEqual(length(FlowInfoIn) + 1, length(FlowInfoOut)),
    %% The two original downlink flows are preserved, plus one uplink flow
    DlFlows = [FI || FI <- FlowInfoOut, maps:get('Flow-Direction', FI) =:= [1]],
    UlFlows = [FI || FI <- FlowInfoOut, maps:get('Flow-Direction', FI) =:= [2]],
    ?assertEqual(2, length(DlFlows)),
    ?assertEqual(1, length(UlFlows)),
    %% Check that Flow-Description is present and non-empty
    lists:foreach(
      fun(FI) ->
	      [Desc] = maps:get('Flow-Description', FI),
	      ?assert(is_binary(Desc)),
	      ?assert(byte_size(Desc) > 0)
      end, FlowInfoOut).

%%--------------------------------------------------------------------
decode_tad_operations() ->
    [{doc, "decode_tad/1 exposes the operation code and the operation-dependent "
      "contents shape (TS 23.401 5.4.5 step 5): full-filter operations yield "
      "flow-info maps, delete_packet_filters yields packet filter ids"}].
decode_tad_operations(_Config) ->
    Filter1 = #{id => 2,
		direction => downlink,
		precedence => 100,
		components => [{ipv4_remote, <<10, 0, 0, 1>>, <<255, 255, 255, 255>>},
			       {protocol, 6},
			       {remote_port, 80}]},
    Filter2 = #{id => 5,
		direction => uplink,
		precedence => 90,
		components => [{ipv4_local, <<192, 168, 1, 1>>, <<255, 255, 255, 255>>},
			       {protocol, 17}]},

    %% create_new_tft — full filters come back as flow-info maps
    CreateBin = smf_tft:encode(#{operation => create_new_tft,
				 filters => [Filter1], parameters => []}),
    {create_new_tft, CreateContents} = smf_tft:decode_tad(CreateBin),
    ?assertEqual(1, length(CreateContents)),
    [CreateFlow] = CreateContents,
    ?assert(is_map(CreateFlow)),
    ?assertEqual([<<2>>], maps:get('Packet-Filter-Identifier', CreateFlow)),
    ?assertEqual([1], maps:get('Flow-Direction', CreateFlow)),
    ?assertMatch([_], maps:get('Flow-Description', CreateFlow)),

    %% add_packet_filters — also full filters -> flow-info maps
    AddBin = smf_tft:encode(#{operation => add_packet_filters,
			      filters => [Filter1, Filter2], parameters => []}),
    {add_packet_filters, AddContents} = smf_tft:decode_tad(AddBin),
    ?assertEqual(2, length(AddContents)),
    ?assert(lists:all(fun is_map/1, AddContents)),

    %% delete_packet_filters — contents are packet filter ids, not maps
    DelFilters = [#{id => 2, direction => bidirectional, precedence => 0, components => []},
		  #{id => 5, direction => bidirectional, precedence => 0, components => []}],
    DelBin = smf_tft:encode(#{operation => delete_packet_filters,
			      filters => DelFilters, parameters => []}),
    {delete_packet_filters, DelContents} = smf_tft:decode_tad(DelBin),
    ?assertEqual([2, 5], DelContents).

flow_info_to_tft_map_no_sdf() ->
    [{doc, "flow_info_to_tft_map returns an empty SDF map when no "
      "Packet-Filter-Identifier is present, and the same binary as flow_info_to_tft"}].
flow_info_to_tft_map_no_sdf(_Config) ->
    FlowInfo = [#{'Flow-Description' => [<<"permit out ip from any to assigned">>],
                  'Flow-Direction' => [1]}],
    {Bin, Filters, SdfToPf} = smf_tft:flow_info_to_tft_map(FlowInfo),
    ?assertEqual(smf_tft:flow_info_to_tft(FlowInfo), Bin),
    ?assertEqual(#{}, SdfToPf),
    ?assert(length(Filters) >= 1),
    ok.

flow_info_to_tft_map_captures_sdf() ->
    [{doc, "flow_info_to_tft_map maps each Gx Packet-Filter-Identifier (SDF id) "
      "to the TFT packet filter id assigned to that filter"}].
flow_info_to_tft_map_captures_sdf(_Config) ->
    FlowInfo = [#{'Flow-Description' => [<<"permit out ip from any to assigned">>],
                  'Flow-Direction' => [2],
                  'Packet-Filter-Identifier' => [<<"sdf-a">>]},
                #{'Flow-Description' => [<<"permit out ip from any to assigned">>],
                  'Flow-Direction' => [1],
                  'Packet-Filter-Identifier' => [<<"sdf-b">>]}],
    {_Bin, Filters, SdfToPf} = smf_tft:flow_info_to_tft_map(FlowInfo),
    %% both SDF ids present, each pointing at a real filter id
    ?assertEqual(2, map_size(SdfToPf)),
    Ids = [Id || #{id := Id} <- Filters],
    ?assert(lists:member(maps:get(<<"sdf-a">>, SdfToPf), Ids)),
    ?assert(lists:member(maps:get(<<"sdf-b">>, SdfToPf), Ids)),
    ok.

flow_info_to_tft_map_bare_binary_sdf() ->
    [{doc, "a bare-binary Packet-Filter-Identifier (not wrapped in a list) is captured"}].
flow_info_to_tft_map_bare_binary_sdf(_Config) ->
    FlowInfo = [#{'Flow-Description' => [<<"permit out ip from any to assigned">>],
                  'Flow-Direction' => [2],
                  'Packet-Filter-Identifier' => <<"sdf-x">>}],
    {_Bin, _Filters, SdfToPf} = smf_tft:flow_info_to_tft_map(FlowInfo),
    ?assertMatch(#{<<"sdf-x">> := _}, SdfToPf),
    ok.
