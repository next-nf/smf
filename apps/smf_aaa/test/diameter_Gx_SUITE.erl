%% Copyright 2017,2018, Travelping GmbH <info@travelping.com>
%%
%% This program is free software: you can redistribute it and/or modify
%% it under the terms of the GNU Lesser General Public License as
%% published by the Free Software Foundation, either version 3 of the
%% License, or (at your option) any later version.
%%
%% This program is distributed in the hope that it will be useful,
%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
%% GNU Lesser General Public License for more details.
%%
%% You should have received a copy of the GNU Lesser General Public License
%% along with this program. If not, see <http://www.gnu.org/licenses/>.

-module(diameter_Gx_SUITE).

-compile([nowarn_export_all, export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("diameter/include/diameter.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include("../include/diameter_3gpp_ts29_212.hrl").
-include("../include/smf_aaa_session.hrl").
-include("smf_aaa_test_lib.hrl").

-define(HUT, smf_aaa_gx).
-define(SERVICE, <<"smf_aaa_gx">>).
-define(API, gx).

-define('Origin-Host', <<"127.0.0.1">>).
-define('Origin-Realm', <<"example.com">>).

-define(STATIC_CONFIG,
	#{defaults =>
	      #{'NAS-Identifier'  => <<"NAS">>,
		'Framed-Protocol' => 'PPP',
		'Service-Type'    => 'Framed-User'}}).

-define(DIAMETER_TRANSPORT,
	#{connect_to => <<"aaa://127.0.0.1">>}).

-define(DIAMETER_FUNCTION,
	#{?SERVICE =>
	      #{handler => smf_aaa_diameter,
		'Origin-Host' => ?'Origin-Host',
		'Origin-Realm' => ?'Origin-Realm',
		transports => [?DIAMETER_TRANSPORT]}}).

-define(DIAMETER_CONFIG,
	#{function => ?SERVICE,
	  'Destination-Realm' => <<"test-srv.example.com">>}).

-define(CONFIG,
	#{functions => ?DIAMETER_FUNCTION,
	  handlers =>
	      #{smf_aaa_static => ?STATIC_CONFIG,
		smf_aaa_nasreq => ?DIAMETER_CONFIG,
		smf_aaa_gx => ?DIAMETER_CONFIG},
	  services =>
	      #{<<"Default">> =>
		    #{handler => 'smf_aaa_static'},
		<<"NASREQ">> =>
		    #{handler => 'smf_aaa_nasreq'},
		<<"Gx">> =>
		    #{handler => 'smf_aaa_gx'}
	       },
	  apps =>
	      #{default =>
		    #{'Origin-Host' => <<"dummy.host">>,
		      procedures =>
			  #{init => [#{service => <<"Default">>}],
			    authenticate => [],
			    authorize => [],
			    start => [#{service => <<"NASREQ">>}],
			    interim => [#{service => <<"NASREQ">>}],
			    stop => [#{service => <<"NASREQ">>}],
			    {gx, 'CCR-Initial'}   => [#{service => <<"Gx">>}],
			    {gx, 'CCR-Update'}    => [#{service => <<"Gx">>}],
			    {gx, 'CCR-Terminate'} => [#{service => <<"Gx">>}]}
		    }
	      }
	}).

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [
     simple_session,
     abort_session_request,
     handle_failure,
     handle_answer_error,
     re_auth_request,
     terminate,
     packet_filter_delete_encoding,
     packet_filter_add_wire_roundtrip
    ].

init_per_suite(Config0) ->
    Config = [{handler_under_test, ?HUT} | Config0],

    application:load(smf_aaa),
    smf_aaa_test_lib:clear_app_env(),

    meck_init(Config),

    diameter_test_server:start_nasreq(),
    {ok, _} = application:ensure_all_started(smf_aaa),
    smf_aaa_test_lib:smf_aaa_init(?CONFIG),

    case wait_for_diameter(?SERVICE, 10) of
	ok ->
	    Config;
	Other ->
	    end_per_suite(Config),
	    ct:fail(Other)
    end.

end_per_suite(Config) ->
    meck_unload(Config),
    application:stop(prometheus),
    application:stop(smf_aaa),
    application:unload(smf_aaa),
    diameter_test_server:stop(),
    ok.

init_per_testcase(_, Config) ->
    reset_session_stats(),
    meck_reset(Config),
    Config.

end_per_testcase(_, _Config) ->
    ok.

%%%===================================================================
%%% Helper
%%%===================================================================

init_session(Session, _Config) ->
    Defaults =
	#{
	  '3GPP-GGSN-Address'       => {172,20,16,28},
	  '3GPP-IMEISV'             => <<82,21,50,96,32,80,30,0>>,
	  '3GPP-IMSI'               => <<"250071234567890">>,
	  %% '3GPP-Charging-Id'        => 3604013806,
	  %% '3GPP-IMSI-MCC-MNC'       => {<<"259">>,<<"99">>},
	  %% '3GPP-GGSN-MCC-MNC'       => {<<"258">>,<<"88">>},
	  '3GPP-MS-TimeZone'        => {128,1},
	  '3GPP-MSISDN'             => <<"46702123456">>,
	  %% '3GPP-NSAPI'              => 5,
	  %% '3GPP-PDP-Type'           => 'IPv4',
	  '3GPP-RAT-Type'           => 6,
	  '3GPP-SGSN-Address'       => {192,168,1,1},
	  '3GPP-SGSN-MCC-MNC'       => {<<"262">>,<<"01">>},
	  '3GPP-Selection-Mode'     => 0,
	  'User-Location-Info' =>
	      #{'ext-macro-eNB' =>
		    #ext_macro_enb{plmn_id = {<<"001">>, <<"001">>},
				   id = rand:uniform(16#1fffff)},
		'TAI' =>
		    #tai{plmn_id = {<<"001">>, <<"001">>},
			 tac = rand:uniform(16#ffff)}},
	  'Called-Station-Id'       => <<"some.station.gprs">>,
	  %% 'Calling-Station-Id'      => <<"543148000012345">>,
	  'Framed-IP-Address'       => {10,106,14,227},
	  %% 'Framed-Protocol'         => 'GPRS-PDP-Context',
	  %% 'Multi-Session-Id'        => 1012552258277823040188863251876666193415858290601,
	  %% 'Username'                => <<"smf">>,
	  %% 'Password'                => <<"smf">>,
	  %% 'Service-Type'            => 'Framed-User',
	  %% 'Node-Id'                 => <<"PGW-001">>,
	  %% 'PDP-Context-Type'        => primary,
	  %% 'Charging-Rule-Base-Name' => <<"m2m0001">>,

	  %% '3GPP-GPRS-Negotiated-QoS-Profile' =>   <<11,146,31,147,150,64,64,255,
	  %% 					    255,255,255,17,1,1,64,64>>,
	  %% '3GPP-Allocation-Retention-Priority' => 2,
	  %% '3GPP-Charging-Characteristics' =>  <<8,0>>

	  'QoS-Information' =>
	      #{
		'QoS-Class-Identifier' => 8,
		'Max-Requested-Bandwidth-DL' => 0,
		'Max-Requested-Bandwidth-UL' => 0,
		'Guaranteed-Bitrate-DL' => 0,
		'Guaranteed-Bitrate-UL' => 0,
		'Allocation-Retention-Priority' =>
		    #{'Priority-Level' => 10,
		      'Pre-emption-Capability' => 1,
		      'Pre-emption-Vulnerability' => 0},
		'APN-Aggregate-Max-Bitrate-DL' => 84000000,
		'APN-Aggregate-Max-Bitrate-UL' => 8640000
	       }
	 },
    maps:merge(Defaults, Session).

%%%===================================================================
%%% Test cases
%%%===================================================================

simple_session() ->
    [{doc, "Simple Gx session"}].
simple_session(Config) ->
    Session = init_session(#{}, Config),
    GxOpts =
	#{'3GPP-IMSI' => <<"IMSI">>},

    Stats0 = get_stats(?SERVICE),

    AAA0 = smf_aaa_session:new(Session),

    ?equal([], get_session_stats()),

    {ok, AAA1, Events1} =
	smf_aaa_session:call(AAA0, GxOpts, {gx, 'CCR-Initial'}, []),

    ?equal([{smf_aaa_gx, started, 1}], get_session_stats()),

    ?match([{pcc, install, [_|_]}], Events1),

    GxTerm =
	#{'Termination-Cause' => ?'DIAMETER_BASE_TERMINATION-CAUSE_LOGOUT'},
    {ok, _AAA2, _Events2} =
	smf_aaa_session:call(AAA1, GxTerm, {gx, 'CCR-Terminate'}, []),

    ?equal([{smf_aaa_gx, started, 0}], get_session_stats()),

    Statistics = diff_stats(Stats0, get_stats(?SERVICE)),

    % check that client has sent CCR
    ?equal(2, proplists:get_value({{16777238, 272, 1}, send}, Statistics)),
    % check that client has received CCA
    ?equal(2, proplists:get_value({{16777238, 272, 0}, recv, {'Result-Code',2001}}, Statistics)),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

abort_session_request() ->
    [{doc, "Stop Gx session with ASR"}].
abort_session_request(Config) ->
    Session = init_session(#{}, Config),
    GxOpts =
	#{'3GPP-IMSI' => <<"IMSI">>},

    Stats0 = get_stats(?SERVICE),
    StatsTestSrv0 = get_stats(diameter_test_server),

    AAA0 = smf_aaa_session:new(Session),

    {ok, AAA1, Events1} =
	smf_aaa_session:call(AAA0, GxOpts, {gx, 'CCR-Initial'}, []),

    ?equal([{smf_aaa_gx, started, 1}], get_session_stats()),

    ?match([{pcc, install, [_|_]}], Events1),

    Session1 = smf_aaa_session:get_session(AAA1),
    SessionId = maps:get('Diameter-Session-Id', Session1),
    ?equal(ok, diameter_test_server:abort_session_request(gx, SessionId, ?'Origin-Host', ?'Origin-Realm')),

    ?equal([{smf_aaa_gx, started, 1}], get_session_stats()),

    receive
	#aaa_request{from = {Pid, Ref}, procedure = {?API, 'ASR'}} ->
	    Pid ! {Ref, {ok, #{}}}
    after 1000 ->
	    ct:fail("no ASR")
    end,

    GxTerm = #{'Termination-Cause' => ?'DIAMETER_BASE_TERMINATION-CAUSE_LOGOUT'},
    {ok, _AAA2, _Events2} =
	smf_aaa_session:call(AAA1, GxTerm, {gx, 'CCR-Terminate'}, []),

    ?equal([{smf_aaa_gx, started, 0}], get_session_stats()),

    Stats1 = diff_stats(Stats0, get_stats(?SERVICE)),
    StatsTestSrv = diff_stats(StatsTestSrv0, get_stats(diameter_test_server)),

    %% check that client has recieved CCA
    ?equal(2, proplists:get_value({{16777238, 272, 0}, recv, {'Result-Code',2001}}, Stats1)),

    %% check that client has send ACA
    ?equal(1, proplists:get_value({{16777238, 274, 0}, send, {'Result-Code',2001}}, Stats1)),

    %% check that test server has recieved ACA
    ?equal(1, proplists:get_value({{16777238, 274, 0}, recv, {'Result-Code',2001}},
				  StatsTestSrv)),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

handle_failure(Config) ->
    Session = init_session(#{}, Config),
    GxOpts =
	#{'3GPP-IMSI' => <<"FAIL">>,
	  '3GPP-MSISDN' => <<"FAIL">>},

    Stats0 = get_stats(?SERVICE),

    AAA0 = smf_aaa_session:new(Session),

    ?match({{fail, 3001}, _, _},
	   smf_aaa_session:call(AAA0, GxOpts, {gx, 'CCR-Initial'}, [])),

    ?equal([], get_session_stats()),

    Statistics = diff_stats(Stats0, get_stats(?SERVICE)),

    % check that client has sent CCR
    ?equal(1, proplists:get_value({{16777238, 272, 1}, send}, Statistics)),
    % check that client has received CCA
    ?equal(1, proplists:get_value({{16777238, 272, 0}, recv, {'Result-Code',3001}}, Statistics)),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

handle_answer_error(Config) ->
    Session = init_session(#{}, Config),
    GxOpts =
	#{'3GPP-IMSI' => <<"FAIL-BROKEN-ANSWER">>,
	  '3GPP-MSISDN' => <<"FAIL-BROKEN-ANSWER">>},

    AAA0 = smf_aaa_session:new(Session),
    ?match({{error, 3007}, _, _},
	   smf_aaa_session:call(AAA0, GxOpts, {gx, 'CCR-Initial'}, [])),

    ?equal([], get_session_stats()),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

re_auth_request() ->
    [{doc, "Send a Re-Auth-Request (RAR) on the Gx session"}].
re_auth_request(Config) ->
    Session = init_session(#{}, Config),
    GxOpts =
	#{'3GPP-IMSI' => <<"noCheck">>},

    Stats0 = get_stats(?SERVICE),
    StatsTestSrv0 = get_stats(diameter_test_server),

    AAA0 = smf_aaa_session:new(Session),

    {ok, AAA1, Events1} =
	smf_aaa_session:call(AAA0, GxOpts, {gx, 'CCR-Initial'}, []),
    ?match([{pcc, install, [_|_]}], Events1),

    ?equal([{smf_aaa_gx, started, 1}], get_session_stats()),

    RAROpts =
	#{'Charging-Rule-Remove' => [],
	  'Charging-Rule-Install' => []},

    Session1 = smf_aaa_session:get_session(AAA1),
    SessionId = maps:get('Diameter-Session-Id', Session1),
    ?equal(ok, diameter_test_server:re_auth_request(gx, SessionId,
						    ?'Origin-Host', ?'Origin-Realm',
						    RAROpts)),

    receive
	#aaa_request{from = {Pid1, Ref1}, procedure = {?API, 'RAR'} = Proc1,
		     handler = Handler1, session = Avps1} ->
	    {_, Events} = Handler1:to_session(Proc1, {Session1, []}, Avps1),
	    ?match([{pcc, install, [#{'Charging-Rule-Name' := [<<"service01">>]}]}],
		   Events),
	    Pid1 ! {Ref1, {ok, #{}}}
    after 1000 ->
	    ct:fail("no RAR")
    end,

    ?equal([{smf_aaa_gx, started, 1}], get_session_stats()),

    ?equal(ok, diameter_test_server:re_auth_request(gx, SessionId,
						    ?'Origin-Host', ?'Origin-Realm',
						    RAROpts)),
    AAA2 =
	receive
	    #aaa_request{from = {Pid2, Ref2}, procedure = {?API, 'RAR'} = Proc2,
			 handler = Handler2, session = Avps2} ->
		{_, Evs2} = Handler2:to_session(Proc2, {Session1, []}, Avps2),
		?match([{pcc, install, [#{'Charging-Rule-Name' := [<<"service01">>]}]}],
		       Evs2),
		%% check that the session is not blocked for other DIAMETER Apps
		{ok, AAA1a, _} = smf_aaa_session:call(AAA1, #{}, start, []),

		?equal([{smf_aaa_gx, started, 1}, {smf_aaa_nasreq, started, 1}], get_session_stats()),

		{ok, AAA1b, _} = smf_aaa_session:call(AAA1a, #{}, interim, []),

		?equal([{smf_aaa_gx, started, 1}, {smf_aaa_nasreq, started, 1}], get_session_stats()),

		{ok, AAA1c, _} = smf_aaa_session:call(AAA1b, #{}, stop, []),

		?equal([{smf_aaa_gx, started, 1}, {smf_aaa_nasreq, started, 0}], get_session_stats()),

		Pid2 ! {Ref2, {ok, #{}}},
		AAA1c
	after 1000 ->
	    ct:fail("no RAR")
    end,

    GxTerm = #{'Termination-Cause' => ?'DIAMETER_BASE_TERMINATION-CAUSE_LOGOUT'},
    {ok, _AAA3, _Events2} =
	smf_aaa_session:call(AAA2, GxTerm, {gx, 'CCR-Terminate'}, []),

    ?equal([{smf_aaa_gx, started, 0}, {smf_aaa_nasreq, started, 0}], get_session_stats()),

    Stats1 = diff_stats(Stats0, get_stats(?SERVICE)),
    StatsTestSrv = diff_stats(StatsTestSrv0, get_stats(diameter_test_server)),

    %% check that client has recieved CCA
    ?equal(2, proplists:get_value({{16777238, 272, 0}, recv, {'Result-Code',2001}}, Stats1)),

    %% check that client has send RAA
    ?equal(2, proplists:get_value({{16777238, 258, 0}, send, {'Result-Code',2001}}, Stats1)),

    %% check that test server has recieved RAA
    ?equal(2, proplists:get_value({{16777238, 258, 0}, recv, {'Result-Code',2001}},
				  StatsTestSrv)),

    %% NASREQ ACA
    ?equal(3, proplists:get_value({{1, 271, 0}, recv, {'Result-Code',2001}}, Stats1)),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

terminate() ->
    [{doc, "Simulate unexpected owner termination"}].
terminate(Config) ->
    Session = init_session(#{}, Config),
    GxOpts =
	#{'3GPP-IMSI' => <<"IMSI">>},

    Stats0 = get_stats(?SERVICE),

    AAA0 = smf_aaa_session:new(Session),

    ?equal([], get_session_stats()),

    {ok, AAA1, _} = smf_aaa_session:call(AAA0, GxOpts, {gx, 'CCR-Initial'}, []),
    ?equal([{smf_aaa_gx, started, 1}], get_session_stats()),

    smf_aaa_session:terminate_action(AAA1),
    wait_for_session(smf_aaa_gx, started, 0, 10),

    Statistics = diff_stats(Stats0, get_stats(?SERVICE)),

    % check that client has sent CCR
    ?equal(2, proplists:get_value(stats({'CCR', send}), Statistics)),
    % check that client has received CCA
    ?equal(2, proplists:get_value(stats({'CCA', recv, {'Result-Code', 2001}}), Statistics)),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

handle_3xxx_error_async() ->
    [{doc, "Error translation in async calls"}].
handle_3xxx_error_async(Config) ->
    Session = init_session(#{}, Config),
    GxOpts =
	#{'3GPP-IMSI' => <<"FAIL-RC-3002">>,
	  '3GPP-MSISDN' => <<"FAIL-RC-3002">>
	 },

    AAA0 = smf_aaa_session:new(Session),
    {{fail, 3002}, _AAA1, Events1} =
	smf_aaa_session:call(AAA0, GxOpts, {gx, 'CCR-Initial'}, #{}),
    ?equal([{stop,{gx,peer_reject}}], Events1),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

packet_filter_delete_encoding() ->
    [{doc, "Packet-Filter-Operation/Information encode into CCR AVPs"}].
packet_filter_delete_encoding(_Config) ->
    Session = #{'Packet-Filter-Operation' =>
                    ?'DIAMETER_GX_PACKET-FILTER-OPERATION_DELETION',
                'Packet-Filter-Information' =>
                    [#{'Packet-Filter-Identifier' => <<16#0A>>},
                     #{'Packet-Filter-Identifier' => <<16#0B>>}]},
    Avps = smf_aaa_gx:from_session(Session, #{}),
    #{'Packet-Filter-Operation' := [0]} = Avps,
    #{'Packet-Filter-Information' :=
          [#{'Packet-Filter-Identifier' := <<16#0A>>},
           #{'Packet-Filter-Identifier' := <<16#0B>>}]} = Avps,
    ok.

packet_filter_add_wire_roundtrip() ->
    [{doc, "flow_info_to_pf_add_group/1's output survives a REAL diameter "
	   "encode/decode through the Gx dictionary (not just the mock "
	   "AVP-map-building path from_session/2 exercises)"}].
packet_filter_add_wire_roundtrip(_Config) ->
    Mod = diameter_3gpp_ts29_212,
    %% a flow-info map as filter_to_flow_info/1 produces
    FI = #{'Flow-Description' => [<<"permit out ip from any to assigned">>],
           'Flow-Direction' => [2],
           'Precedence' => [100],
           'Packet-Filter-Identifier' => [<<3:8>>]},
    Group = smf_tft:flow_info_to_pf_add_group(FI),

    Avps = #{'Session-Id' => <<"test;1;2">>,
             'Origin-Host' => <<"host.example.com">>,
             'Origin-Realm' => <<"example.com">>,
             'Destination-Realm' => <<"dest.example.com">>,
             'Auth-Application-Id' => Mod:id(),
             'CC-Request-Type' => 1,
             'CC-Request-Number' => 0,
             'Packet-Filter-Information' => [Group]},

    %% encode() and decode() go all the way through the generated diameter
    %% dictionary's codec — an actual binary wire encoding, not the mock
    %% path (from_session/2 alone, as packet_filter_delete_encoding tests).
    Pkt = diameter_codec:encode(Mod, ['CCR' | Avps]),
    true = is_binary(Pkt#diameter_packet.bin),

    DecPkt = diameter_codec:decode(Mod, #{decode_format => map,
					  string_decode => false},
				   Pkt#diameter_packet.bin),
    ?equal([], DecPkt#diameter_packet.errors),

    ['CCR' | DecAvps] = DecPkt#diameter_packet.msg,
    #{'Packet-Filter-Information' := [DecGroup]} = DecAvps,

    %% content, precedence and direction survive the wire. diameter's map
    %% decode format list-wraps optional (0-1 arity) grouped members — the
    %% same convention filter_to_flow_info/1 already uses — regardless of
    %% whether the encode-side map presented them bare or list-wrapped.
    #{'Packet-Filter-Content' := [<<"permit out ip from any to assigned">>],
      'Precedence' := [100],
      'Flow-Direction' := [2]} = DecGroup,
    %% the UE's TFT filter id is still omitted on the wire
    false = maps:is_key('Packet-Filter-Identifier', DecGroup),
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

stats('CCR') -> {16777238, 272, 1};
stats('CCA') -> {16777238, 272, 0};
stats(Tuple) when is_tuple(Tuple) ->
    setelement(1, Tuple, stats(element(1, Tuple)));
stats(V) -> V.
