%% Copyright 2017,2018, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(complex_SUITE).

%% Common Test callbacks
-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eradius/include/eradius_lib.hrl").
-include_lib("eradius/include/dictionary.hrl").
-include_lib("eradius/include/dictionary_ituma.hrl").
-include_lib("diameter/include/diameter.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include("../include/diameter_3gpp_ts32_299.hrl").
-include("../include/diameter_3gpp_ts32_299_rf.hrl").
-include("../include/smf_aaa_session.hrl").
-include("smf_aaa_test_lib.hrl").

-define(HUT, smf_aaa_rf).
-define(SERVICE, <<"combined-test">>).
%% -define(SERVICE, <<"aaa-test">>).

-define('Origin-Host', <<"127.0.0.1">>).
-define('Origin-Realm', <<"example.com">>).

-define(STATIC_CONFIG,
	#{defaults =>
	      #{'NAS-Identifier'  => <<"NAS">>,
		'Framed-Protocol' => 'PPP',
		'Service-Type'    => 'Framed-User'}}).

-define(RADIUS_CONFIG,
	#{server =>
	      #{host => {127,0,0,1},
		port => 1812,
		secret => <<"secret">>}}).

-define(DIAMETER_TRANSPORT,
	#{connect_to => <<"aaa://127.0.0.1">>}).

-define(DIAMETER_FUNCTION,
	#{?SERVICE =>
	      #{handler => smf_aaa_diameter,
		'Origin-Host' => ?'Origin-Host',
		'Origin-Realm' => ?'Origin-Realm',
		transports => [?DIAMETER_TRANSPORT]}}).

-define(DIAMETER_RF_CONFIG,
	#{function => ?SERVICE,
	  'Destination-Realm' => <<"test-srv.example.com">>}).

-define(CONFIG,
	%% #{rate_limits =>
	%%       #{default => #{outstanding_requests => 50, rate => 1000}},
	#{rate_limits =>
	      #{default => #{outstanding_requests => 3, rate => 20}},
	  functions => ?DIAMETER_FUNCTION,
	  handlers =>
	      #{smf_aaa_static => ?STATIC_CONFIG,
		smf_aaa_radius => ?RADIUS_CONFIG,
		smf_aaa_rf => ?DIAMETER_RF_CONFIG},
	  services =>
	      #{<<"Default">> =>
		    #{handler => 'smf_aaa_static'},
		<<"Rf">> =>
		    #{handler => 'smf_aaa_rf'},
		<<"RADIUS-Auth">> =>
		    #{handler => 'smf_aaa_radius',
		      server =>
			  #{host => {127,0,0,1},
			    port => 1812,
			    secret => <<"secret">>}},
		<<"RADIUS-Acct">> =>
		    #{handler => 'smf_aaa_radius',
		      server =>
			  #{host => {127,0,0,1},
			    port => 1813,
			    secret => <<"secret">>}}},
	  apps =>
	      #{default =>
		    #{'Origin-Host' => <<"dummy.host">>,
		      procedures =>
			  #{init => [#{service => <<"Default">>}],
			    authenticate => [#{service => <<"RADIUS-Auth">>}],
			    authorize    => [#{service => <<"RADIUS-Auth">>}],
			    start        => [#{service => <<"RADIUS-Acct">>}],
			    interim      => [#{service => <<"RADIUS-Acct">>}],
			    stop         => [#{service => <<"RADIUS-Acct">>}],
			    {rf, 'Initial'}   => [#{service => <<"Rf">>}],
			    {rf, 'Update'}    => [#{service => <<"Rf">>}],
			    {rf, 'Terminate'} => [#{service => <<"Rf">>}]
			  }
	            }
	      }
       }).



%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [radius_rf_tdv_crash
    ].

init_per_suite(Config0) ->
    Config = [{handler_under_test, ?HUT} | Config0],

    application:load(smf_aaa),
    smf_aaa_test_lib:clear_app_env(),

    eradius_test_handler:start(),

    meck_init(Config),

    diameter_test_server:start(),
    {ok, _} = application:ensure_all_started(smf_aaa),
    smf_aaa_test_lib:smf_aaa_init(?CONFIG),

    case wait_for_diameter(?SERVICE, 10) of
	ok ->
	    Config;
	Other ->
	    end_per_suite(Config),
	    {skip, Other}
    end.

end_per_suite(Config) ->
    meck_unload(Config),
    eradius_test_handler:stop(),
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
	  '3GPP-Charging-Id'        => 3604013806,
	  '3GPP-IMSI-MCC-MNC'       => {<<"259">>,<<"99">>},
	  '3GPP-GGSN-MCC-MNC'       => {<<"258">>,<<"88">>},
	  '3GPP-MS-TimeZone'        => {128,1},
	  '3GPP-MSISDN'             => <<"46702123456">>,
	  '3GPP-NSAPI'              => 5,
	  '3GPP-PDP-Type'           => 'IPv4',
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
	  'Calling-Station-Id'      => <<"543148000012345">>,
	  'Framed-IP-Address'       => {10,106,14,227},
	  'Framed-Protocol'         => 'GPRS-PDP-Context',
	  'Multi-Session-Id'        => 1012552258277823040188863251876666193415858290601,
	  'Username'                => <<"smf">>,
	  'Password'                => <<"smf">>,
	  'Service-Type'            => 'Framed-User',
	  'Node-Id'                 => <<"PGW-001">>,
	  'PDP-Context-Type'        => primary,
	  'Charging-Rule-Base-Name' => <<"m2m0001">>,

	  '3GPP-GPRS-Negotiated-QoS-Profile' =>   <<11,146,31,147,150,64,64,255,
						    255,255,255,17,1,1,64,64>>,
	  '3GPP-Allocation-Retention-Priority' => 2,
	  '3GPP-Charging-Characteristics' =>      <<8,0>>,

	  'QoS-Information' =>
	      #{
		'QoS-Class-Identifier' => 255,
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

radius_rf_tdv_crash() ->
    [{doc, "Rf session with in octets clashing with the TDVs"}].
radius_rf_tdv_crash(Config) ->
    CustomSession = #{'3GPP-IMSI' => <<"999999999999999">>,
		      'Framed-IP-Address' => {10,10,10,10},
		      'Framed-IPv6-Prefix' => {{16#fe80,0,0,0,0,0,0,0}, 64},
		      'Framed-Pool' => <<"pool-A">>,
		      'Framed-IPv6-Pool' => <<"pool-A">>,
		      'Framed-Interface-Id' => {0,0,0,0,0,0,0,1}},
    Session = init_session(CustomSession, Config),
    Stats0 = get_stats(?SERVICE),

    SOpts = #{now => erlang:monotonic_time()},
    AAA0 = smf_aaa_session:new(Session),
    {ok, AAA1, _} =
	smf_aaa_session:call(AAA0, #{}, start, SOpts),
    {_, AAA2, _} = smf_aaa_session:call(AAA1, #{}, {rf, 'Initial'}, SOpts),

    %% ?equal([{smf_aaa_rf, started, 1}], get_session_stats()),

    {ok, AAA3, Events} = smf_aaa_session:call(AAA2, #{}, authenticate, []),
    SOut = smf_aaa_session:get_session(AAA3),
    ?match(#{'MS-Primary-DNS-Server' := {8,8,8,8}}, SOut),
    ?match(#{'Framed-MTU' := 1500}, SOut),

    %% ?equal(0, get_session_stats(smf_aaa_radius, started)),

    ?match([{set, {{accounting, 'IP-CAN', periodic}, {periodic, 'IP-CAN', 1800, []}}}],
	   Events),
    {ok, AAA4, _} = smf_aaa_session:call(AAA3, #{}, authorize, []),
    {ok, AAA5, _} = smf_aaa_session:call(AAA4, #{}, start, []),

    ?equal(1, get_session_stats(smf_aaa_radius, started)),

    SDC0 =
	[#{'Rating-Group'             => 3000,
	   'Accounting-Input-Octets'  => 1092,
	   'Accounting-Output-Octets' => 0,
	   'Change-Condition'         => 4,
	   'Change-Time'              => {{2018,11,30},{12,22,00}},
	   'Time-First-Usage'         => {{2018,11,30},{12,20,00}},
	   'Time-Last-Usage'          => {{2018,11,30},{12,21,00}},
	   'Time-Usage'               => 60}
	],

    TD0 =
	[#{'3GPP-Charging-Id' => [123456],
	   'Accounting-Input-Octets' => [1],
	   'Accounting-Output-Octets' => [2],
	   'Change-Condition' => [4],
	   'Change-Time'      => [{{2020,2,20},{12,30,00}}]},
	  #{'3GPP-Charging-Id' => [123456],
	   'Accounting-Input-Octets' => [1],
	   'Accounting-Output-Octets' => [2],
	   'Change-Condition' => [0],
	   'Change-Time'      => [{{2020,2,20},{12,34,00}}]}],

    SDC1 =
	[#{'Rating-Group'             => 3000,
	   'Accounting-Input-Octets'  => 1092,
	   'Accounting-Output-Octets' => 0,
	   'Change-Condition'         => 4,
	   'Change-Time'              => {{2018,11,30},{13,22,00}},
	   'Time-First-Usage'         => {{2018,11,30},{13,20,00}},
	   'Time-Last-Usage'          => {{2018,11,30},{13,21,00}},
	   'Time-Usage'               => 60}
	],

    TD1 =
	[#{'3GPP-Charging-Id' => [123456],
	   'Accounting-Input-Octets' => [3],
	   'Accounting-Output-Octets' => [4],
	   'Change-Condition' => [4],
	   'Change-Time'      => [{{2020,2,20},{13,30,00}}]},
	  #{'3GPP-Charging-Id' => [123456],
	   'Accounting-Input-Octets' => [3],
	   'Accounting-Output-Octets' => [4],
	   'Change-Condition' => [0],
	   'Change-Time'      => [{{2020,2,20},{13,34,00}}]}],

    SDC2 =
	[#{'Rating-Group'             => 3000,
	   'Accounting-Input-Octets'  => 2092,
	   'Accounting-Output-Octets' => 0,
	   'Change-Condition'         => 4,
	   'Change-Time'              => {{2018,11,30},{14,22,00}},
	   'Time-First-Usage'         => {{2018,11,30},{14,20,00}},
	   'Time-Last-Usage'          => {{2018,11,30},{14,21,00}},
	   'Time-Usage'               => 60}
	],

    TD2 =
	[#{'3GPP-Charging-Id' => [123456],
	   'Accounting-Input-Octets' => [5],
	   'Accounting-Output-Octets' => [6],
	   'Change-Condition' => [4],
	   'Change-Time'      => [{{2020,2,20},{14,30,00}}]},
	  #{'3GPP-Charging-Id' => [123456],
	   'Accounting-Input-Octets' => [5],
	   'Accounting-Output-Octets' => [6],
	   'Change-Condition' => [0],
	   'Change-Time'      => [{{2020,2,20},{14,34,00}}]}],

    RfUpdCont1 = #{service_data => SDC0, traffic_data => TD0},
    %% RfUpdCDR1  = #{service_data => SDC1, traffic_data => TD1},
    RfUpdCont2 = #{service_data => SDC2, traffic_data => TD2},
    %% The diameter server discards any request with this IMSI
    {_, AAA6, _} =
	smf_aaa_session:call(AAA5, RfUpdCont1, {rf, 'Update'},
				SOpts#{'gy_event' => container_closure}),
    %% ?equal([{smf_aaa_rf, started, 1}], get_session_stats()),

    %% The diameter server discards any request with this IMSI
    {_, AAA7, _} =
	smf_aaa_session:call(AAA6, RfUpdCont2, {rf, 'Update'},
				SOpts#{'gy_event' => container_closure}),

    %% We ensure the session has several TDVs so the In/OutOctets from_session clause crashes
%%     {_, _, _} =
%% 	smf_aaa_session:call(AAA7, RfUpdCDR1, {rf, 'Update'},
%% 				SOpts#{'gy_event' => cdr_closure}),

    InterimData = #{
	'InPackets' => 10,
	'OutPackets' => 20,
	'InOctets' => 100,
	'OutOctets' => 200},
    {ok, AAA8, _} = smf_aaa_session:call(AAA7, InterimData, interim, []),

    %% ?equal([{smf_aaa_rf, started, 1}], get_session_stats()),

    %% The diameter server discards any request with this IMSI
    {_, AAA9, _} =
	smf_aaa_session:call(AAA8, RfUpdCont2, {rf, 'Update'},
				SOpts#{'gy_event' => container_closure}),

    RfTerm = #{'Termination-Cause' => ?'DIAMETER_BASE_TERMINATION-CAUSE_LOGOUT',
	       service_data => SDC2, traffic_data => TD2},
    {_, AAA10, _} = smf_aaa_session:call(AAA9, #{}, stop, SOpts),
    {_, AAA11, _} =
	smf_aaa_session:call(AAA10, RfTerm, {rf, 'Terminate'}, SOpts),

    %% ?equal([{smf_aaa_rf, started, 0}], get_session_stats()),

    Stats1 = diff_stats(Stats0, get_stats(?SERVICE)),
    ct:pal("Stats: ~p~n", [Stats1]),
    %% ?equal(4, proplists:get_value({{3, 271, 0}, recv, {'Result-Code',2001}}, Stats1)),

    TermOpts = #{'Termination-Cause' => ?'DIAMETER_BASE_TERMINATION-CAUSE_LOGOUT'},
    {ok, _AAA12, _} = smf_aaa_session:call(AAA11, TermOpts, stop, []),

    ?equal(0, get_session_stats(smf_aaa_radius, started)),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

%%%===================================================================
%%% Generic helpers
%%%===================================================================

stats('ACR') -> {3, 271, 1};
stats('ACA') -> {3, 271, 0};
stats(Tuple) when is_tuple(Tuple) ->
    setelement(1, Tuple, stats(element(1, Tuple)));
stats(V) -> V.
