%% Copyright 2017-2020, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(diameter_nasreq_SUITE).

%% Common Test callbacks
-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include("../include/smf_aaa_session.hrl").
-include("smf_aaa_test_lib.hrl").

-define(HUT, smf_aaa_nasreq).
-define(SERVICE, <<"diam-test">>).
-define(API, nasreq).

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
	#{rate_limits =>
	      #{default => #{outstanding_requests => 10, rate => 1000}},
	  functions => ?DIAMETER_FUNCTION,
	  handlers =>
	      #{smf_aaa_static => ?STATIC_CONFIG,
		smf_aaa_nasreq => ?DIAMETER_CONFIG},
	  services =>
	      #{<<"Default">> =>
		    #{handler => 'smf_aaa_static'},
		<<"NASREQ">> =>
		    #{handler => 'smf_aaa_nasreq'}},
	  apps =>
	      #{default =>
		    #{'Origin-Host' => <<"dummy.host">>,
		      procedures =>
			  #{init => [#{service => <<"Default">>}],
			    authenticate => [#{service => <<"NASREQ">>}],
			    authorize => [#{service => <<"NASREQ">>}],
			    start => [#{service => <<"NASREQ">>}],
			    interim => [#{service => <<"NASREQ">>}],
			    stop => [#{service => <<"NASREQ">>}]
			  }
		    }
	      }
	 }).

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

common() ->
    [compat,
     simple,
     simple_tdf_userid,
     simple_normal_terminate,
     accounting,
     acct_interim_interval,
     attrs_3gpp,
     handle_failure,
     handle_answer_error,
     abort_session_request,
     terminate].

groups() ->
    [{coupled, [], common()},
     {split, [], common()}].

all() ->
    [{group, coupled},
     {group, split}].

init_per_suite(Config0) ->
    [{handler_under_test, ?HUT} | Config0].

end_per_suite(_Config) ->
    ok.

init_per_group(Group, Config) ->
    application:load(smf_aaa),
    smf_aaa_test_lib:clear_app_env(),

    AppConfig =
	case Group of
	    coupled -> set_cfg_value([handlers, smf_aaa_nasreq, accounting], coupled, ?CONFIG);
	    split   -> set_cfg_value([handlers, smf_aaa_nasreq, accounting], split, ?CONFIG);
	    _       -> ?CONFIG
	end,

    meck_init(Config),

    diameter_test_server:start_nasreq(),
    {ok, _} = application:ensure_all_started(smf_aaa),
    smf_aaa_test_lib:smf_aaa_init(AppConfig),

    case wait_for_diameter(?SERVICE, 10) of
	ok ->
	    Config;
	Other ->
	    end_per_group(Group, Config),
	    {skip, Other}
    end.

end_per_group(_Group, Config) ->
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
%%% Test cases
%%%===================================================================

compat() ->
    [{doc, "Check that the old API is still working"}].
compat(Config) ->
    Stats0 = get_stats(?SERVICE),

    AAA0 = smf_aaa_session:new(#{'Framed-IP-Address' => {10,10,10,10}}),
    {ok, AAA1, _} = smf_aaa_session:call(AAA0, #{}, authenticate, []),
    {ok, AAA2, _} = smf_aaa_session:call(AAA1, #{}, start, []),
    {ok, AAA3, _} = smf_aaa_session:call(AAA2, #{}, interim, []),
    {ok, _AAA4, _} = smf_aaa_session:call(AAA3, #{}, stop, []),

    Statistics = diff_stats(Stats0, get_stats(?SERVICE)),

    ct:pal("Statistics: ~p", [Statistics]),
    [?equal(Cnt, stats(Msg, Config, Statistics)) ||
	{Cnt, Msg} <- [{3, 'ACR'}, {3, {'ACA', 2001}}]],

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

simple() ->
    [{doc, "Simple NASREQ session"}].

simple(Config) ->
    simple(Config, #{'Termination-Cause' => ?'DIAMETER_BASE_TERMINATION-CAUSE_LOGOUT'}).

simple_tdf_userid() ->
    [{doc, "Simple NASREQ session with UserID info for TDF"}].

simple_tdf_userid(Config) ->
    simple_tdf_userid(Config, #{'Termination-Cause' => ?'DIAMETER_BASE_TERMINATION-CAUSE_LOGOUT'}).

simple_normal_terminate() ->
    [{doc, "Simple terminate NASREQ session with `normal` atom"}].

simple_normal_terminate(Config) ->
    simple(Config, #{'Termination-Cause' => normal}).

accounting() ->
    [{doc, "Check that we can successfully send ACR's and get ACA's"}].
accounting(Config) ->
    Stats0 = get_stats(?SERVICE),

    AAA0 = smf_aaa_session:new(#{'Framed-IP-Address' => {10,10,10,10}}),
    {ok, AAA1, _} = smf_aaa_session:call(AAA0, #{}, authenticate, []),
    {ok, AAA2, _} = smf_aaa_session:call(AAA1, #{}, start, []),

    ?equal([{smf_aaa_nasreq, started, 1}], get_session_stats()),

    {ok, AAA3, _} = smf_aaa_session:call(AAA2, #{}, interim, []),

    ?equal([{smf_aaa_nasreq, started, 1}], get_session_stats()),

    {ok, _AAA4, _} = smf_aaa_session:call(AAA3, #{}, stop, []),

    ?equal([{smf_aaa_nasreq, started, 0}], get_session_stats()),

    Statistics = diff_stats(Stats0, get_stats(?SERVICE)),

    ct:pal("Statistics: ~p", [Statistics]),
    % check that client has sent ACR/ACA
    [?equal(Cnt, stats(Msg, Config, Statistics)) ||
	{Cnt, Msg} <- [{3, 'ACR'}, {3, {'ACA', 2001}}]],

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

acct_interim_interval() ->
    [{doc, "test diameter provider can reset interim interval"
      "by data from ACA Acct-Interim-Interval"}].
acct_interim_interval(Config) ->
    Fun = fun(_, S) -> S end,
    AAA0 = smf_aaa_session:new(#{'Accouting-Update-Fun' => Fun}),
    {ok, AAA1, _} = smf_aaa_session:call(AAA0, #{}, authenticate, []),
    {ok, AAA2, Ev} = smf_aaa_session:call(AAA1, #{}, start, []),

    ?equal([{smf_aaa_nasreq, started, 1}], get_session_stats()),

    SessionOpts = smf_aaa_session:get_session(AAA2),
    ?match(#{'Session-Id' := _,
	     'Diameter-Session-Id' := _,
	     'Service-Type' := 'Framed-User',
	     'Framed-Protocol' := 'PPP'
	    }, SessionOpts),
    ?match([{set, {{accounting, 'IP-CAN', periodic},
		   {periodic, 'IP-CAN', 1, _}}}], Ev),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

attrs_3gpp() ->
    [{doc, "Check encoding of 3GPP attributes"}].
attrs_3gpp(Config) ->
    Attrs = #{
	      '3GPP-GGSN-Address'       => {199,255,4,125},
	      '3GPP-IMEISV'             => <<82,21,50,96,32,80,30,0>>,
	      '3GPP-IMSI'               => <<"250071234567890">>,
	      '3GPP-Charging-Id'        => 3604013806,
	      '3GPP-IMSI-MCC-MNC'       => {<<"259">>,<<"99">>},
	      '3GPP-GGSN-MCC-MNC'       => {<<"258">>,<<"88">>},
	      '3GPP-MS-TimeZone'        => {128,1},
	      '3GPP-NSAPI'              => 5,
	      '3GPP-PDP-Type'           => 'IPv4',
	      '3GPP-RAT-Type'           => 6,
	      '3GPP-SGSN-Address'       => {192,168,1,1},
	      '3GPP-SGSN-MCC-MNC'       => {<<"262">>,<<"01">>},
	      '3GPP-SGSN-IPv6-Address'  => {16#fd96, 16#dcd2, 16#efdb, 16#41c4, 0, 0, 0, 16#1000},
	      '3GPP-GGSN-IPv6-Address'  => {16#fd96, 16#dcd2, 16#efdb, 16#41c4, 0, 0, 0, 16#2000},
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
	      'Framed-IP-Address'       => {0,0,0,0},
	      'Framed-Protocol'         => 'GPRS-PDP-Context',
	      'Multi-Session-Id'        => 1012552258277823040188863251876666193415858290601,
	      'Password'                => <<"smf">>,
	      'Service-Type'            => 'Framed-User',
	      'Session-Id'              => 1012552258277823040188863251876666193415858290601,
	      'Username'                => <<"smf">>
	     },

    Stats0 = get_stats(?SERVICE),

    AAA0 = smf_aaa_session:new(Attrs),
    {ok, AAA1, _} = smf_aaa_session:call(AAA0, #{}, authenticate, [inc_session_id]),
    SessionAfterAuth = smf_aaa_session:get_session(AAA1),
    ?match(#{'MS-Primary-DNS-Server' := {1,2,3,4}, 'MS-Secondary-DNS-Server' := {5,6,7,8}}, SessionAfterAuth),
    ?match(#{'Framed-MTU' := 1500}, SessionAfterAuth),

    ?match({ok, _, _}, smf_aaa_session:call(AAA1, #{}, start, [])),

    ?equal([{smf_aaa_nasreq, started, 1}], get_session_stats()),

    Stats1 = diff_stats(Stats0, get_stats(?SERVICE)),
    ?equal(1, stats({'ACA', 2001}, Config, Stats1)),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

handle_failure(Config) ->
    SOpts = #{'Called-Station-Id' => <<"FAIL-RC-3007">>,
	      'Framed-IP-Address' => {10,10,10,10}},
    AAA0 = smf_aaa_session:new(SOpts),

    {{fail, 3007}, AAA1, _} = smf_aaa_session:call(AAA0, #{}, start, []),

    %% a accounting error is not treated as session stop
    ?equal([{smf_aaa_nasreq, started, 1}], get_session_stats()),

    ?match({{fail, 3007}, _, _}, smf_aaa_session:call(AAA1, #{}, stop, [])),

    ?equal([{smf_aaa_nasreq, started, 0}], get_session_stats()),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

handle_answer_error(Config) ->
    SOpts = #{'Called-Station-Id' => <<"FAIL-BROKEN-ANSWER">>,
	      'Framed-IP-Address' => {10,10,10,10}},
    AAA0 = smf_aaa_session:new(SOpts),

    {{error, 3007}, AAA1, _} = smf_aaa_session:call(AAA0, #{}, start, []),

    %% a accounting error is not treated as session stop
    ?equal([{smf_aaa_nasreq, started, 1}], get_session_stats()),

    ?match({{error, 3007}, _, _}, smf_aaa_session:call(AAA1, #{}, stop, [])),

    ?equal([{smf_aaa_nasreq, started, 0}], get_session_stats()),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

%%%===================================================================
%%% Helpers
%%%===================================================================

stats('AAR', _, Stats) ->
    proplists:get_value({{1, 265, 1}, send}, Stats);
stats({'AAA', RC}, _, Stats) ->
    proplists:get_value({{1, 265, 0}, recv, {'Result-Code', RC}}, Stats);
stats('STR', _, Stats) ->
    proplists:get_value({{1, 275, 1}, send}, Stats);
stats({'STA', RC}, _, Stats) ->
    proplists:get_value({{1, 275, 0}, recv, {'Result-Code', RC}}, Stats);
stats('ACR', Config, Stats) ->
    TCGProps = ?config(tc_group_properties, Config),
    AccAppId =
	case proplists:get_value(name, TCGProps) of
	    split -> 3;
	    _     -> 1
	end,
    proplists:get_value({{AccAppId, 271, 1}, send}, Stats);
stats({'ACA', RC}, Config, Stats) ->
    TCGProps = ?config(tc_group_properties, Config),
    AccAppId =
	case proplists:get_value(name, TCGProps) of
	    split -> 3;
	    _     -> 1
	end,
    proplists:get_value({{AccAppId, 271, 0}, recv, {'Result-Code', RC}}, Stats).

simple(Config, TermOpts) ->
    Stats0 = get_stats(?SERVICE),

    AAA0 = smf_aaa_session:new(
	     #{'Framed-IP-Address' => {10,10,10,10},
	       'Framed-IPv6-Prefix' => {{16#fe80,0,0,0,0,0,0,0}, 64},
	       'Framed-Pool' => <<"pool-A">>,
	       'Framed-IPv6-Pool' => <<"pool-A">>,
	       'NAT-Pool-Id' => <<"nat-A">>}),

    {ok, AAA1, Events} = smf_aaa_session:call(AAA0, #{}, authenticate, []),
    ?match([{set, {{accounting, 'IP-CAN', periodic}, {periodic, 'IP-CAN', 1800, []}}}],
	   Events),
    {ok, AAA2, _} = smf_aaa_session:call(AAA1, #{}, authorize, []),
    {ok, AAA3, _} = smf_aaa_session:call(AAA2, #{}, start, []),

    {ok, AAA4, _} = smf_aaa_session:call(AAA3, #{}, interim, []),

    ?equal([{smf_aaa_nasreq, started, 1}], get_session_stats()),

    {ok, _AAA5, _} = smf_aaa_session:call(AAA4, TermOpts, stop, []),

    ?equal([{smf_aaa_nasreq, started, 0}], get_session_stats()),

    Statistics = diff_stats(Stats0, get_stats(?SERVICE)),

    ct:pal("Statistics: ~p", [Statistics]),
    [?equal(Cnt, stats(Msg, Config, Statistics)) ||
	{Cnt, Msg} <- [{1, 'AAR'}, {1, {'AAA', 2001}},
		       {3, 'ACR'}, {3, {'ACA', 2001}},
		       {1, 'STR'}, {1, {'STA', 2001}}
		      ]],

    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

simple_tdf_userid(Config, TermOpts) ->
    Stats0 = get_stats(?SERVICE),
    Msisdn = ?MSISDN_FOR_IMEI_SV,
    Imsi = <<"250071234567890">>,
    Imei = <<82,21,50,96,32,80,30,0>>,
    AAA0 = smf_aaa_session:new(
	     #{'Framed-IP-Address' => {10,10,10,10},
	       'Framed-IPv6-Prefix' => {{16#fe80,0,0,0,0,0,0,0}, 64},
	       'Framed-Pool' => <<"pool-A">>,
	       'Framed-IPv6-Pool' => <<"pool-A">>,
	       'Calling-Station-Id' => Msisdn,
	       '3GPP-IMSI' => Imsi,
	       '3GPP-IMEISV' => Imei,
	       'NAT-Pool-Id' => <<"nat-A">>}),

    {ok, AAA1, Events} = smf_aaa_session:call(AAA0, #{}, authenticate, []),
    SessionUpdates = smf_aaa_session:get_session(AAA1),
    ?match(#{'3GPP-IMSI' := Imsi}, SessionUpdates),
    ?match(#{'3GPP-IMEISV' := Imei}, SessionUpdates),
    ?match(#{'Calling-Station-Id' := Msisdn}, SessionUpdates),
    ?match([{set, {{accounting, 'IP-CAN', periodic}, {periodic, 'IP-CAN', 1800, []}}}],
	   Events),
    {ok, AAA2, _} = smf_aaa_session:call(AAA1, #{}, authorize, []),
    {ok, AAA3, _} = smf_aaa_session:call(AAA2, #{}, start, []),

    {ok, AAA4, _} = smf_aaa_session:call(AAA3, #{}, interim, []),

    ?equal([{smf_aaa_nasreq, started, 1}], get_session_stats()),

    {ok, _AAA5, _} = smf_aaa_session:call(AAA4, TermOpts, stop, []),

    ?equal([{smf_aaa_nasreq, started, 0}], get_session_stats()),

    Statistics = diff_stats(Stats0, get_stats(?SERVICE)),

    ct:pal("Statistics: ~p", [Statistics]),
    [?equal(Cnt, stats(Msg, Config, Statistics)) ||
	{Cnt, Msg} <- [{1, 'AAR'}, {1, {'AAA', 2001}},
		       {3, 'ACR'}, {3, {'ACA', 2001}},
		       {1, 'STR'}, {1, {'STA', 2001}}
		      ]],

    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

abort_session_request() ->
    [{doc, "Stop NASREQ session with ASR"}].
abort_session_request(Config) ->
    AAA0 = smf_aaa_session:new(#{'Framed-IP-Address' => {10,10,10,10}}),
    {ok, AAA1, _} = smf_aaa_session:call(AAA0, #{}, authenticate, []),
    {ok, AAA2, _} = smf_aaa_session:call(AAA1, #{}, start, []),
    {ok, AAA3, _} = smf_aaa_session:call(AAA2, #{}, interim, []),

    ?equal([{smf_aaa_nasreq, started, 1}], get_session_stats()),

    SessionOpts = smf_aaa_session:get_session(AAA3),
    SessionId = maps:get('Diameter-Session-Id', SessionOpts),
    ?equal(ok, diameter_test_server:abort_session_request(nasreq, SessionId, ?'Origin-Host', ?'Origin-Realm')),

    receive
	#aaa_request{from = {Pid, Ref}, procedure = {?API, 'ASR'}} ->
	    Pid ! {Ref, {ok, #{}}}
    after 1000 ->
	    ct:fail("no ASR")
    end,

    {ok, _AAA4, _} = smf_aaa_session:call(AAA3, #{}, stop, []),
    ?equal([{smf_aaa_nasreq, started, 0}], get_session_stats()),

    %% make sure nothing crashed
    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.

terminate() ->
    [{doc, "Simulate unexpected owner termiantion"}].
terminate(Config) ->
   Stats0 = get_stats(?SERVICE),

    AAA0 = smf_aaa_session:new(
	      #{'Framed-IP-Address' => {10,10,10,10},
		'Framed-IPv6-Prefix' => {{16#fe80,0,0,0,0,0,0,0}, 64},
		'Framed-Pool' => <<"pool-A">>,
		'Framed-IPv6-Pool' => <<"pool-A">>}),

    {ok, AAA1, _} = smf_aaa_session:call(AAA0, #{}, authenticate, []),
    {ok, AAA2, _} = smf_aaa_session:call(AAA1, #{}, authorize, []),
    {ok, AAA3, _} = smf_aaa_session:call(AAA2, #{}, start, []),
    ?equal([{smf_aaa_nasreq, started, 1}], get_session_stats()),

    smf_aaa_session:terminate_action(AAA3),
    wait_for_session(smf_aaa_nasreq, started, 0, 10),


    Statistics = diff_stats(Stats0, get_stats(?SERVICE)),

    ct:pal("Statistics: ~p", [Statistics]),
    [?equal(Cnt, stats(Msg, Config, Statistics)) ||
	{Cnt, Msg} <- [{1, 'AAR'}, {1, {'AAA', 2001}},
		       {2, 'ACR'}, {2, {'ACA', 2001}},
		       {1, 'STR'}, {1, {'STA', 2001}}
		      ]],

    ?match(0, outstanding_reqs()),
    meck_validate(Config),
    ok.
