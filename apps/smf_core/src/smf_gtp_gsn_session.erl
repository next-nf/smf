%% Copyright 2020, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(smf_gtp_gsn_session).

-compile([{parse_transform, do},
	  {parse_transform, cut}]).

-export([authenticate/2,
	 ccr_initial/4,
	 usage_report_request/6,
	 usage_report/4,
	 close_context/4]).

-include_lib("kernel/include/logger.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include_lib("pfcplib/include/pfcp_packet.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").
-include_lib("smf_aaa/include/diameter_3gpp_ts29_212.hrl").
-include_lib("smf_aaa/include/smf_aaa_session.hrl").
-include("include/smf.hrl").

authenticate(AAA0, SessionOpts) ->
    ?LOG(debug, "SessionOpts: ~p", [SessionOpts]),
    case smf_aaa_session:call(AAA0, SessionOpts, authenticate, [inc_session_id]) of
	{ok, AAA1, SEvs} ->
	    SOpts = smf_aaa_session:get_session(AAA1),
	    {ok, {SOpts, SEvs, AAA1}};
	Other ->
	    ?LOG(debug, "AuthResult: ~p", [Other]),
	    {error, ?CTX_ERR(?FATAL, user_authentication_failed)}
    end.

ccr_initial(AAA0, API, SessionOpts, ReqOpts) ->
    case smf_aaa_session:call(AAA0, SessionOpts, {API, 'CCR-Initial'}, ReqOpts) of
	{ok, AAA1, SEvs} ->
	    SOpts = smf_aaa_session:get_session(AAA1),
	    {ok, {SOpts, SEvs, AAA1}};
	{_Fail, _, _} ->
	    %% TBD: replace with sensible mapping
	    {error, ?CTX_ERR(?FATAL, system_failure)}
    end.


usage_report_request(ChargeEv, Now, UsageReport, PCtx, PCC, AAA0) ->
    ReqOpts = #{now => Now, async => true},

    {Online, Offline, Monitor} =
	smf_pfcp_context:usage_report_to_charging_events(UsageReport, ChargeEv, PCtx),
    AAA1 = smf_gsn_lib:process_accounting_monitor_events(ChargeEv, Monitor, Now, AAA0),
    GyReqServices = smf_pcc_context:gy_credit_request(Online, PCC),
    {AAA2, _} = smf_gsn_lib:process_online_charging_events(ChargeEv, GyReqServices, AAA1, ReqOpts),
    smf_gsn_lib:process_offline_charging_events(ChargeEv, Offline, Now, AAA2).

usage_report(URRActions, UsageReport, PCtx, AAA0) ->
    Now = erlang:monotonic_time(),
    case proplists:get_value(offline, URRActions) of
	{ChargeEv, OldS} ->
	    {_Online, Offline, _} =
		smf_pfcp_context:usage_report_to_charging_events(UsageReport, ChargeEv, PCtx),
	    smf_gsn_lib:process_offline_charging_events(ChargeEv, Offline, Now, OldS, AAA0);
	_ ->
	    AAA0
    end.

close_context(Reason, UsageReport, PCtx, AAA0) ->
    %% TODO: Monitors, AAA over SGi

    %%  1. CCR on Gx to get PCC rules
    Now = erlang:monotonic_time(),
    ReqOpts = #{now => Now, async => true},
    AAA1 = case smf_aaa_session:call(AAA0, #{}, {gx, 'CCR-Terminate'}, ReqOpts#{async => false}) of
	{ok, AAA0a, _} ->
	    ?LOG(debug, "Gx terminate succeeded"),
	    AAA0a;
	GxOther ->
	    ?LOG(warning, "Gx terminate failed with: ~p", [GxOther]),
	    AAA0
    end,

    ChargeEv = {terminate, Reason},
    {Online, Offline, Monitor} =
	smf_pfcp_context:usage_report_to_charging_events(UsageReport, ChargeEv, PCtx),
    AAA2 = smf_gsn_lib:process_accounting_monitor_events(ChargeEv, Monitor, Now, AAA1),
    GyReqServices = smf_gsn_lib:gy_credit_report(Online),
    {AAA3, _} = smf_gsn_lib:process_online_charging_events(ChargeEv, GyReqServices, AAA2, ReqOpts),
    smf_gsn_lib:process_offline_charging_events(ChargeEv, Offline, Now, AAA3).
