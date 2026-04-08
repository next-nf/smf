%% Copyright 2020, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(smf_gtp_gsn_session).

-compile([{parse_transform, do},
	  {parse_transform, cut}]).

-export([authenticate/3,
	 ccr_initial_gx/4,
	 ccr_initial_gy/4,
	 usage_report_request/8,
	 usage_report/4,
	 close_context/7]).

-include_lib("kernel/include/logger.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include_lib("pfcplib/include/pfcp_packet.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").
-include_lib("smf_aaa/include/diameter_3gpp_ts29_212.hrl").
-include_lib("smf_aaa/include/smf_aaa_session.hrl").
-include("include/smf.hrl").

authenticate(Auth0, Session0, SessionOpts) ->
    ?LOG(debug, "SessionOpts: ~p", [SessionOpts]),
    case smf_aaa_auth:authenticate(Auth0, Session0, SessionOpts, [inc_session_id]) of
	{ok, Auth1, Session1, SEvs} ->
	    {ok, {Session1, SEvs, Auth1}};
	Other ->
	    ?LOG(debug, "AuthResult: ~p", [Other]),
	    {error, ?CTX_ERR(?FATAL, user_authentication_failed)}
    end.

ccr_initial_gx(PCF0, Session0, SessionOpts, ReqOpts) ->
    case smf_aaa_pcf:ccr_initial(PCF0, Session0, SessionOpts, ReqOpts) of
	{ok, PCF1, Session1, SEvs} ->
	    {ok, {Session1, SEvs, PCF1}};
	{_Fail, _, _, _} ->
	    {error, ?CTX_ERR(?FATAL, system_failure)}
    end.

ccr_initial_gy(C0, Session0, SessionOpts, ReqOpts) ->
    case smf_aaa_charging:gy_ccr_initial(C0, Session0, SessionOpts, ReqOpts) of
	{ok, C1, Session1, SEvs} ->
	    {ok, {Session1, SEvs, C1}};
	{_Fail, _, _, _} ->
	    {error, ?CTX_ERR(?FATAL, system_failure)}
    end.


usage_report_request(ChargeEv, Now, UsageReport, PCtx, PCC,
		     Session0, Charging0, Auth0) ->
    ReqOpts = #{now => Now, async => true},

    {Online, Offline, Monitor} =
	smf_pfcp_context:usage_report_to_charging_events(UsageReport, ChargeEv, PCtx),
    {Auth1, Session1} = smf_gsn_lib:process_accounting_monitor_events(ChargeEv, Monitor, Now, Auth0, Session0),
    GyReqServices = smf_pcc_context:gy_credit_request(Online, PCC),
    {Charging1, Session2, GyEvs} = smf_gsn_lib:process_online_charging_events(ChargeEv, GyReqServices, Charging0, Session1, ReqOpts),
    {Charging2, Session3} = smf_gsn_lib:process_offline_charging_events(ChargeEv, Offline, Now, Charging1, Session2),
    {Session3, Charging2, Auth1, GyEvs}.

usage_report(URRActions, UsageReport, PCtx, {Session0, Charging0}) ->
    Now = erlang:monotonic_time(),
    case proplists:get_value(offline, URRActions) of
	{ChargeEv, OldS} ->
	    {_Online, Offline, _} =
		smf_pfcp_context:usage_report_to_charging_events(UsageReport, ChargeEv, PCtx),
	    {Charging1, Session1} = smf_gsn_lib:process_offline_charging_events(ChargeEv, Offline, Now, OldS, Charging0, Session0),
	    {Session1, Charging1};
	_ ->
	    {Session0, Charging0}
    end.

close_context(Reason, UsageReport, PCtx, Session0, PCF0, Charging0, Auth0) ->
    %% TODO: Monitors, AAA over SGi

    %%  1. CCR on Gx to get PCC rules
    Now = erlang:monotonic_time(),
    ReqOpts = #{now => Now, async => true},
    {PCF1, Session1} =
	case smf_aaa_pcf:ccr_terminate(PCF0, Session0, #{}, ReqOpts#{async => false}) of
	    {ok, PCF0a, Session0a, _} ->
		?LOG(debug, "Gx terminate succeeded"),
		{PCF0a, Session0a};
	    _ ->
		?LOG(warning, "Gx terminate failed"),
		{PCF0, Session0}
	end,

    ChargeEv = {terminate, Reason},
    {Online, Offline, Monitor} =
	smf_pfcp_context:usage_report_to_charging_events(UsageReport, ChargeEv, PCtx),
    {Auth1, Session2} = smf_gsn_lib:process_accounting_monitor_events(ChargeEv, Monitor, Now, Auth0, Session1),
    GyReqServices = smf_gsn_lib:gy_credit_report(Online),
    {Charging1, Session3, _} = smf_gsn_lib:process_online_charging_events(ChargeEv, GyReqServices, Charging0, Session2, ReqOpts),
    {Charging2, Session4} = smf_gsn_lib:process_offline_charging_events(ChargeEv, Offline, Now, Charging1, Session3),
    {Session4, PCF1, Charging2, Auth1}.
