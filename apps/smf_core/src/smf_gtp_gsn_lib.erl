%% Copyright 2020, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(smf_gtp_gsn_lib).

-compile([{parse_transform, do},
	  {parse_transform, cut}]).

-export([connect_upf_candidates/4, create_session/13]).
-export([triggered_charging_event/4, usage_report/3, close_context/3, close_context/4]).
-export([update_tunnel_endpoint/2,
	 apply_bearer_change/5]).

-include_lib("kernel/include/logger.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include_lib("pfcplib/include/pfcp_packet.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").
-include_lib("smf_aaa/include/diameter_3gpp_ts29_212.hrl").
-include_lib("smf_aaa/include/smf_aaa_session.hrl").
-include("include/smf.hrl").

%%====================================================================
%% Session Setup
%%====================================================================

connect_upf_candidates(APN, Services, NodeSelect, PeerUpNode) ->
    APN_FQDN = smf_node_selection:apn_to_fqdn(APN),
    Candidates = smf_node_selection:topology_select(APN_FQDN, PeerUpNode, Services, NodeSelect),
    SxConnectId = smf_sx_node:request_connect(Candidates, NodeSelect, 1000),

    {ok, {Candidates, SxConnectId}}.

create_session(APN, PAA, DAF, UPSelInfo, Session, PCF, Charging, Auth,
	       SessionOpts, Context, AccessTunnel, LeftBearer, PCC) ->
    try
	{ok, create_session_fun(APN, PAA, DAF, UPSelInfo, Session, PCF, Charging, Auth,
				SessionOpts, Context, AccessTunnel, LeftBearer, PCC)}
    catch
	throw:Error ->
	    {error, Error}
    end.

create_session_fun(APN, PAA, DAF, {Candidates, SxConnectId}, Session0, PCF0, Charging0, Auth0,
		   SessionOpts0, Context0, AccessTunnel, LeftBearer, PCC0) ->

    smf_sx_node:wait_connect(SxConnectId),

    APNOpts =
	case smf_apn:get(APN) of
	    {ok, Result2} -> Result2;
	    {error, Err2} -> throw(Err2#ctx_err{context = Context0, tunnel = AccessTunnel})
	end,

    {UPinfo, SessionOpts1} =
	case smf_pfcp_context:select_upf(Candidates, SessionOpts0, APNOpts) of
	    {ok, Result3} -> Result3;
	    {error, Err3} -> throw(Err3#ctx_err{context = Context0, tunnel = AccessTunnel})
	end,

    {Session1, AuthSEvs, Auth1} =
	case smf_gtp_gsn_session:authenticate(Auth0, Session0, SessionOpts1) of
	    {ok, Result4} -> Result4;
	    {error, Err4} -> throw(Err4#ctx_err{context = Context0, tunnel = AccessTunnel})
	end,

    {PCtx0, NodeCaps, RightBearer0} =
	case smf_pfcp_context:reselect_upf(Candidates, Session1, APNOpts, UPinfo) of
	    {ok, Result5} -> Result5;
	    {error, Err5} -> throw(Err5#ctx_err{context = Context0, tunnel = AccessTunnel})
	end,

    {Result6, {Cause, SessionOpts3, RightBearer, Context1}} =
	smf_gsn_lib:allocate_ips(PAA, APNOpts, Session1, DAF, AccessTunnel, RightBearer0, Context0),
    case Result6 of
	ok -> ok;
	{error, Err6} -> throw(Err6#ctx_err{context = Context1, tunnel = AccessTunnel})
    end,

    Context = add_apn_timeout(APNOpts, SessionOpts3, Context1),

    Bearer0 = #{left => LeftBearer, right => RightBearer},
    Bearer1 =
	case smf_gsn_lib:assign_local_data_teid(left, PCtx0, NodeCaps, AccessTunnel, Bearer0) of
	    {ok, Result7} -> Result7;
	    {error, Err7} -> throw(Err7#ctx_err{context = Context, tunnel = AccessTunnel})
	end,

    Session2 = maps:merge(Session1, SessionOpts3),

    Now = erlang:monotonic_time(),
    SOpts = #{now => Now},

    GxOpts = #{'Event-Trigger' => ?'DIAMETER_GX_EVENT-TRIGGER_UE_IP_ADDRESS_ALLOCATE',
	       'Bearer-Operation' => ?'DIAMETER_GX_BEARER-OPERATION_ESTABLISHMENT'},

    {GxSession, GxEvents, PCF1} =
	case smf_gtp_gsn_session:ccr_initial_gx(PCF0, Session2, GxOpts, SOpts) of
	    {ok, Result8} -> Result8;
	    {error, Err8} -> throw(Err8#ctx_err{context = Context, tunnel = AccessTunnel})
	end,

    RuleBase = smf_charging:rulebase(),
    {PCC1, PCCErrors1} = smf_pcc_context:gx_events_to_pcc_ctx(GxEvents, '_', RuleBase, PCC0),
    case smf_pcc_context:pcc_ctx_has_rules(PCC1) of
	true ->
	    ok;
	_ ->
	    throw(#ctx_err{level = ?FATAL, reply = user_authentication_failed,
			   tunnel = AccessTunnel, where = {?FILE, ?LINE}})
    end,

    %% TBD............
    CreditsAdd = smf_pcc_context:pcc_ctx_to_credit_request(PCC1),
    GyReqServices = #{credits => CreditsAdd},

    {GySession, GyEvs, Charging1} =
	case smf_gtp_gsn_session:ccr_initial_gy(Charging0, GxSession, GyReqServices, SOpts) of
	    {ok, Result9} -> Result9;
	    {error, Err9} -> throw(Err9#ctx_err{context = Context, tunnel = AccessTunnel})
	end,

    ?LOG(debug, "Initial GyEvs: ~p", [GyEvs]),

    {ok, Charging2, Session3, RfSEvs} =
	smf_aaa_charging:rf_initial(Charging1, GySession, #{}, SOpts),

    {PCC2, PCCErrors2} = smf_pcc_context:gy_events_to_pcc_ctx(Now, GyEvs, PCC1),
    PCC3 = smf_pcc_context:session_events_to_pcc_ctx(AuthSEvs, PCC2),
    PCC4 = smf_pcc_context:session_events_to_pcc_ctx(RfSEvs, PCC3),

    {PCtx, Bearer, SessionInfo} =
	case smf_pfcp_context:create_session(gtp_context, PCC4, PCtx0, Bearer1, Context) of
	       {ok, Result10} -> Result10;
	       {error, Err10} -> throw(Err10#ctx_err{context = Context, tunnel = AccessTunnel})
	   end,

    SessionOpts = maps:merge(SessionOpts3, SessionInfo),
    Session4 = maps:merge(Session3, SessionOpts),
    {_, Auth2, Session5, _} = smf_aaa_auth:start(Auth1, Session4, SessionOpts, SOpts#{async => true}),

    GxReport = smf_gsn_lib:pcc_events_to_charging_rule_report(PCCErrors1 ++ PCCErrors2),
    {PCF2, Session6} =
	if map_size(GxReport) /= 0 ->
	       {ok, PCF1a, Session5a, _} =
		   smf_aaa_pcf:ccr_update(PCF1, Session5, GxReport, SOpts#{async => true}),
	       {PCF1a, Session5a};
	   true ->
	       {PCF1, Session5}
	end,

    case gtp_context:remote_context_register_new(AccessTunnel, Bearer, Context) of
	ok ->
	    {ok, Cause, SessionOpts, Context, Bearer, PCC4, PCtx,
	     Session6, PCF2, Charging2, Auth2};
	{error, #ctx_err{level = Level, where = {File, Line}}} ->
	    ?LOG(debug, #{type => ctx_err, level => Level, file => File,
			  line => Line, reply => system_failure}),
	    {error, system_failure, SessionOpts, Context, Bearer, PCC4, PCtx,
	     Session6, PCF2, Charging2, Auth2}
    end.


%% 'Idle-Timeout' received from smf_aaa Session takes precedence over configured one
add_apn_timeout(Opts, Session, Context) ->
    InactTimeout = maps:get(inactivity_timeout, Opts, infinity),
    SessionTimeout = maps:get('Idle-Timeout', Session, infinity),
    Timeout =
	case {InactTimeout, SessionTimeout} of
	    {_, infinity} -> InactTimeout;
	    {infinity, X} when is_integer(X) -> X + 300 * 1000;
	    {X, Y} when is_integer(X), is_integer(Y) ->
		erlang:max(X, Y + 300 * 1000);
	    _ ->
		48 * 3600 * 1000
	end,
    %% TODO: moving idle_timeout to the PCC ctx might make more sense
    Context#context{inactivity_timeout = Timeout, idle_timeout = SessionTimeout}.

%%====================================================================
%% Tunnel
%%====================================================================

update_tunnel_endpoint(TunnelOld, Tunnel0) ->
    %% TBD: handle errors
    {ok, Tunnel} = gtp_path:bind_tunnel(Tunnel0),
    gtp_context:tunnel_reg_update(TunnelOld, Tunnel),
    if Tunnel#tunnel.path /= TunnelOld#tunnel.path ->
	    gtp_path:unbind_tunnel(TunnelOld);
       true ->
	    ok
    end,
    Tunnel.

%%====================================================================
%% Bearer Support
%%====================================================================

apply_bearer_change(Bearer, URRActions, SendEM, PCtx0, PCC) ->
    ModifyOpts =
	if SendEM -> #{send_end_marker => true};
	   true   -> #{}
	end,
    case smf_pfcp_context:modify_session(PCC, URRActions, ModifyOpts, Bearer, PCtx0) of
	{ok, {PCtx, UsageReport, SessionInfo}} ->
	    gtp_context:usage_report(self(), URRActions, UsageReport),
	    {ok, {PCtx, SessionInfo}};
	{error, _} = Error ->
	    Error
    end.

%%====================================================================
%% Charging API
%%====================================================================

triggered_charging_event(ChargeEv, Now, Request,
			 #{pfcp := PCtx, aaa_session := S0, pcf := _PCF,
			   charging := C0, aaa_auth := A0, pcc := PCC} = Data) ->
    case query_usage_report(Request, PCtx) of
	{ok, {_, UsageReport, _}} ->
	    {S1, C1, A1, GyEvs} = smf_gtp_gsn_session:usage_report_request(
				     ChargeEv, Now, UsageReport, PCtx, PCC,
				     S0, C0, A0),
	    {Data#{aaa_session := S1, charging := C1, aaa_auth := A1}, GyEvs};
	{error, CtxErr} ->
	    ?LOG(error, "Triggered Charging Event failed with ~p", [CtxErr]),
	    {Data, []}
    end.

usage_report(URRActions, UsageReport, #{pfcp := PCtx, aaa_session := S0, charging := C0} = Data) ->
    {S1, C1} = smf_gtp_gsn_session:usage_report(URRActions, UsageReport, PCtx, {S0, C0}),
    Data#{aaa_session := S1, charging := C1};
usage_report(_URRActions, _UsageReport, #{aaa_session := _} = Data) ->
    ?LOG(info, "PFCP Usage Report after PFCP context closure"),
    Data.


%% close_context/3
close_context(_, {API, TermCause}, Context) ->
    close_context(API, TermCause, Context);
close_context(API, TermCause, #{pfcp := PCtx} = Data)
  when is_atom(TermCause) ->
    UsageReport = smf_pfcp_context:delete_session(TermCause, PCtx),
    close_context(API, TermCause, UsageReport, Data);
close_context(_API, _TermCause, Data) ->
    Data.

%% close_context/4
close_context(API, TermCause, UsageReport,
	      #{pfcp := PCtx, aaa_session := S0,
		pcf := PCF0, charging := C0, aaa_auth := A0} = Data)
  when is_atom(TermCause) ->
    {S1, PCF1, C1, A1} =
	smf_gtp_gsn_session:close_context(TermCause, UsageReport, PCtx,
					   S0, PCF0, C0, A0),
    smf_prometheus:termination_cause(API, TermCause),
    maps:remove(pfcp, Data#{aaa_session := S1, pcf := PCF1, charging := C1, aaa_auth := A1}).

%%====================================================================
%% Helper
%%====================================================================

query_usage_report(ChargingKeys, PCtx)
  when is_list(ChargingKeys) ->
    smf_pfcp_context:query_usage_report(ChargingKeys, PCtx);
query_usage_report(_, PCtx) ->
    smf_pfcp_context:query_usage_report(PCtx).

%% -*- mode: Erlang; whitespace-line-column: 120; -*-
