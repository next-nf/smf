%% Copyright 2020, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(smf_gtp_gsn_lib).

-compile([{parse_transform, do},
	  {parse_transform, cut}]).

-export([connect_upf_candidates/4, create_session/13, create_session/14]).
-export([triggered_charging_event/4, usage_report/3,
	 close_context/4, close_context_proc/3]).
-export([update_tunnel_endpoint/2,
	 apply_bearer_change_proc/5, access_bearer_change_proc/6]).

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

%% Interfaces whose establishment request carries only the default bearer.
create_session(APN, PAA, DAF, UPSelInfo, Session, PCF, Charging, Auth,
	       SessionOpts, Context, AccessTunnel, AccessBearer, PCC) ->
    create_session(APN, PAA, DAF, UPSelInfo, Session, PCF, Charging, Auth,
		   SessionOpts, Context, AccessTunnel, AccessBearer, PCC,
		   fun(BearerMap, _Context) -> {BearerMap, #{}, []} end).

%% StageExtra folds any further bearers the establishment request asked for into
%% the bearer map, and is applied BEFORE the PFCP Session Establishment so that
%% one exchange provisions every bearer. It runs after apply_authorized_qos/4 so
%% an additional bearer's {qci_arp, _, _} key still wins over the default's, as
%% it did when this staging ran after establishment.
%%
%% It stages the remote side only and names the keys it added; their local
%% F-TEIDs are assigned here, through the same assign_local_data_teid/5 the
%% default bearer goes through, so an FTUP node allocates for every bearer in
%% the one establishment exchange.
create_session(APN, PAA, DAF, UPSelInfo, Session, PCF, Charging, Auth,
	       SessionOpts, Context, AccessTunnel, AccessBearer, PCC, StageExtra) ->
    try
	{ok, create_session_fun(APN, PAA, DAF, UPSelInfo, Session, PCF, Charging, Auth,
				SessionOpts, Context, AccessTunnel, AccessBearer, PCC,
				StageExtra)}
    catch
	throw:Error ->
	    {error, Error}
    end.

create_session_fun(APN, PAA, DAF, {Candidates, SxConnectId}, Session0, PCF0, Charging0, Auth0,
		   SessionOpts0, Context0, AccessTunnel, AccessBearer, PCC0, StageExtra) ->

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

    {PCtx0, NodeCaps, SGiBearer0} =
	case smf_pfcp_context:reselect_upf(Candidates, Session1, APNOpts, UPinfo) of
	    {ok, Result5} -> Result5;
	    {error, Err5} -> throw(Err5#ctx_err{context = Context0, tunnel = AccessTunnel})
	end,

    {Result6, {Cause, SessionOpts3, SGiBearer, Context1}} =
	smf_gsn_lib:allocate_ips(PAA, APNOpts, Session1, DAF, AccessTunnel, SGiBearer0, Context0),
    case Result6 of
	ok -> ok;
	{error, Err6} -> throw(Err6#ctx_err{context = Context1, tunnel = AccessTunnel})
    end,

    Context = add_apn_timeout(APNOpts, SessionOpts3, Context1),

    EBI = Context#context.default_bearer_id,
    BearerMap0a = #{{'Access', default_ebi} => EBI,
		    {'Access', EBI} => AccessBearer,
		    {'SGi-LAN', default_lan_id} => 1,
		    {'SGi-LAN', 1} => SGiBearer},
    %% Register the default bearer under its {QCI, ARP} so a PCC rule at the
    %% default's QoS binds to it (via detect_new_bearers) instead of spawning a
    %% dedicated bearer. Kept in sync on a later default-ARP re-authorization by
    %% fan_out_subscribed_arp_change/6 (rekey_default_qci_arp/3).
    BearerMap0 =
	case smf_gsn_lib:get_qci_arp(maps:get('QoS-Information', SessionOpts3, #{})) of
	    {QCI, ARP} -> BearerMap0a#{{qci_arp, QCI, ARP} => EBI};
	    undefined  -> BearerMap0a
	end,
    BearerMap1 =
	case smf_gsn_lib:assign_local_data_teid({'Access', EBI}, PCtx0, NodeCaps, AccessTunnel, BearerMap0) of
	    {ok, Result7} -> Result7;
	    {error, Err7} -> throw(Err7#ctx_err{context = Context, tunnel = AccessTunnel})
	end,

    Session2 = maps:merge(Session1, SessionOpts3),

    Now = erlang:monotonic_time(),
    SOpts = #{now => Now},

    GxOpts = #{'Event-Trigger' => ?'DIAMETER_GX_EVENT-TRIGGER_UE_IP_ADDRESS_ALLOCATE',
	       'Bearer-Operation' => ?'DIAMETER_GX_BEARER-OPERATION_ESTABLISHMENT',
	       'Network-Request-Support' =>
		   ?'DIAMETER_GX_NETWORK-REQUEST-SUPPORT_NETWORK_REQUEST_SUPPORTED'},

    {GxSession, GxEvents, PCF1} =
	case smf_gtp_gsn_session:ccr_initial_gx(PCF0, Session2, GxOpts, SOpts) of
	    {ok, Result8} -> Result8;
	    {error, Err8} -> throw(Err8#ctx_err{context = Context, tunnel = AccessTunnel})
	end,

    %% TS 29.212 4.5.5 / B.3.3.1: the CCA-I may carry an authorized
    %% Default-EPS-Bearer-QoS (QCI + ARP) and — for EPS, unconditionally — an
    %% authorized APN-AMBR, either of which may override the subscribed values.
    %% Enforce them from here on, before the bearer map is handed to PFCP and
    %% before the Create Session Response is built (#73).
    {SessionOpts4, BearerMap2} =
	apply_authorized_qos(GxSession, SessionOpts3, EBI, BearerMap1),

    %% Fold in the request's further bearer contexts before anything reaches the
    %% UPF. A multi-bearer establishment is ONE PFCP exchange: staging these
    %% afterwards would establish the session without them and then modify it to
    %% add them, exposing an intermediate rule set the UE never asked for.
    {BearerMap2a, Dedicated, ExtraKeys} = StageExtra(BearerMap2, Context),
    BearerMap =
	lists:foldl(
	  fun(Key, BM0) ->
		  case smf_gsn_lib:assign_local_data_teid(
			 Key, PCtx0, NodeCaps, AccessTunnel, BM0) of
		      {ok, BM} -> BM;
		      {error, ErrX} ->
			  throw(ErrX#ctx_err{context = Context, tunnel = AccessTunnel})
		  end
	  end, BearerMap2a, ExtraKeys),

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

    %% A bearer the request asked for is established only if policy AND charging
    %% authorized it: some PCC rule must still bind to it. Rules that got no
    %% charging decision were already dropped from the PCC context by
    %% gy_events_to_pcc_ctx/3, so "a rule still binds" is exactly that condition.
    %% An unauthorized bearer gets no PDR, so it must not reach the UPF at all --
    %% it is dropped here, before the establishment, and reported back for the
    %% response to reject (TS 29.274 7.2.2: per-bearer Cause is mandatory).
    {BearerMapF, Rejected} = drop_unauthorized_bearers(ExtraKeys, PCC4, BearerMap),

    {PCtx, BearerMap3, SessionInfo} =
	case smf_pfcp_context:create_session(gtp_context, PCC4, PCtx0, BearerMapF, Context) of
	       {ok, Result10} -> Result10;
	       {error, Err10} -> throw(Err10#ctx_err{context = Context, tunnel = AccessTunnel})
	   end,

    SessionOpts = maps:merge(SessionOpts4, SessionInfo),
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

    case gtp_context:remote_context_register_new(AccessTunnel, BearerMap3, Context) of
	ok ->
	    {ok, Cause, SessionOpts, Context, BearerMap3, extra(Dedicated, Rejected), PCC4, PCtx,
	     Session6, PCF2, Charging2, Auth2};
	{error, #ctx_err{level = Level, where = {File, Line}}} ->
	    ?LOG(debug, #{type => ctx_err, level => Level, file => File,
			  line => Line, reply => system_failure}),
	    {error, system_failure, SessionOpts, Context, BearerMap3, extra(Dedicated, Rejected),
	     PCC4, PCtx, Session6, PCF2, Charging2, Auth2}
    end.

extra(Dedicated, Rejected) ->
    #{dedicated => maps:without(Rejected, Dedicated), rejected => Rejected}.

%% Partition the staged extra bearers into those a PCC rule binds to and those it
%% does not. Binding is by {qci_arp, QCI, ARP}, the same key resolve_access_bearer/2
%% uses when it picks the bearer a rule's PDR is built against.
drop_unauthorized_bearers([], _PCC, BearerMap) ->
    {BearerMap, []};
drop_unauthorized_bearers(Keys, #pcc_ctx{rules = Rules}, BearerMap) ->
    Bound =
	maps:fold(
	  fun(_Name, Definition, Acc) ->
		  case smf_gsn_lib:get_rule_qci_arp(Definition) of
		      {QCI, ARP} ->
			  case maps:get({qci_arp, QCI, ARP}, BearerMap, undefined) of
			      EBI when is_integer(EBI) -> Acc#{EBI => []};
			      _                        -> Acc
			  end;
		      _ ->
			  Acc
		  end
	  end, #{}, Rules),
    lists:foldl(
      fun({'Access', EBI} = Key, {BM, Rej}) ->
	      case is_map_key(EBI, Bound) of
		  true  -> {BM, Rej};
		  false -> {smf_gsn_lib:remove_bearer_metadata_for_ebi(EBI, maps:remove(Key, BM)),
			    [EBI | Rej]}
	      end
      end, {BearerMap, []}, Keys).

%% apply_authorized_qos/4 — enforce the CCA-I's authorized default-bearer QoS.
%%
%% smf_aaa_gx surfaces the CCA's command-level Default-EPS-Bearer-QoS and
%% APN-AMBR as 'Authorized-QoS-Information' (they are session-level policy, not
%% PCC rules — TS 29.212 4.5.5). Overlaying them field by field onto the
%% subscribed 'QoS-Information' leaves anything the PCRF did not authorize alone.
%%
%% The overlay has to land here rather than at the bearer map's construction:
%% that runs before the CCR-I is even issued, so the subscribed QoS is all it
%% could have seen. Re-keying matters because {qci_arp, QCI, ARP} is how
%% detect_new_bearers decides a later PCC rule binds to the DEFAULT bearer —
%% left on the subscribed values, a rule at the authorized QoS would miss it and
%% wrongly spawn a dedicated bearer.
apply_authorized_qos(GxSession, SessionOpts, EBI, BearerMap) ->
    case maps:get('Authorized-QoS-Information', GxSession, #{}) of
	Auth when map_size(Auth) =:= 0 ->
	    {SessionOpts, BearerMap};
	Auth ->
	    QoS0 = maps:get('QoS-Information', SessionOpts, #{}),
	    QoS = maps:merge(QoS0, Auth),
	    ?LOG(debug, "PCRF authorized default-bearer QoS: ~p -> ~p", [QoS0, QoS]),
	    {SessionOpts#{'QoS-Information' => QoS},
	     rekey_default_qci_arp(EBI, QoS0, QoS, BearerMap)}
    end.

rekey_default_qci_arp(EBI, QoS0, QoS, BearerMap) ->
    Old = smf_gsn_lib:get_qci_arp(QoS0),
    New = smf_gsn_lib:get_qci_arp(QoS),
    case New =:= Old of
	true ->
	    BearerMap;
	false ->
	    Dropped =
		case Old of
		    {QCI0, ARP0} -> maps:remove({qci_arp, QCI0, ARP0}, BearerMap);
		    undefined    -> BearerMap
		end,
	    case New of
		{QCI, ARP} -> Dropped#{{qci_arp, QCI, ARP} => EBI};
		undefined  -> Dropped
	    end
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

%% Re-provision the UPF for an access bearer change: one PFCP Session
%% Modification carrying the whole recomputed rule set, awaited without blocking
%% the context. Yields {PCtx, SessionInfo} for the caller to commit.
apply_bearer_change_proc(BearerMap, URRActions, SendEM, PCtx0, PCC) ->
    do([async_m ||
	   Issued <- async_m:lift(
		       smf_pfcp_context:modify_session_async(
			 PCC, URRActions, modify_opts(SendEM), BearerMap, PCtx0)),
	   Result <- await_modify(Issued),
	   async_m:return(apply_bearer_change_result(Result, URRActions))
       ]).

%% The conditional form the GTP request handlers share: re-provision the UPF only
%% when the access bearer actually changed, otherwise just ask for the usage
%% report. Both arms yield {PCtx, SessionInfo}; the unchanged arm never suspends,
%% so those requests still answer within the handler call.
access_bearer_change_proc(false, _BearerMap, URRActions, _SendEM, PCtx0, _PCC) ->
    gtp_context:trigger_usage_report(self(), URRActions, PCtx0),
    async_m:return({PCtx0, #{}});
access_bearer_change_proc(true, BearerMap, URRActions, SendEM, PCtx0, PCC) ->
    apply_bearer_change_proc(BearerMap, URRActions, SendEM, PCtx0, PCC).

modify_opts(true)  -> #{send_end_marker => true};
modify_opts(false) -> #{}.

apply_bearer_change_result({PCtx, UsageReport, SessionInfo}, URRActions) ->
    gtp_context:usage_report(self(), URRActions, UsageReport),
    {PCtx, SessionInfo}.

%% Local mirror of gtp_context:await_modify/1 — await the async PFCP modify reply,
%% or short-circuit when the rule diff was empty and nothing went on the wire.
%% A non-accepted reply makes modify_session_result return {error, #ctx_err{FATAL}},
%% which travels the procedure's error channel to the caller's ErrFun.
await_modify({request, ReqId, PCtx1}) ->
    do([async_m || Reply <- async_m:await(ReqId),
		   async_m:lift(smf_pfcp_context:modify_session_result(Reply, PCtx1))]);
await_modify({no_request, PCtx1}) ->
    async_m:return({PCtx1, undefined, #{}}).

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


%% close_context_proc/3 — tear the context down: delete the PFCP session, harvest
%% the final usage report from the response and close out the accounting with it.
%% Yields the closed Data for the caller to commit; it never travels the error
%% channel, because a failed or unanswered Session Deletion only costs the final
%% usage report (delete_session_result/1 yields `undefined`) and must not stop the
%% teardown.
%%
%% The caller must move to `session := shutdown` from its OkFun, not before: the
%% shutdown enter casts `stop` to itself to be the last message in the inbox, so
%% entering shutdown while this procedure is still parked would kill the context
%% before the deletion reply arrives and lose the report it was waiting for.
close_context_proc(_, {API, TermCause}, Data) ->
    close_context_proc(API, TermCause, Data);
close_context_proc(API, TermCause, #{pfcp := PCtx} = Data)
  when is_atom(TermCause) ->
    do([async_m ||
	   UsageReport <- await_delete(smf_pfcp_context:delete_session_async(TermCause, PCtx)),
	   async_m:return(close_context(API, TermCause, UsageReport, Data))
       ]);
close_context_proc(_API, _TermCause, Data) ->
    async_m:return(Data).

await_delete({request, ReqId}) ->
    do([async_m || Reply <- async_m:await(ReqId),
		   async_m:return(smf_pfcp_context:delete_session_result(Reply))]);
await_delete(no_request) ->
    async_m:return(undefined).

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
