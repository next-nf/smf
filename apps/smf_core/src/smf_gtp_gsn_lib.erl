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
	 close_context/4, close_context_proc/3,
	 compensate_establishment/1, establishment_failed/2]).
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
    create_session_fun(APN, PAA, DAF, UPSelInfo, Session, PCF, Charging, Auth,
		       SessionOpts, Context, AccessTunnel, AccessBearer, PCC,
		       StageExtra).

%% Lift a conventional {ok,_} | {error, #ctx_err{}} return into the procedure's
%% error channel, decorating the error with the context and tunnel the throw it
%% replaces used to attach. Every step of the establishment failed by throwing;
%% they now fail through the channel instead, because a throw unwinds past the
%% state the procedure has accumulated and the compensation needs it (#87).
lift_err({ok, V}, _Context, _Tunnel)      -> async_m:return(V);
lift_err(ok, _Context, _Tunnel)           -> async_m:return(ok);
lift_err({error, #ctx_err{} = Err}, Context, Tunnel) ->
    async_m:fail(Err#ctx_err{context = Context, tunnel = Tunnel}).

%% Await a Diameter pipeline that may or may not have suspended. As on the Gx
%% update path, smf_aaa_* answers either {async, ReqId} or the folded result
%% outright; both are normal and only the first has anything to await.
await_invoke({async, ReqId}) -> async_m:await(ReqId);
await_invoke(Folded)         -> async_m:return(Folded).

%% The CCR-Initial legs. The worker posts {Result, Ctx, Session, Events}; a dead
%% worker surfaces as {error, _} and travels the channel like any other failure.
await_ccr_initial(Issued, Context, Tunnel) ->
    do([async_m ||
	   Reply <- await_invoke(Issued),
	   lift_err(ccr_initial_ok(Reply), Context, Tunnel)
       ]).

ccr_initial_ok({ok, Ctx, Session, Events}) -> {ok, {Session, Events, Ctx}};
ccr_initial_ok({_Fail, _, _, _})           -> {error, ?CTX_ERR(?FATAL, system_failure)};
ccr_initial_ok({error, _})                 -> {error, ?CTX_ERR(?FATAL, system_failure)}.

await_establish({request, ReqId, PCtx}, Handler, BearerMap, Context, Tunnel) ->
    do([async_m ||
	   Reply <- async_m:await(ReqId),
	   lift_err(smf_pfcp_context:create_session_result(Reply, Handler, BearerMap, PCtx),
		    Context, Tunnel)
       ]).

create_session_fun(APN, PAA, DAF, {Candidates, SxConnectId}, Session0, PCF0, Charging0, Auth0,
		   SessionOpts0, Context0, AccessTunnel, AccessBearer, PCC0, StageExtra) ->
    do([async_m ||
	   %% Still synchronous: the association wait, the AAA authentication and
	   %% the UPF (re)selection have no async transport yet. They are also the
	   %% three that establish nothing at a peer, so a failure in them has
	   %% nothing to compensate.
	   _ = smf_sx_node:wait_connect(SxConnectId),

	   APNOpts <- lift_err(smf_apn:get(APN), Context0, AccessTunnel),

	   {UPinfo, SessionOpts1} <-
	       lift_err(smf_pfcp_context:select_upf(Candidates, SessionOpts0, APNOpts),
			Context0, AccessTunnel),

	   {Session1, AuthSEvs, Auth1} <-
	       lift_err(smf_gtp_gsn_session:authenticate(Auth0, Session0, SessionOpts1),
			Context0, AccessTunnel),

	   {PCtx0, NodeCaps, SGiBearer0} <-
	       lift_err(smf_pfcp_context:reselect_upf(Candidates, Session1, APNOpts, UPinfo),
			Context0, AccessTunnel),

	   {Result6, {Cause, SessionOpts3, SGiBearer, Context1}} =
	       smf_gsn_lib:allocate_ips(PAA, APNOpts, Session1, DAF, AccessTunnel,
					SGiBearer0, Context0),
	   lift_err(Result6, Context1, AccessTunnel),

	   Context = add_apn_timeout(APNOpts, SessionOpts3, Context1),

	   EBI = Context#context.default_bearer_id,
	   BearerMap0a = #{{'Access', default_ebi} => EBI,
			   {'Access', EBI} => AccessBearer,
			   {'SGi-LAN', default_lan_id} => 1,
			   {'SGi-LAN', 1} => SGiBearer},
	   %% Register the default bearer under its {QCI, ARP} so a PCC rule at the
	   %% default's QoS binds to it (via detect_new_bearers) instead of spawning
	   %% a dedicated bearer. Kept in sync on a later default-ARP
	   %% re-authorization by fan_out_subscribed_arp_change/6.
	   BearerMap0 =
	       case smf_gsn_lib:get_qci_arp(maps:get('QoS-Information', SessionOpts3, #{})) of
		   {QCI, ARP} -> BearerMap0a#{{qci_arp, QCI, ARP} => EBI};
		   undefined  -> BearerMap0a
	       end,
	   BearerMap1 <-
	       lift_err(smf_gsn_lib:assign_local_data_teid(
			  {'Access', EBI}, PCtx0, NodeCaps, AccessTunnel, BearerMap0),
			Context, AccessTunnel),

	   Session2 = maps:merge(Session1, SessionOpts3),

	   Now = erlang:monotonic_time(),
	   SOpts = #{now => Now},

	   GxOpts = #{'Event-Trigger' => ?'DIAMETER_GX_EVENT-TRIGGER_UE_IP_ADDRESS_ALLOCATE',
		      'Bearer-Operation' => ?'DIAMETER_GX_BEARER-OPERATION_ESTABLISHMENT',
		      'Network-Request-Support' =>
			  ?'DIAMETER_GX_NETWORK-REQUEST-SUPPORT_NETWORK_REQUEST_SUPPORTED'},

	   %% From here on a failure has something to undo: the PCRF now believes an
	   %% IP-CAN session exists. Each context is committed to Data as it advances
	   %% so create_session_err/4 can find it -- the error channel hands ErrFun
	   %% the live Data, which is the whole reason these steps stopped throwing.
	   {GxSession, GxEvents, PCF1} <-
	       await_ccr_initial(
		 smf_aaa_pcf:ccr_initial(PCF0, Session2, GxOpts,
					 SOpts#{pipeline_async => true}),
		 Context, AccessTunnel),
	   async_m:modify_data(
	     fun(D) -> started(gx, D#{pcf => PCF1, aaa_session => GxSession}) end),

	   %% TS 29.212 4.5.5 / B.3.3.1: the CCA-I may carry an authorized
	   %% Default-EPS-Bearer-QoS (QCI + ARP) and -- for EPS, unconditionally --
	   %% an authorized APN-AMBR, either of which may override the subscribed
	   %% values. Enforce them from here on, before the bearer map is handed to
	   %% PFCP and before the Create Session Response is built (#73).
	   {SessionOpts4, BearerMap2} =
	       apply_authorized_qos(GxSession, SessionOpts3, EBI, BearerMap1),

	   %% Fold in the request's further bearer contexts before anything reaches
	   %% the UPF. A multi-bearer establishment is ONE PFCP exchange: staging
	   %% these afterwards would establish the session without them and then
	   %% modify it to add them, exposing an intermediate rule set the UE never
	   %% asked for.
	   {BearerMap2a, Dedicated, ExtraKeys} = StageExtra(BearerMap2, Context),
	   BearerMap <-
	       lift_err(assign_extra_teids(ExtraKeys, PCtx0, NodeCaps, AccessTunnel,
					   BearerMap2a),
			Context, AccessTunnel),

	   RuleBase = smf_charging:rulebase(),
	   {PCC1, PCCErrors1} =
	       smf_pcc_context:gx_events_to_pcc_ctx(GxEvents, '_', RuleBase, PCC0),
	   lift_err(pcc_has_rules(PCC1), Context, AccessTunnel),

	   CreditsAdd = smf_pcc_context:pcc_ctx_to_credit_request(PCC1),
	   GyReqServices = #{credits => CreditsAdd},

	   {GySession, GyEvs, Charging1} <-
	       await_ccr_initial(
		 smf_aaa_charging:gy_ccr_initial(Charging0, GxSession, GyReqServices,
						 SOpts#{pipeline_async => true}),
		 Context, AccessTunnel),
	   async_m:modify_data(
	     fun(D) -> started(gy, D#{charging => Charging1, aaa_session => GySession}) end),

	   {ok, Charging2, Session3, RfSEvs} =
	       smf_aaa_charging:rf_initial(Charging1, GySession, #{}, SOpts),
	   async_m:modify_data(
	     fun(D) -> started(rf, D#{charging => Charging2, aaa_session => Session3}) end),

	   {PCC2, PCCErrors2} = smf_pcc_context:gy_events_to_pcc_ctx(Now, GyEvs, PCC1),
	   PCC3 = smf_pcc_context:session_events_to_pcc_ctx(AuthSEvs, PCC2),
	   PCC4 = smf_pcc_context:session_events_to_pcc_ctx(RfSEvs, PCC3),

	   %% A bearer the request asked for is established only if policy AND
	   %% charging authorized it: some PCC rule must still bind to it. Rules that
	   %% got no charging decision were already dropped from the PCC context by
	   %% gy_events_to_pcc_ctx/3, so "a rule still binds" is exactly that
	   %% condition. An unauthorized bearer gets no PDR, so it must not reach the
	   %% UPF at all -- it is dropped here, before the establishment, and reported
	   %% back for the response to reject (TS 29.274 7.2.2).
	   {BearerMapF, Rejected} = drop_unauthorized_bearers(ExtraKeys, PCC4, BearerMap),

	   Issued <- lift_err(smf_pfcp_context:create_session_async(
				gtp_context, PCC4, PCtx0, BearerMapF, Context),
			      Context, AccessTunnel),
	   {PCtx, BearerMap3, SessionInfo} <-
	       await_establish(Issued, gtp_context, BearerMapF, Context, AccessTunnel),
	   async_m:modify_data(fun(D) -> started(pfcp, D#{pfcp => PCtx}) end),

	   SessionOpts = maps:merge(SessionOpts4, SessionInfo),
	   Session4 = maps:merge(Session3, SessionOpts),
	   {_, Auth2, Session5, _} =
	       smf_aaa_auth:start(Auth1, Session4, SessionOpts, SOpts#{async => true}),

	   GxReport = smf_gsn_lib:pcc_events_to_charging_rule_report(PCCErrors1 ++ PCCErrors2),
	   {PCF2, Session6} = report_establishment_failures(GxReport, PCF1, Session5, SOpts),
	   %% `=>` throughout, not `:=`: this is the creation path, so Data does not
	   %% yet carry every key -- `pfcp` in particular is absent until now.
	   async_m:modify_data(_#{pcf => PCF2, aaa_session => Session6, aaa_auth => Auth2}),

	   %% A failed registration replaces the Cause as well as the verdict: the
	   %% response must say system_failure, not the cause the allocation produced.
	   {Verdict, Cause1} =
	       register_new_context(AccessTunnel, BearerMap3, Context, Cause),
	   async_m:return(
	     {Verdict, Cause1, SessionOpts, Context, BearerMap3,
	      extra(Dedicated, Rejected), PCC4, PCtx, Session6, PCF2, Charging2, Auth2})
       ]).

%% Record that an external session is now open at a peer, so a later failure
%% knows what there is to undo. Only what is listed here is compensated: calling
%% terminate/3 on a context whose session was never started would report the
%% teardown of something the peer never had.
started(What, Data) ->
    Data#{establishment => [What | maps:get(establishment, Data, [])]}.

%% compensate_establishment/1 — tear down the external sessions a failed
%% establishment had already opened.
%%
%% A create that fails partway leaves the PCRF, the OCS and the CDF each
%% believing a session exists. Nothing used to undo that: close_context/7 -- which
%% sends the Gx CCR-T, the Gy CCR-T and the Rf stop -- is reachable only from the
%% teardown paths, and a failed create ends at the interface's terminate/3, which
%% deletes the PFCP session and releases the IPs and nothing else (#87).
%%
%% Each context module carries a terminate/3 that runs the `terminate` procedure
%% across every service the context ever used (smf_aaa_session:get_services/2
%% special-cases `terminate` to fan out that way), so one call per context covers
%% whatever it actually started. They were written for this and had no caller.
%%
%% Failures here are logged and swallowed on purpose: this runs on an error path
%% that is already answering the peer, and a compensation that cannot complete
%% must not turn a rejected session into a crashed context.
%% establishment_failed/2 — compensate, and hand back the Data the teardown needs.
%%
%% The #ctx_err{} carries the context holding the allocated UE IPs, and the
%% interface's terminate/3 releases them from Data -- so it has to be put there.
%% handle_ctx_error/4 did exactly this for the throw path this replaces
%% ({stop, normal, Data#{context => Context}}); losing it leaks an IP per failed
%% establishment.
establishment_failed(#ctx_err{context = Context}, Data)
  when is_record(Context, context) ->
    ok = compensate_establishment(Data),
    Data#{context => Context};
establishment_failed(#ctx_err{}, Data) ->
    ok = compensate_establishment(Data),
    Data.

compensate_establishment(#{aaa_session := Session} = Data) ->
    Started = maps:get(establishment, Data, []),
    Opts = #{now => erlang:monotonic_time(), async => true},
    _ = [compensate(What, Data, Session, Opts) || What <- Started, What /= pfcp],
    ok.

compensate(gx, #{pcf := PCF}, Session, Opts) ->
    compensate_call(fun() -> smf_aaa_pcf:terminate(PCF, Session, Opts) end, gx);
compensate(gy, #{charging := Charging}, Session, Opts) ->
    compensate_call(fun() -> smf_aaa_charging:terminate(Charging, Session, Opts) end, gy);
compensate(rf, _Data, _Session, _Opts) ->
    %% Gy and Rf share the charging context, and terminate/3 fans out across every
    %% service that context used, so the gy entry already covered this one.
    ok;
compensate(auth, #{aaa_auth := Auth}, Session, Opts) ->
    compensate_call(fun() -> smf_aaa_auth:terminate(Auth, Session, Opts) end, auth).

compensate_call(Fun, What) ->
    try Fun() of
	_ -> ok
    catch
	Class:Reason:St ->
	    ?LOG(error, "could not compensate the ~p session of a failed "
		 "establishment: ~p:~p~n~p", [What, Class, Reason, St]),
	    ok
    end.

%% Assign the local data F-TEID for each staged extra bearer, stopping at the
%% first failure. Was a lists:foldl with a throw inside; the throw would have
%% unwound past the Gx session opened just above it.
assign_extra_teids(Keys, PCtx, NodeCaps, Tunnel, BearerMap) ->
    lists:foldl(
      fun(_Key, {error, _} = Err) -> Err;
	 (Key, {ok, BM}) ->
	      smf_gsn_lib:assign_local_data_teid(Key, PCtx, NodeCaps, Tunnel, BM)
      end, {ok, BearerMap}, Keys).

pcc_has_rules(PCC) ->
    case smf_pcc_context:pcc_ctx_has_rules(PCC) of
	true -> ok;
	_    -> {error, ?CTX_ERR(?FATAL, user_authentication_failed)}
    end.

report_establishment_failures(GxReport, PCF, Session, SOpts)
  when map_size(GxReport) /= 0 ->
    {ok, PCF1, Session1, _} =
	smf_aaa_pcf:ccr_update(PCF, Session, GxReport, SOpts#{async => true}),
    {PCF1, Session1};
report_establishment_failures(_GxReport, PCF, Session, _SOpts) ->
    {PCF, Session}.

register_new_context(AccessTunnel, BearerMap, Context, Cause) ->
    case gtp_context:remote_context_register_new(AccessTunnel, BearerMap, Context) of
	ok ->
	    {ok, Cause};
	{error, #ctx_err{level = Level, where = {File, Line}}} ->
	    ?LOG(debug, #{type => ctx_err, level => Level, file => File,
			  line => Line, reply => system_failure}),
	    {error, system_failure}
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
%% the context. Yields {PCtx, BearerMap, SessionInfo} for the caller to commit --
%% the bearer map comes back because a modification that created PDRs has the UP's
%% allocated F-TEIDs folded into it (TS 23.214 5.4.3).
apply_bearer_change_proc(BearerMap, URRActions, SendEM, PCtx0, PCC) ->
    do([async_m ||
	   Issued <- async_m:lift(
		       smf_pfcp_context:modify_session_async(
			 PCC, URRActions, modify_opts(SendEM), BearerMap, PCtx0)),
	   Result <- smf_pfcp_context:await_modify(Issued),
	   async_m:return(apply_bearer_change_result(Result, URRActions))
       ]).

%% The conditional form the GTP request handlers share: re-provision the UPF only
%% when the access bearer actually changed, otherwise just ask for the usage
%% report. Both arms yield {PCtx, BearerMap, SessionInfo}; the unchanged arm never suspends,
%% so those requests still answer within the handler call.
access_bearer_change_proc(false, BearerMap, URRActions, _SendEM, PCtx0, _PCC) ->
    gtp_context:trigger_usage_report(self(), URRActions, PCtx0),
    async_m:return({PCtx0, BearerMap, #{}});
access_bearer_change_proc(true, BearerMap, URRActions, SendEM, PCtx0, PCC) ->
    apply_bearer_change_proc(BearerMap, URRActions, SendEM, PCtx0, PCC).

modify_opts(true)  -> #{send_end_marker => true};
modify_opts(false) -> #{}.

apply_bearer_change_result({PCtx, BearerMap, UsageReport, SessionInfo}, URRActions) ->
    gtp_context:usage_report(self(), URRActions, UsageReport),
    {PCtx, BearerMap, SessionInfo}.

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
	   UsageReport <- smf_pfcp_context:await_delete(smf_pfcp_context:delete_session_async(TermCause, PCtx)),
	   async_m:return(close_context(API, TermCause, UsageReport, Data))
       ]);
close_context_proc(_API, _TermCause, Data) ->
    async_m:return(Data).

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
