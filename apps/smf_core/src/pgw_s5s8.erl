%% Copyright 2015, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(pgw_s5s8).

-behaviour(gtp_api).

-compile([{parse_transform, do},
	  {parse_transform, cut}]).

-export([validate_options/1, init/2, request_spec/3,
	 handle_pdu/4,
	 handle_request/5, handle_response/5,
	 handle_event/4, terminate/3]).

-export([delete_context/4, close_context_proc/5]).
-export([init_session/4, init_session_from_gtp_req/5, update_session_from_gtp_req/4]).
-export([handle_dedicated_bearer_changes/3]).
-ignore_xref([handle_dedicated_bearer_changes/3]).	% called via Interface variable

-include_lib("kernel/include/logger.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include_lib("pfcplib/include/pfcp_packet.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").
-include_lib("smf_aaa/include/diameter_3gpp_ts29_212.hrl").
-include_lib("smf_aaa/include/smf_aaa_session.hrl").
-include("include/smf.hrl").

-import(smf_aaa_session, [to_session/1]).

-define(API, 's5/s8').
-define(GTP_v1_Interface, ggsn_gn).
-define(T3, 10 * 1000).
-define(N3, 5).

%%====================================================================
%% API
%%====================================================================

-define('Cause',					{v2_cause, 0}).
-define('Recovery',					{v2_recovery, 0}).
-define('IMSI',						{v2_international_mobile_subscriber_identity, 0}).
-define('MSISDN',					{v2_msisdn, 0}).
-define('PDN Address Allocation',			{v2_pdn_address_allocation, 0}).
-define('RAT Type',					{v2_rat_type, 0}).
-define('Sender F-TEID for Control Plane',		{v2_fully_qualified_tunnel_endpoint_identifier, 0}).
-define('Access Point Name',				{v2_access_point_name, 0}).
-define('Bearer Contexts to be created',		{v2_bearer_context, 0}).
-define('Bearer Contexts to be modified',		{v2_bearer_context, 0}).
-define('Bearer Contexts',				{v2_bearer_context, 0}).
-define('Protocol Configuration Options',		{v2_protocol_configuration_options, 0}).
-define('ME Identity',					{v2_mobile_equipment_identity, 0}).
-define('APN-AMBR',					{v2_aggregate_maximum_bit_rate, 0}).
-define('Bearer Level QoS',				{v2_bearer_level_quality_of_service, 0}).
-define('EPS Bearer ID',                                {v2_eps_bearer_id, 0}).
-define('Linked EPS Bearer ID',                         {v2_eps_bearer_id, 0}).
-define('SGW-U node name',                              {v2_fully_qualified_domain_name, 0}).
-define('Secondary RAT Usage Data Report',              {v2_secondary_rat_usage_data_report, 0}).
-define('Procedure Transaction Id',                     {v2_procedure_transaction_id, 0}).
-define('Traffic Aggregate Description',                {v2_traffic_aggregation_description, 0}).
-define('Flow QoS',                                     {v2_flow_quality_of_service, 0}).

-define('S5/S8-U SGW',  4).
-define('S5/S8-U PGW',  5).
-define('S5/S8-C SGW',  6).
-define('S5/S8-C PGW',  7).

-define(CAUSE_OK(Cause), (Cause =:= request_accepted orelse
			  Cause =:= request_accepted_partially orelse
			  Cause =:= new_pdp_type_due_to_network_preference orelse
			  Cause =:= new_pdp_type_due_to_single_address_bearer_only)).

request_spec(v1, Type, Cause) ->
    ?GTP_v1_Interface:request_spec(v1, Type, Cause);
request_spec(v2, _Type, Cause)
  when Cause /= undefined andalso not ?CAUSE_OK(Cause) ->
    [];
request_spec(v2, create_session_request, _) ->
    [{?'RAT Type',						mandatory},
     {?'Sender F-TEID for Control Plane',			mandatory},
     {?'Access Point Name',					mandatory},
     {?'APN-AMBR' ,						mandatory},
     {?'Bearer Contexts to be created',				mandatory}];
request_spec(v2, delete_session_request, _) ->
    [];
request_spec(v2, modify_bearer_request, _) ->
    [];
request_spec(v2, modify_bearer_command, _) ->
    [{?'APN-AMBR' ,						mandatory},
     {?'Bearer Contexts to be modified',			mandatory}];
request_spec(v2, delete_bearer_command, _) ->
    [{?'Bearer Contexts',					mandatory}];
request_spec(v2, resume_notification, _) ->
    [{?'IMSI',							mandatory}];
request_spec(v2, create_bearer_response, _) ->
    [{?'Cause',                                                         mandatory},
     {?'Bearer Contexts to be created',                                 mandatory}];
request_spec(v2, bearer_resource_command, _) ->
    [{?'Linked EPS Bearer ID',                                          mandatory},
     {?'Procedure Transaction Id',                                      mandatory},
     {?'Traffic Aggregate Description',                                 mandatory}];
request_spec(v2, _, _) ->
    [].

-define(HandlerDefaults, [{protocol, undefined}]).

validate_options(Options) ->
    ?LOG(debug, "GGSN S5/S8 Options: ~p", [Options]),
    gtp_context:validate_options(fun validate_option/2, Options, ?HandlerDefaults).

validate_option(Opt, Value) ->
    gtp_context:validate_option(Opt, Value).

init(_Opts, Data0) ->
    AAASession0 = smf_aaa_session:new_session(to_session([])),
    AppId = maps:get('AAA-Application-Id', AAASession0, default),
    {PCF, AAASession1} = smf_aaa_pcf:new(AppId, AAASession0),
    {Charging, AAASession2} = smf_aaa_charging:new(AppId, AAASession1),
    {AAAAuth, AAASession} = smf_aaa_auth:new(AppId, AAASession2),
    OCPcfg = maps:get('Offline-Charging-Profile', AAASession, #{}),
    PCC = #pcc_ctx{offline_charging_profile = OCPcfg},
    Data = Data0#{'Version' => v2, aaa_session => AAASession, pcf => PCF,
		  charging => Charging, aaa_auth => AAAAuth, pcc => PCC,
		  pending_bearers => #{}, retry_bearers => #{},
		  dedicated => #{}},
    {ok, smf_context:init_state(), Data}.

handle_event(Type, Content, State, #{'Version' := v1} = Data) ->
    ?GTP_v1_Interface:handle_event(Type, Content, State, Data);

handle_event(enter, _OldState, _State, _Data) ->
    keep_state_and_data;

handle_event(cast, {packet_in, _Socket, _IP, _Port, _Msg}, _State, _Data) ->
    ?LOG(warning, "packet_in not handled (yet): ~p", [_Msg]),
    keep_state_and_data;

handle_event({timeout, context_idle}, check_session_liveness, State,
	     #{context := Context, pfcp := PCtx} = Data) ->
    case smf_pfcp_context:session_liveness_check(PCtx) of
	ok ->
	    Actions = context_idle_action([], Context),
	    {keep_state, Data, Actions};
	_ ->
	    delete_context(undefined, cp_inactivity_timeout, State, Data)
    end;

handle_event(info, _Info, _State, _Data) ->
    keep_state_and_data.

handle_pdu(ReqKey, #gtp{ie = PDU} = Msg, _State,
	   #{context := Context, pfcp := PCtx,
	     bearers := BearerMap} = Data) ->
    ?LOG(debug, "GTP-U PGW: ~p, ~p", [ReqKey, gtp_c_lib:fmt_gtp(Msg)]),
    AccessBearer = smf_gsn_lib:get_access_default_bearer(BearerMap),
    SGiBearer = smf_gsn_lib:get_sgi_default_bearer(BearerMap),

    smf_gsn_lib:ip_pdu(PDU, AccessBearer, SGiBearer, Context, PCtx),
    {keep_state, Data}.

%% API Message Matrix:
%%
%% SGSN/MME/ TWAN/ePDG to PGW (S4/S11, S5/S8, S2a, S2b)
%%
%%   Create Session Request/Response
%%   Delete Session Request/Response
%%
%% SGSN/MME/ePDG to PGW (S4/S11, S5/S8, S2b)
%%
%%   Modify Bearer Request/Response
%%
%% SGSN/MME to PGW (S4/S11, S5/S8)
%%
%%   Change Notification Request/Response
%%   Resume Notification/Acknowledge

handle_request(ReqKey, #gtp{version = v1} = Msg, Resent, State, Data) ->
    ?GTP_v1_Interface:handle_request(ReqKey, Msg, Resent, State, Data#{'Version' => v1});
handle_request(ReqKey, #gtp{version = v2} = Msg, Resent, State, #{'Version' := v1} = Data) ->
    handle_request(ReqKey, Msg, Resent, State, Data#{'Version' => v2});

handle_request(_ReqKey, _Msg, true, _State, _Data) ->
    %% resent request
    keep_state_and_data;

handle_request(ReqKey,
	       #gtp{type = create_session_request,
		    ie = #{?'Access Point Name' := #v2_access_point_name{apn = APN}
			  } = IEs} = Request,
	       _Resent, State,
	       #{context := Context0, aaa_opts := AAAopts, node_selection := NodeSelect,
		 tunnels := #{'Access' := AccessTunnel0} = Tunnels,
		 aaa_session := S0, pcf := PCF0, charging := C0, aaa_auth := A0,
		 pcc := PCC0} = Data) ->
    #v2_bearer_context{group = DefaultBearerGroup} = get_default_bearer_ctx(IEs),
    PeerUpNode =
	case IEs of
	    #{?'SGW-U node name' := #v2_fully_qualified_domain_name{fqdn = SGWuFQDN}} ->
		SGWuFQDN;
	    _ -> []
	end,
    Services = [{'x-3gpp-upf', 'x-sxb'}],

    {ok, UpSelInfo} =
	smf_gtp_gsn_lib:connect_upf_candidates(APN, Services, NodeSelect, PeerUpNode),

    PAA = maps:get(?'PDN Address Allocation', IEs, undefined),
    DAF = proplists:get_bool('DAF', gtp_v2_c:get_indication_flags(IEs)),

    Context1 = update_context_from_gtp_req(Request, Context0),

    {AccessTunnel1, AccessBearer1} =
	case update_tunnel_from_gtp_req(Request, DefaultBearerGroup,
					AccessTunnel0, #bearer{interface = 'Access'}) of
	    {ok, Result1} -> Result1;
	    {error, Err1} -> throw(Err1#ctx_err{context = Context1, tunnel = AccessTunnel0})
	end,

    AccessTunnel =
	case gtp_path:bind_tunnel(AccessTunnel1) of
	    {ok, LT} -> LT;
	    {error, #ctx_err{} = Err2} ->
		throw(Err2#ctx_err{context = Context1, tunnel = AccessTunnel1});
	    {error, _} ->
		throw(?CTX_ERR(?FATAL, system_failure))
	end,

    gtp_context:terminate_colliding_context(AccessTunnel, Context1),

    SessionOpts0 = init_session(IEs, AccessTunnel, Context0, AAAopts),
    SessionOpts1 = init_session_from_gtp_req(IEs, AAAopts, AccessTunnel, AccessBearer1, SessionOpts0),
    %% SessionOpts = init_session_qos(ReqQoSProfile, SessionOpts1),

    %% Additional bearer contexts (handover) are staged into the bearer map from
    %% inside create_session, before the PFCP Session Establishment, so the whole
    %% PDN connection is provisioned in one exchange.
    StageExtra = stage_additional_bearers(IEs, Context1),

    {Verdict, Cause, SessionOpts, Context, BearerMap, ExtraBearers, PCC4, PCtx,
     S1, PCF1, C1, A1} =
       case smf_gtp_gsn_lib:create_session(APN, pdn_alloc(PAA), DAF, UpSelInfo,
					    S0, PCF0, C0, A0,
					    SessionOpts1, Context1, AccessTunnel, AccessBearer1,
					    PCC0, StageExtra) of
	   {ok, Result} -> Result;
	   {error, Err} -> throw(Err)
       end,

    #{dedicated := Dedicated, rejected := Rejected} = ExtraBearers,
    FinalData1 =
	Data#{context => Context, pfcp => PCtx, pcc => PCC4,
	      tunnels => Tunnels#{'Access' => AccessTunnel}, bearers => BearerMap,
	      dedicated => maps:merge(maps:get(dedicated, Data, #{}), Dedicated),
	      aaa_session => S1, pcf => PCF1, charging => C1, aaa_auth => A1},

    ResponseIEs = create_session_response(Cause, SessionOpts, IEs,
					  AccessTunnel,
					  BearerMap, Rejected,
					  Context),
    Response = response(create_session_response, AccessTunnel, ResponseIEs, Request),
    gtp_context:send_response(ReqKey, Request, Response),

    case Verdict of
	ok ->
	    Actions = context_idle_action([], Context),
	    {next_state, State#{session := connected}, FinalData1, Actions};
	_ ->
	    {next_state, State#{session := shutdown}, FinalData1}
    end;

%% TODO(#24):
%%  Only single or no bearer modification is supported by this and the next function.
%%  Both function are largy identical, only the bearer modification itself is the key
%%  difference. It should be possible to unify that into one handler
handle_request(ReqKey,
	       #gtp{type = modify_bearer_request,
		    ie = #{?'Bearer Contexts to be modified' :=
			       #v2_bearer_context{group = #{?'EPS Bearer ID' := EBI}}
			  } = IEs} = Request,
	       _Resent, #{session := connected} = State,
	       #{context := Context, pfcp := PCtx0,
		 tunnels := #{'Access' := AccessTunnelOld} = Tunnels,
		 bearers := BearerMap0,
		 aaa_session := S0, pcc := PCC} = Data) ->
    process_secondary_rat_usage_data_reports(IEs, Context, Data),
    AccessBearerOld = smf_gsn_lib:get_access_default_bearer(BearerMap0),

    {AccessTunnel0, AccessBearer} =
	case update_tunnel_from_gtp_req(
	       Request, AccessTunnelOld#tunnel{version = v2}, AccessBearerOld) of
	    {ok, Result1} -> Result1;
	    {error, Err1} -> throw(Err1#ctx_err{context = Context, tunnel = AccessTunnelOld})
	end,
    BearerMap = smf_gsn_lib:put_access_default_bearer(AccessBearer, BearerMap0),

    AccessTunnel = smf_gtp_gsn_lib:update_tunnel_endpoint(AccessTunnelOld, AccessTunnel0),
    {URRActions, S1} = update_session_from_gtp_req(IEs, S0, AccessTunnel, AccessBearer),
    SendEM = AccessTunnelOld#tunnel.version == AccessTunnel#tunnel.version,
    Proc = smf_gtp_gsn_lib:access_bearer_change_proc(
	     AccessBearer /= AccessBearerOld, BearerMap, URRActions, SendEM, PCtx0, PCC),
    Req = #{req_key => ReqKey, request => Request, ies => IEs, ebi => EBI,
	    context => Context, tunnels => Tunnels, access_tunnel => AccessTunnel,
	    bearers => BearerMap, aaa_session => S1},
    OkFun = fun(V, S, D) -> modify_bearer_ok(V, S, D, Req) end,
    ErrFun = fun(E, S, D) -> modify_bearer_err(E, S, D, Req) end,
    async_m:run_async(Proc, OkFun, ErrFun, State, Data);

handle_request(ReqKey,
	       #gtp{type = modify_bearer_request, ie = IEs} = Request,
	       _Resent, #{session := connected} = _State,
	       #{context := Context, pfcp := PCtx,
		 tunnels := #{'Access' := AccessTunnelOld} = Tunnels, bearers := BearerMap0,
		 aaa_session := S0} = Data)
  when not is_map_key(?'Bearer Contexts to be modified', IEs) ->
    process_secondary_rat_usage_data_reports(IEs, Context, Data),
    AccessBearerOld = smf_gsn_lib:get_access_default_bearer(BearerMap0),

    {AccessTunnel0, AccessBearer} =
	case update_tunnel_from_gtp_req(
	       Request, AccessTunnelOld#tunnel{version = v2}, AccessBearerOld) of
	    {ok, Result1} -> Result1;
	    {error, Err1} -> throw(Err1#ctx_err{context = Context, tunnel = AccessTunnelOld})
	end,

    AccessTunnel = smf_gtp_gsn_lib:update_tunnel_endpoint(AccessTunnelOld, AccessTunnel0),
    {URRActions, S1} = update_session_from_gtp_req(IEs, S0, AccessTunnel, AccessBearer),
    gtp_context:trigger_usage_report(self(), URRActions, PCtx),

    ResponseIEs = [#v2_cause{v2_cause = request_accepted}],
    Response = response(modify_bearer_response, AccessTunnel, ResponseIEs, Request),
    gtp_context:send_response(ReqKey, Request, Response),

    DataNew0 = Data#{pfcp => PCtx, tunnels => Tunnels#{'Access' => AccessTunnel}, aaa_session => S1},
    DataNew = retry_pending_bearers(AccessTunnel, DataNew0),
    Actions = context_idle_action([], Context),
    {keep_state, DataNew, Actions};

handle_request(#request{src = Src, ip = IP, port = Port} = ReqKey,
	       #gtp{type = modify_bearer_command,
		    seq_no = SeqNo,
		    ie = #{?'APN-AMBR' := AMBR,
			   ?'Bearer Contexts to be modified' :=
			       #v2_bearer_context{
				   group = #{?'EPS Bearer ID' := EBI} = Bearer}} = IEs},
	       _Resent, #{session := connected} = State,
	       #{context := Context, tunnels := #{'Access' := AccessTunnel},
		 bearers := BearerMap, aaa_session := S0} = Data) ->
    AccessBearer = smf_gsn_lib:get_access_default_bearer(BearerMap),
    {_URRActions, S1} = update_session_from_gtp_req(IEs, S0, AccessTunnel, AccessBearer),

    %% TS 23.401 5.4.2.2 steps 4-5: a Modify Bearer Command is an HSS-initiated
    %% Subscribed QoS Modification for the default bearer. The PGW reports the
    %% updated EPS Bearer QoS / APN-AMBR to the PCRF (a PCEF-initiated IP-CAN
    %% Session Modification, i.e. a Gx CCR-Update) and the PCRF MAY answer with an
    %% overriding decision that the PGW enforces in the Update Bearer Request --
    %% so this awaits the CCA instead of firing and forgetting (#23). Async, so
    %% the context stays responsive while the PCRF thinks.
    Cmd = #{req_key => ReqKey, seq_no => SeqNo, src => Src, ip => IP, port => Port,
	    ambr => AMBR, bearer => Bearer, ebi => EBI, old_sopts => S0},
    Proc = subscribed_qos_change_proc(Cmd, AccessTunnel, Context),
    OkFun = fun(_V, S, D) -> mbc_done(S, D, Context) end,
    ErrFun = fun(E, S, D) -> mbc_err(E, S, D, Cmd, AccessTunnel, Context) end,
    async_m:run_async(Proc, OkFun, ErrFun, State, Data#{aaa_session => S1});

handle_request(ReqKey,
	       #gtp{type = change_notification_request, ie = IEs} = Request,
	       _Resent, #{session := connected} = _State,
	       #{context := Context, pfcp := PCtx, tunnels := #{'Access' := AccessTunnel},
		 bearers := BearerMap, aaa_session := S0} = Data) ->
    process_secondary_rat_usage_data_reports(IEs, Context, Data),
    AccessBearer = smf_gsn_lib:get_access_default_bearer(BearerMap),

    {URRActions, S1} = update_session_from_gtp_req(IEs, S0, AccessTunnel, AccessBearer),
    gtp_context:trigger_usage_report(self(), URRActions, PCtx),

    ResponseIEs0 = [#v2_cause{v2_cause = request_accepted}],
    ResponseIEs = copy_ies_to_response(IEs, ResponseIEs0, [?'IMSI', ?'ME Identity']),
    Response = response(change_notification_response, AccessTunnel, ResponseIEs, Request),
    gtp_context:send_response(ReqKey, Request, Response),

    Actions = context_idle_action([], Context),
    {keep_state, Data#{aaa_session => S1}, Actions};

handle_request(ReqKey,
	       #gtp{type = suspend_notification} = Request,
	       _Resent, #{session := connected} = _State,
	       #{context := Context, tunnels := #{'Access' := AccessTunnel}}) ->
    ResponseIEs = [#v2_cause{v2_cause = request_accepted}],
    Response = response(suspend_acknowledge, AccessTunnel, ResponseIEs, Request),
    gtp_context:send_response(ReqKey, Request, Response),

    Actions = context_idle_action([], Context),
    {keep_state_and_data, Actions};

handle_request(ReqKey,
	       #gtp{type = resume_notification} = Request,
	       _Resent, #{session := connected} = _State,
	       #{context := Context, tunnels := #{'Access' := AccessTunnel}}) ->
    ResponseIEs = [#v2_cause{v2_cause = request_accepted}],
    Response = response(resume_acknowledge, AccessTunnel, ResponseIEs, Request),
    gtp_context:send_response(ReqKey, Request, Response),

    Actions = context_idle_action([], Context),
    {keep_state_and_data, Actions};

handle_request(ReqKey,
	       #gtp{type = bearer_resource_command,
		    ie = #{?'Linked EPS Bearer ID' :=
			       #v2_eps_bearer_id{eps_bearer_id = LinkedEBI},
			   ?'Procedure Transaction Id' :=
			       #v2_procedure_transaction_id{pti = PTI},
			   ?'Traffic Aggregate Description' :=
			       #v2_traffic_aggregation_description{value = TADBin}
			  } = IEs} = Request,
	       _Resent, #{session := connected} = State,
	       #{context := Context,
		 tunnels := #{'Access' := AccessTunnel},
		 bearers := BearerMap,
		 dedicated := Dedicated,
		 aaa_session := Session} = Data) ->
    FlowInfo = smf_tft:tft_to_flow_info(TADBin),
    {TADOp, TADContents} = smf_tft:decode_tad(TADBin),
    ReqQoS = extract_flow_qos(IEs),
    EBI = case IEs of
	      #{{v2_eps_bearer_id, 1} := #v2_eps_bearer_id{eps_bearer_id = E}} -> E;
	      _ -> 0
	  end,
    BCM = maps:get('Bearer-Control-Mode', Session,
		   ?'DIAMETER_GX_BEARER-CONTROL-MODE_UE_ONLY'),
    if EBI =:= 0, BCM =:= ?'DIAMETER_GX_BEARER-CONTROL-MODE_UE_NW' ->
	    QoS = ReqQoS,
	    QCI = maps:get('QoS-Class-Identifier', QoS, 9),
	    ARP0 = maps:get('Allocation-Retention-Priority', QoS, #{}),
	    PL = maps:get('Priority-Level', ARP0, 1),
	    PCI0 = maps:get('Pre-emption-Capability', ARP0, 1),
	    PVI = maps:get('Pre-emption-Vulnerability', ARP0, 0),
	    ARP = {PL, PCI0, PVI},
	    DefaultEBI = Context#context.default_bearer_id,
	    Data1 = initiate_create_dedicated_bearer(
		      PTI, QCI, ARP, QoS, FlowInfo,
		      DefaultEBI, AccessTunnel, Data),
	    gtp_context:request_finished(ReqKey),
	    Actions = context_idle_action([], Context),
	    {keep_state, Data1, Actions};
       EBI =/= 0, BCM =:= ?'DIAMETER_GX_BEARER-CONTROL-MODE_UE_NW',
       TADOp =:= delete_existing_tft,
       is_map_key({'Access', EBI}, BearerMap) ->
	    %% TS 23.401 5.4.5 step 5: the UE TAD removes the whole TFT of a
	    %% dedicated bearer, so all packet filters are gone -> run the PGW
	    %% Initiated Bearer Deactivation Procedure. Echo the PTI so the
	    %% Delete Bearer Request is tied to this UE-requested procedure
	    %% (TS 29.274 7.2.9.2, PTI Conditional). Ack the command the same
	    %% way the create branch does, then initiate the deactivation.
	    Data1 = initiate_ue_delete_dedicated_bearer(PTI, EBI, AccessTunnel, Data),
	    gtp_context:request_finished(ReqKey),
	    Actions = context_idle_action([], Context),
	    {keep_state, Data1, Actions};
       EBI =/= 0, BCM =:= ?'DIAMETER_GX_BEARER-CONTROL-MODE_UE_NW',
       TADOp =:= delete_packet_filters,
       is_map_key(EBI, Dedicated) ->
	    %% TS 23.401 5.4.5 step 5: the UE removes specific packet filters from a
	    %% dedicated bearer. Report the removed SDF filters to the PCRF (Gx
	    %% CCR-Update) and let its decision govern; when the bearer's last rule
	    %% is gone, deactivate it echoing the PTI (#22 Inc2), else re-provision
	    %% PFCP and emit an Update Bearer with the surviving TFT (#22 Inc3). Runs
	    %% async: park on the CCA (and the PFCP modify), ack/fail in the callbacks.
	    Proc = ue_delete_filters_proc(EBI, TADContents, PTI, AccessTunnel),
	    OkFun = fun(V, S, D) -> br_ok(V, S, D, ReqKey, Context) end,
	    ErrFun = fun(E, S, D) ->
			     br_err(E, S, D, ReqKey, Request,
				    AccessTunnel, LinkedEBI, PTI, Context)
		     end,
	    async_m:run_async(Proc, OkFun, ErrFun, State, Data);
       EBI =/= 0, BCM =:= ?'DIAMETER_GX_BEARER-CONTROL-MODE_UE_NW',
       TADOp =:= add_packet_filters,
       is_map_key(EBI, Dedicated) ->
	    %% TS 23.401 5.4.5 step 5: the UE adds packet filters to a dedicated
	    %% bearer. Report the new filters' content to the PCRF (Gx CCR-U
	    %% ADDITION); the resulting rule install grows the bearer's TFT ->
	    %% Update Bearer echoing the PTI (#22 Increment 4). Runs async.
	    Proc = ue_add_filters_proc(EBI, TADContents, PTI, AccessTunnel),
	    OkFun = fun(V, S, D) -> br_ok(V, S, D, ReqKey, Context) end,
	    ErrFun = fun(E, S, D) ->
			     br_err(E, S, D, ReqKey, Request,
				    AccessTunnel, LinkedEBI, PTI, Context)
		     end,
	    async_m:run_async(Proc, OkFun, ErrFun, State, Data);
       EBI =/= 0, BCM =:= ?'DIAMETER_GX_BEARER-CONTROL-MODE_UE_NW',
       TADOp =:= replace_packet_filters,
       is_map_key(EBI, Dedicated) ->
		    %% TS 23.401 5.4.5 step 5: the UE replaces packet filters on a
		    %% dedicated bearer. Report each as a MODIFICATION (the existing SDF
		    %% handle + the new content) to the PCRF; the rule change re-signals
		    %% the TFT -> Update Bearer echoing the PTI (#22 Increment 5). Async.
		    Proc = ue_replace_filters_proc(EBI, TADContents, PTI, AccessTunnel),
		    OkFun = fun(V, S, D) -> br_ok(V, S, D, ReqKey, Context) end,
		    ErrFun = fun(E, S, D) ->
				     br_err(E, S, D, ReqKey, Request,
					    AccessTunnel, LinkedEBI, PTI, Context)
			     end,
		    async_m:run_async(Proc, OkFun, ErrFun, State, Data);
       EBI =/= 0, BCM =:= ?'DIAMETER_GX_BEARER-CONTROL-MODE_UE_NW',
       TADOp =:= no_tft_operation,
       is_map_key(EBI, Dedicated),
       map_size(ReqQoS) =/= 0 ->
	    %% TS 23.401 5.4.5: the UE requests a QoS/GBR change on a dedicated
	    %% bearer with no TFT change (no_tft_operation). Report the requested
	    %% QoS to the PCRF (Gx CCR-U with QoS-Information); the authorized rule
	    %% QoS re-signals the bearer -> Update Bearer echoing the PTI
	    %% (#22 Increment 6). Async.
	    Proc = ue_qos_change_proc(EBI, ReqQoS, PTI, AccessTunnel),
	    OkFun = fun(V, S, D) -> br_ok(V, S, D, ReqKey, Context) end,
	    ErrFun = fun(E, S, D) ->
			     br_err(E, S, D, ReqKey, Request,
				    AccessTunnel, LinkedEBI, PTI, Context)
		     end,
	    async_m:run_async(Proc, OkFun, ErrFun, State, Data);
       true ->
	    %% Unhandled TAD op, or the target EBI is not a known dedicated bearer.
	    %% create / delete_existing_tft / delete / add / replace_packet_filters
	    %% are each handled above; anything else is rejected.
	    ResponseIEs = [#v2_cause{v2_cause = request_rejected},
			   #v2_eps_bearer_id{eps_bearer_id = LinkedEBI},
			   #v2_procedure_transaction_id{pti = PTI}],
	    Response = response(bearer_resource_failure_indication,
				AccessTunnel, ResponseIEs, Request),
	    gtp_context:send_response(ReqKey, Request, Response),
	    Actions = context_idle_action([], Context),
	    {keep_state, Data, Actions}
    end;

handle_request(ReqKey,
	       #gtp{type = delete_session_request, ie = IEs} = Request,
	       _Resent, #{session := connected} = State,
	       #{context := Context, tunnels := #{'Access' := AccessTunnel}} = Data0) ->
    FqTEID = maps:get(?'Sender F-TEID for Control Plane', IEs, undefined),

    case match_tunnel(?'S5/S8-C SGW', AccessTunnel, FqTEID) of
	ok ->
	    process_secondary_rat_usage_data_reports(IEs, Context, Data0),
	    Proc = smf_gtp_gsn_lib:close_context_proc(?API, normal, Data0),
	    OkFun = fun(Data, S, _D) ->
			    Response = response(delete_session_response, AccessTunnel,
						request_accepted),
			    gtp_context:send_response(ReqKey, Request, Response),
			    {next_state, S#{session := shutdown}, Data}
		    end,
	    async_m:run_async(Proc, OkFun, fun teardown_err/3, State, Data0);

	{error, ReplyIEs} ->
	    Response = response(delete_session_response, AccessTunnel, ReplyIEs),
	    gtp_context:send_response(ReqKey, Request, Response),
	    keep_state_and_data
    end;

handle_request(ReqKey,
	       #gtp{type = delete_bearer_command,
		    ie = #{?'Bearer Contexts' := BearerContexts}},
	       _Resent, #{session := connected} = State,
	       #{context := Context, tunnels := #{'Access' := AccessTunnel}} = Data0) ->
    %% MME-Initiated Dedicated Bearer Deactivation (TS 23.401 5.4.4.2,
    %% TS 29.274 7.2.17). The PGW does not delete immediately: for each
    %% commanded dedicated bearer it runs a PCEF-initiated IP-CAN Session
    %% Modification (Gx CCR-Update reporting the affected PCC rule(s) as
    %% INACTIVE), removes the rule(s) from the PCC context, and only then
    %% issues a network-initiated Delete Bearer Request. Default bearers are
    %% never deleted this way.
    DefaultEBI = Context#context.default_bearer_id,
    %% Strip every commanded bearer's rules from the PCC context first, then do
    %% ONE PFCP re-provision and ONE Gx report for the whole batch: modify_session/5
    %% diffs the final rule set against the stored one, and report_rules_inactive/2
    %% already carries a list of rule names in a single Charging-Rule-Report (#79).
    {Data1, EBIs, RuleNames} =
	ie_foldl(
	  fun(BearerContext, Acc) ->
		  prep_commanded_deactivation(BearerContext, DefaultEBI,
					      AccessTunnel, Acc)
	  end, {Data0, [], []}, BearerContexts),
    Data = case RuleNames of
	       [] -> Data1;
	       _  -> report_rules_inactive(RuleNames, Data1)
	   end,
    send_dedicated_bearers_delete(EBIs, AccessTunnel),
    %% Like modify_bearer_command, no direct response is sent; the follow-on
    %% Delete Bearer Request carries the procedure forward.
    gtp_context:request_finished(ReqKey),
    %% One async re-provision for the whole batch (#65/#79).
    #{bearers := BearerMap} = Data,
    async_m:run_async(reprovision_proc(BearerMap),
		      fun(_V, S, D) -> {next_state, S, D, context_idle_action([], Context)} end,
		      fun(_R, S, D) -> {next_state, S, D, context_idle_action([], Context)} end,
		      State, Data);

handle_request(ReqKey, _Msg, _Resent, _State, _Data) ->
    gtp_context:request_finished(ReqKey),
    keep_state_and_data.

%% close_context_proc/3 has no error channel — a Session Deletion that fails or
%% goes unanswered only costs the final usage report, and the teardown proceeds
%% either way. This exists so a driver-level failure (which would otherwise have
%% no callback) still lands the context in shutdown rather than wedging it live.
teardown_err(Reason, State, Data) ->
    ?LOG(error, "teardown procedure failed with ~p", [Reason]),
    {next_state, State#{session := shutdown}, Data}.

%% The Modify Bearer Response is built from the PFCP result, so it goes out from
%% here rather than from the handler. {next_state, ...} (not keep_state) because
%% the drained async_pending re-delivers what the coarse gate postponed.
modify_bearer_ok({PCtx, SessionInfo}, State, Data,
		 #{req_key := ReqKey, request := Request, ies := IEs, ebi := EBI,
		   context := Context, tunnels := Tunnels, access_tunnel := AccessTunnel,
		   bearers := BearerMap, aaa_session := S1}) ->
    ResponseIEs0 =
	case maps:is_key(?'Sender F-TEID for Control Plane', IEs) of
	    true ->
		%% take the presens of the FQ-TEID element as SGW change indication
		%%
		%% 3GPP TS 29.274, Sect. 7.2.7 Modify Bearer Request says that we should
		%% consider the content as well, but in practice that is not stable enough
		%% in the presense of middle boxes between the SGW and the PGW
		%%
		[EBI,				%% Linked EPS Bearer ID
		 #v2_apn_restriction{restriction_type_value = 0},
		 context_charging_id(Context) |
		 [#v2_msisdn{msisdn = Context#context.msisdn} || Context#context.msisdn /= undefined]];
	    false ->
		[]
	end,

    ResponseIEs = [#v2_cause{v2_cause = request_accepted},
		   #v2_bearer_context{
		      group=[#v2_cause{v2_cause = request_accepted},
			     context_charging_id(Context),
			     EBI]} |
		   ResponseIEs0],
    Response = response(modify_bearer_response, AccessTunnel, ResponseIEs, Request),
    gtp_context:send_response(ReqKey, Request, Response),

    DataNew0 = Data#{pfcp => PCtx, tunnels => Tunnels#{'Access' => AccessTunnel},
		     bearers => BearerMap, aaa_session => maps:merge(S1, SessionInfo)},
    DataNew = retry_pending_bearers(AccessTunnel, DataNew0),
    Actions = context_idle_action([], Context),
    {next_state, State, DataNew, Actions}.

%% The only failure the procedure can produce is the FATAL #ctx_err from
%% modify_session_result/2. Decorate and re-throw so async_dispatch's #ctx_err
%% catch runs handle_ctx_error — exactly what the synchronous branch did.
modify_bearer_err(#ctx_err{} = E, _State, _Data,
		  #{context := Context, access_tunnel := AccessTunnel}) ->
    throw(E#ctx_err{context = Context, tunnel = AccessTunnel}).

handle_response(ReqInfo, #gtp{version = v1} = Msg, Request, State, Data) ->
    ?GTP_v1_Interface:handle_response(ReqInfo, Msg, Request, State, Data);

handle_response({create_bearer, PgwFTEID},
		#gtp{type = create_bearer_response,
		     ie = #{?'Cause' := #v2_cause{v2_cause = Cause},
			    ?'Bearer Contexts to be created' :=
				#v2_bearer_context{group = BearerCtxGroup}}},
		_Request, #{session := connected} = State,
		#{bearers := BearerMap0, pcc := PCC,
		  pending_bearers := Pending0} = Data0)
  when ?CAUSE_OK(Cause) ->
    %% The message-level Cause may be request_accepted_partially, so the
    %% per-bearer Cause inside the Bearer Context is authoritative for this
    %% bearer (TS 29.274 7.2.4, TS 29.212 4.5.12). Only install the bearer
    %% when its own Cause is OK; otherwise treat it as a failed activation.
    case ?CAUSE_OK(bearer_context_cause(BearerCtxGroup)) of
	true ->
	    case maps:take(PgwFTEID, Pending0) of
		{{QCI, ARP, AccessBearer0, ChId}, Pending} ->
		    #{?'EPS Bearer ID' := #v2_eps_bearer_id{eps_bearer_id = EBI}} = BearerCtxGroup,
		    AccessBearer = update_bearer_from_response(BearerCtxGroup, AccessBearer0),
		    PgwBI = <<EBI:8>>,
		    BearerMap = BearerMap0#{{'Access', EBI} => AccessBearer,
					    {qci_arp, QCI, ARP} => EBI,
					    {bearer_id, PgwBI} => EBI},
		    Desc = smf_gsn_lib:normalize_bearer(EBI, QCI, ARP, PCC, ChId),
		    Dedicated = maps:get(dedicated, Data0, #{}),
		    Data1 = Data0#{bearers := BearerMap,
				   pending_bearers := Pending,
				   dedicated := Dedicated#{EBI => Desc},
				   retry_bearers :=
				       maps:remove(PgwFTEID,
						   maps:get(retry_bearers, Data0, #{}))},
		    Data = report_successful_resource_allocation(QCI, ARP, Data1),
		    %% Re-provision the UPF asynchronously (#65). The bearer is
		    %% already committed above; a failed modification only costs
		    %% the new PCtx, as it did when this call blocked.
		    async_m:run_async(reprovision_proc(BearerMap),
				      fun(_V, S, D) -> {next_state, S, D} end,
				      fun(_R, S, D) -> {next_state, S, D} end,
				      State, Data);
		error ->
		    keep_state_and_data
	    end;
	false ->
	    handle_create_bearer_failure(PgwFTEID, State, Data0)
    end;

handle_response({create_bearer, PgwFTEID},
		#gtp{type = create_bearer_response,
		     ie = #{?'Cause' :=
				#v2_cause{v2_cause =
					      ue_is_temporarily_not_reachable_due_to_power_saving}}},
		_Request, _State, Data0) ->
    %% Temporary condition (TS 29.274 8.4, TS 23.401 5.4.1 step 12): the UE is
    %% not reachable due to power saving. Do NOT remove the PCC rule or report a
    %% failure to the PCRF; hold the procedure and re-attempt the Create Bearer
    %% Request once the UE is reachable again (next Modify Bearer Request).
    handle_create_bearer_power_saving(PgwFTEID, Data0);

handle_response({create_bearer, PgwFTEID},
		#gtp{type = create_bearer_response},
		_Request, State, Data0) ->
    %% Dedicated bearer could not be activated (message-level Cause not OK).
    handle_create_bearer_failure(PgwFTEID, State, Data0);

handle_response({create_bearer, _PgwFTEID}, timeout,
		#gtp{type = create_bearer_request}, _State, _Data) ->
    ?LOG(error, "Create Bearer Request timed out"),
    keep_state_and_data;

handle_response({delete_dedicated_bearers, EBIs},
		#gtp{type = delete_bearer_response,
		     ie = #{?'Cause' := #v2_cause{v2_cause = _Cause}}},
		_Request, State,
		#{bearers := BearerMap0, dedicated := Ded0} = Data0) ->
    %% TODO(#35): honor the per-bearer Cause in the Delete Bearer Response and release
    %% only accepted EBIs; today the whole batch is released (as the single-EBI clause did).
    BearerMap = lists:foldl(
		  fun(EBI, BM) ->
			  smf_gsn_lib:remove_bearer_metadata_for_ebi(
			    EBI, maps:remove({'Access', EBI}, BM))
		  end, BearerMap0, EBIs),
    Data1 = Data0#{dedicated := maps:without(EBIs, Ded0),
		   bearers := BearerMap},
    %% Re-provision PFCP asynchronously (#65). The bearer removal is committed
    %% above either way -- this path always treated a failed modification as
    %% non-fatal -- so only the new PCtx rides on the reply.
    async_m:run_async(reprovision_proc(BearerMap),
		      fun(_V, S, D) -> {next_state, S, D} end,
		      fun(_R, S, D) -> {next_state, S, D} end,
		      State, Data1);

handle_response({delete_dedicated_bearers, _EBIs}, timeout,
		#gtp{type = delete_bearer_request}, _State, _Data) ->
    ?LOG(error, "batched Delete Dedicated Bearer Request timed out"),
    keep_state_and_data;

handle_response({update_dedicated_bearers, Kind, Staged},
		#gtp{type = update_bearer_response,
		     ie = #{?'Bearer Contexts to be modified' := BearerCtxs}},
		_Request, #{session := connected} = State,
		#{tunnels := #{'Access' := AccessTunnel}} = Data) ->
    %% Network-initiated batched Update Bearer Request (M3 rule change / M5
    %% subscribed-QoS fan-out). Per-bearer Cause governs (TS 29.274 §7.2.15).
    %%
    %% The fold is pure; the UPF re-provision and the Gx report happen ONCE for
    %% the whole batch. modify_session/5 reconciles the final PCC context against
    %% the stored rule set and sends only the diff, and report_bearer_failure/2
    %% carries a list of rule names in one Charging-Rule-Report -- so per-bearer
    %% calls meant N PFCP requests and N CCR-Updates for one response (#81).
    {Data1, RuleNames, DelEBIs} =
	ie_foldl(fun(BC, Acc) -> apply_bearer_update_result(Kind, BC, Staged, Acc) end,
		 {Data, [], []}, BearerCtxs),
    finish_update_bearer_failures({Data1, RuleNames, DelEBIs}, AccessTunnel, State);

handle_response({update_dedicated_bearers, Kind, Staged},
		#gtp{type = update_bearer_response,
		     ie = #{?'Cause' := #v2_cause{v2_cause = Cause}}},
		_Request, #{session := connected} = State,
		#{tunnels := #{'Access' := AccessTunnel}} = Data) ->
    %% Legitimate message-level rejection with NO per-bearer Bearer Contexts
    %% (e.g. context_not_found, TS 29.274 §7.2.16) -- there is nothing to fold
    %% per-bearer, so apply the message-level Cause class to every EBI staged
    %% for this batch instead of crashing with function_clause.
    ?LOG(warning, "batched Update Bearer Response carried no Bearer Contexts; "
	 "applying message-level Cause ~p to ~p staged bearer(s)",
	 [Cause, map_size(Staged)]),
    case smf_gsn_lib:bearer_update_cause_class(Cause) of
	accepted ->
	    {keep_state,
	     maps:fold(fun(EBI, _Desc, D) -> commit_staged_descriptor(EBI, Staged, D) end,
		       Data, Staged)};
	temporary ->
	    ?LOG(warning, "batched Update Bearer Request temporarily rejected (~p); "
		 "change not applied this round", [Cause]),
	    {keep_state, Data};
	terminal ->
	    finish_update_bearer_failures(
	      maps:fold(fun(EBI, _Desc, Acc) ->
				stage_update_bearer_failure(Kind, EBI, Cause, Acc)
			end, {Data, [], []}, Staged),
	      AccessTunnel, State)
    end;

handle_response({update_dedicated_bearers, Kind, Staged}, timeout,
		#gtp{type = update_bearer_request}, #{session := connected} = State,
		#{tunnels := #{'Access' := AccessTunnel}} = Data) ->
    ?LOG(error, "batched Update Bearer Request timed out; ~p bearer(s) affected",
	 [map_size(Staged)]),
    finish_update_bearer_failures(
      maps:fold(fun(EBI, _Desc, Acc) ->
			stage_update_bearer_failure(Kind, EBI, request_rejected, Acc)
		end, {Data, [], []}, Staged),
      AccessTunnel, State);

handle_response({CommandReqKey, OldSOpts},
		#gtp{type = update_bearer_response,
		     ie = #{?'Cause' := #v2_cause{v2_cause = Cause},
			    ?'Bearer Contexts to be modified' :=
				#v2_bearer_context{
				   group = #{?'Cause' := #v2_cause{v2_cause = BearerCause}}
				  }} = IEs},
		_Request, #{session := connected} = State,
		#{pfcp := PCtx, tunnels := #{'Access' := AccessTunnel}, bearers := BearerMap,
		  aaa_session := S0} = Data) ->
    gtp_context:request_finished(CommandReqKey),
    AccessBearer = smf_gsn_lib:get_access_default_bearer(BearerMap),

    if Cause =:= request_accepted andalso BearerCause =:= request_accepted ->
	    {_URRActions, S1} = update_session_from_gtp_req(IEs, S0, AccessTunnel, AccessBearer),
	    URRActions = gtp_context:collect_charging_events(OldSOpts, S1),
	    gtp_context:trigger_usage_report(self(), URRActions, PCtx),
	    {keep_state, Data#{aaa_session => S1}};
       true ->
	    ?LOG(error, "Update Bearer Request failed with ~p/~p",
			[Cause, BearerCause]),
	    delete_context(undefined, link_broken, State, Data)
    end;

handle_response({CommandReqKey, _}, timeout, #gtp{type = update_bearer_request},
		#{session := connected} = State, Data) ->
    ?LOG(error, "Update Bearer Request failed with timeout"),
    gtp_context:request_finished(CommandReqKey),
    delete_context(undefined, link_broken, State, Data);

handle_response({From, TermCause}, timeout, #gtp{type = delete_bearer_request},
		State, Data0) ->
    Proc = smf_gtp_gsn_lib:close_context_proc(?API, TermCause, Data0),
    OkFun = fun(Data, S, _D) -> delete_bearer_done(Data, S, From, {error, timeout}) end,
    async_m:run_async(Proc, OkFun, fun teardown_err/3, State, Data0);

handle_response({From, TermCause},
		#gtp{type = delete_bearer_response,
		     ie = #{?'Cause' := #v2_cause{v2_cause = RespCause}} = IEs},
		_Request, State,
		#{context := Context} = Data0) ->
    process_secondary_rat_usage_data_reports(IEs, Context, Data0),
    Proc = smf_gtp_gsn_lib:close_context_proc(?API, TermCause, Data0),
    OkFun = fun(Data, S, _D) -> delete_bearer_done(Data, S, From, {ok, RespCause}) end,
    async_m:run_async(Proc, OkFun, fun teardown_err/3, State, Data0);

handle_response(_CommandReqKey, _Response, _Request, #{session := SState}, _Data)
  when SState =/= connected ->
    keep_state_and_data.

%% The delete_bearer caller (if there is one — the cast entry points pass a bare
%% atom) is answered once the teardown is actually done, as it was when the PFCP
%% deletion blocked inline.
delete_bearer_done(Data, State, From, Reply) ->
    if is_tuple(From) -> gen_statem:reply(From, Reply);
       true -> ok
    end,
    {next_state, State#{session := shutdown}, Data}.

%%%===================================================================
%%% Dedicated Bearer helpers
%%%===================================================================

%% TS 23.401 5.4.2.2 step 5: when a Modify Bearer Command (HSS Initiated
%% Subscribed QoS Modification) changes the default bearer's subscribed ARP, the
%% PGW must also modify every dedicated bearer that still carries the previously
%% subscribed ARP. Compare the old subscribed ARP (from the session as it stood
%% before the command was folded in) with the new ARP from the command's Bearer
%% Level QoS; if they differ, emit a network-initiated Update Bearer Request per
%% affected dedicated bearer with QCI/GBR/MBR unchanged but the new ARP.
%% NewARP is the *effective* ARP -- the PCRF's authorized one when it provisioned
%% a Default-EPS-Bearer-QoS, else the command's (see effective_arp/2).
fan_out_subscribed_arp_change(OldSOpts, NewARP, AMBR, Context, AccessTunnel,
			      #{dedicated := Dedicated} = Data) ->
    OldARP = session_default_arp(OldSOpts),
    DefaultEBI = Context#context.default_bearer_id,
    case NewARP =/= undefined andalso OldARP =/= undefined andalso NewARP =/= OldARP of
	true ->
	    %% TODO(#31): the is_map(QoS) guard skips a descriptor with undefined
	    %% QoS; the pre-branch code still fanned out with a QCI-only fallback.
	    {Contexts, Staged} =
		maps:fold(
		  fun(EBI, #ded_bearer{arp = ARP, qos = QoS} = Desc, {Cs, St})
			when ARP =:= OldARP, EBI =/= DefaultEBI, is_map(QoS) ->
			  NewQoS = set_qos_arp(QoS, NewARP),
			  NewDesc = Desc#ded_bearer{arp = NewARP, qos = NewQoS},
			  {[{EBI, NewQoS, undefined} | Cs], St#{EBI => NewDesc}};
		     (_, _, Acc) ->
			  Acc
		  end, {[], #{}}, Dedicated),
	    send_dedicated_bearers_update(subscribed_qos, Contexts, [AMBR],
					  Staged, AccessTunnel),
	    rekey_default_qci_arp(DefaultEBI, NewARP, Data);
	false ->
	    Data
    end.

%% New ARP carried in the command's Bearer Level QoS, as a {PL, PCI, PVI} tuple.
command_bearer_arp(#{?'Bearer Level QoS' :=
			 #v2_bearer_level_quality_of_service{pl = PL, pci = PCI, pvi = PVI}})
  when is_integer(PL) ->
    {PL, PCI, PVI};
command_bearer_arp(_) ->
    undefined.

%% Old subscribed ARP of the default bearer, read from the session's
%% 'QoS-Information' before the command was applied, as a {PL, PCI, PVI} tuple.
session_default_arp(#{'QoS-Information' := #{'Allocation-Retention-Priority' := ARP}})
  when is_map(ARP) ->
    {maps:get('Priority-Level', ARP, 1),
     maps:get('Pre-emption-Capability', ARP, 1),
     maps:get('Pre-emption-Vulnerability', ARP, 0)};
session_default_arp(_) ->
    undefined.

%% Overwrite the Allocation-Retention-Priority in a QoS-Information map.
set_qos_arp(QoS, NewARP) ->
    QoS#{'Allocation-Retention-Priority' => arp_to_map(NewARP)}.

%% Emit one network-initiated Update Bearer Request (TS 29.274 §7.2.15) carrying a
%% list of Bearer Contexts. The network-initiated form MAY batch bearers of the
%% same PDN connection — contrast the UE-requested single-context invariant
%% (§7.2.15 NOTE), which is handled on a separate path and never uses this helper.
%% Kind (rule_change | subscribed_qos) selects the response failure policy; Staged
%% maps each EBI to the descriptor to commit when that bearer is accepted.
send_dedicated_bearers_update(_Kind, [], _ExtraIEs, _Staged, _AccessTunnel) ->
    ok;
send_dedicated_bearers_update(Kind, Contexts, ExtraIEs, Staged, AccessTunnel) ->
    BearerCtxIEs = [update_bearer_context(EBI, QoS, FlowInfo)
		    || {EBI, QoS, FlowInfo} <- Contexts],
    Type = update_bearer_request,
    RequestIEs0 = ExtraIEs ++ BearerCtxIEs,
    RequestIEs = gtp_v2_c:build_recovery(Type, AccessTunnel, false, RequestIEs0),
    send_request(AccessTunnel, ?T3, ?N3, Type, RequestIEs,
		 {update_dedicated_bearers, Kind, Staged}).

update_bearer_context(EBI, QoS, FlowInfo) ->
    Group0 = [#v2_eps_bearer_id{eps_bearer_id = EBI}, encode_bearer_level_qos(QoS)],
    Group = case FlowInfo of
		[_ | _] ->
		    TFTBin = smf_tft:flow_info_to_tft(FlowInfo),
		    Group0 ++ [#v2_eps_bearer_level_traffic_flow_template{value = TFTBin}];
		_ ->
		    Group0
	    end,
    #v2_bearer_context{group = Group}.

arp_to_map({PL, PCI, PVI}) ->
    #{'Priority-Level' => PL,
      'Pre-emption-Capability' => PCI,
      'Pre-emption-Vulnerability' => PVI}.

encode_bearer_level_qos(#{'QoS-Class-Identifier' := QCI} = QoS) ->
    MBR4ul = maps:get('Max-Requested-Bandwidth-UL', QoS, 0),
    MBR4dl = maps:get('Max-Requested-Bandwidth-DL', QoS, 0),
    GBR4ul = maps:get('Guaranteed-Bitrate-UL', QoS, 0),
    GBR4dl = maps:get('Guaranteed-Bitrate-DL', QoS, 0),
    ARP = maps:get('Allocation-Retention-Priority', QoS, #{}),
    PL  = maps:get('Priority-Level', ARP, 1),
    PCI = maps:get('Pre-emption-Capability', ARP, 1),
    PVI = maps:get('Pre-emption-Vulnerability', ARP, 0),
    #v2_bearer_level_quality_of_service{
       pci = PCI, pl = PL, pvi = PVI, label = QCI,
       maximum_bit_rate_for_uplink      = MBR4ul div 1000,
       maximum_bit_rate_for_downlink    = MBR4dl div 1000,
       guaranteed_bit_rate_for_uplink   = GBR4ul div 1000,
       guaranteed_bit_rate_for_downlink = GBR4dl div 1000};
encode_bearer_level_qos(_) ->
    #v2_bearer_level_quality_of_service{
       pci = 1, pl = 1, pvi = 0, label = 9,
       maximum_bit_rate_for_uplink = 0,
       maximum_bit_rate_for_downlink = 0,
       guaranteed_bit_rate_for_uplink = 0,
       guaranteed_bit_rate_for_downlink = 0}.

extract_flow_qos(#{?'Flow QoS' :=
		       #v2_flow_quality_of_service{
			  label = QCI,
			  maximum_bit_rate_for_uplink = MBR4ul,
			  maximum_bit_rate_for_downlink = MBR4dl,
			  guaranteed_bit_rate_for_uplink = GBR4ul,
			  guaranteed_bit_rate_for_downlink = GBR4dl}}) ->
    #{'QoS-Class-Identifier' => QCI,
      'Max-Requested-Bandwidth-UL' => MBR4ul * 1000,
      'Max-Requested-Bandwidth-DL' => MBR4dl * 1000,
      'Guaranteed-Bitrate-UL' => GBR4ul * 1000,
      'Guaranteed-Bitrate-DL' => GBR4dl * 1000};
extract_flow_qos(_) ->
    #{}.

update_bearer_field(
  _, #v2_fully_qualified_tunnel_endpoint_identifier{
	 interface_type = ?'S5/S8-U SGW',
	 key = TEI, ipv4 = IP4, ipv6 = IP6}, Bearer) ->
    IP = if is_binary(IP4), byte_size(IP4) =:= 4 -> smf_inet:bin2ip(IP4);
	    is_binary(IP6), byte_size(IP6) =:= 16 -> smf_inet:bin2ip(IP6);
	    true -> undefined
	 end,
    Bearer#bearer{remote = #fq_teid{ip = IP, teid = TEI}};
update_bearer_field(_, _, Bearer) ->
    Bearer.

update_bearer_from_response(BearerCtxGroup, Bearer0) ->
    maps:fold(fun update_bearer_field/3, Bearer0, BearerCtxGroup).

%% Get the default bearer context from IEs.
%% Single bearer: the record itself is the default.
%% Multiple bearers (list): the top-level EBI IE identifies the default.
get_default_bearer_ctx(#{?'EPS Bearer ID' := #v2_eps_bearer_id{eps_bearer_id = DefaultEBI},
			 ?'Bearer Contexts to be created' := BearerCtxs})
  when is_list(BearerCtxs) ->
    find_bearer_by_ebi(DefaultEBI, BearerCtxs);
get_default_bearer_ctx(#{?'Bearer Contexts to be created' := #v2_bearer_context{} = Ctx}) ->
    Ctx;
get_default_bearer_ctx(_) ->
    undefined.

find_bearer_by_ebi(EBI, [#v2_bearer_context{
			     group = #{?'EPS Bearer ID' :=
					   #v2_eps_bearer_id{eps_bearer_id = EBI}}} = Ctx | _]) ->
    Ctx;
find_bearer_by_ebi(EBI, [_ | Rest]) ->
    find_bearer_by_ebi(EBI, Rest).

%% Process additional bearer contexts in CSR.
%% In GTPv2, multiple bearers all use the same instance (0); put_ie stores them as a list.
%% Skip the default bearer (already handled by create_session) and install the rest.
%% Build the staging fun smf_gtp_gsn_lib:create_session/14 applies to the bearer
%% map just before the PFCP Session Establishment. A Create Session Request may
%% carry several Bearer Contexts to be created (handover); all of them belong in
%% the one establishment exchange, so this only accumulates -- nothing here talks
%% to the UPF.
stage_additional_bearers(IEs, #context{default_bearer_id = DefaultEBI}) ->
    BearerCtxs = case IEs of
                     #{?'Bearer Contexts to be created' := L} when is_list(L) -> L;
                     #{?'Bearer Contexts to be created' := S} -> [S];
                     _ -> []
                 end,
    fun(BearerMap, _Context) ->
	    lists:foldl(
	      fun(#v2_bearer_context{group = #{?'EPS Bearer ID' :=
						   #v2_eps_bearer_id{eps_bearer_id = EBI}} = Group},
		  Acc) when EBI /= DefaultEBI ->
		      stage_additional_bearer(EBI, Group, Acc);
		 (_, Acc) ->
		      Acc
	      end, {BearerMap, #{}, []}, BearerCtxs)
    end.

%% Stage one additional bearer into the bearer map and descriptor table. Purely
%% accumulative: it fills in the REMOTE side from the request and names its key,
%% leaving the local F-TEID to smf_gtp_gsn_lib:create_session/14 -- which assigns
%% it exactly as it does the default bearer's, so an FTUP node allocates for this
%% bearer too, in the same establishment exchange.
stage_additional_bearer(EBI, BearerGroup, {BearerMap0, Ded0, Keys}) ->
    Key = {'Access', EBI},
    AccessBearer = update_bearer_from_response(BearerGroup, #bearer{interface = 'Access'}),
    BearerMap1 = BearerMap0#{Key => AccessBearer},
    case BearerGroup of
	#{?'Bearer Level QoS' := #v2_bearer_level_quality_of_service{} = BLQoS} ->
	    #ded_bearer{qci = QCI, arp = ARP} = Desc = ded_bearer_from_blqos(EBI, BLQoS),
	    {BearerMap1#{{qci_arp, QCI, ARP} => EBI}, Ded0#{EBI => Desc}, [Key | Keys]};
	_ ->
	    {BearerMap1, Ded0, [Key | Keys]}
    end.

create_dedicated_bearer(PTI, LinkedEBI, QoS, TFTBin, ChId, AccessBearer, Tunnel) ->
    BearerCtx =
	[#v2_eps_bearer_id{eps_bearer_id = 0},
	 encode_bearer_level_qos(QoS),
	 #v2_eps_bearer_level_traffic_flow_template{value = TFTBin},
	 s5s8_pgw_gtp_u_tei(1, AccessBearer),
	 #v2_charging_id{id = <<ChId:32>>}],
    RequestIEs0 = [#v2_eps_bearer_id{eps_bearer_id = LinkedEBI},
		   #v2_bearer_context{group = BearerCtx}],
    RequestIEs1 = case PTI of
		      undefined -> RequestIEs0;
		      _ -> [#v2_procedure_transaction_id{pti = PTI} | RequestIEs0]
		  end,
    RequestIEs = gtp_v2_c:build_recovery(create_bearer_request, Tunnel, false, RequestIEs1),
    PgwFTEID = AccessBearer#bearer.local,
    send_request(Tunnel, ?T3, ?N3, create_bearer_request, RequestIEs,
		 {create_bearer, PgwFTEID}).

%% Emit one network-initiated Delete Bearer Request (TS 29.274 §7.2.9.2) carrying a
%% list of dedicated EBIs. Never carries the LBI — that tears down the whole PDN
%% connection (TS 23.401 §5.4.4.1). No PTI (network-initiated).
send_dedicated_bearers_delete([], _Tunnel) ->
    ok;
send_dedicated_bearers_delete(EBIs, Tunnel) ->
    RequestIEs0 = [#v2_eps_bearer_id{instance = 1, eps_bearer_id = EBI} || EBI <- EBIs],
    RequestIEs = gtp_v2_c:build_recovery(delete_bearer_request, Tunnel, false, RequestIEs0),
    send_request(Tunnel, ?T3, ?N3, delete_bearer_request, RequestIEs,
		 {delete_dedicated_bearers, EBIs}).

handle_dedicated_bearer_changes(OldPCC, NewPCC,
				#{bearers := BearerMap,
				  tunnels := #{'Access' := AccessTunnel},
				  context := #context{default_bearer_id = DefaultEBI},
				  aaa_session := Session} = Data) ->
    BCM = maps:get('Bearer-Control-Mode', Session,
		   ?'DIAMETER_GX_BEARER-CONTROL-MODE_UE_ONLY'),
    NewBearers = smf_gsn_lib:detect_new_bearers(OldPCC, NewPCC, BearerMap, BCM),
    Data1 = lists:foldl(
	      fun({QCI, ARP, QoS, FlowInfo}, D) ->
		  initiate_create_dedicated_bearer(undefined, QCI, ARP, QoS, FlowInfo,
						   DefaultEBI, AccessTunnel, D)
	      end, Data, NewBearers),
    Dedicated = maps:get(dedicated, Data, #{}),
    ModifiedBearers = smf_gsn_lib:detect_modified_bearers(NewPCC, Dedicated),
    Contexts = [{EBI, QoS, FlowInfo}
		|| {EBI, QoS, FlowInfo, _Desc} <- ModifiedBearers],
    Staged = maps:from_list([{EBI, Desc}
			     || {EBI, _QoS, _FlowInfo, Desc} <- ModifiedBearers]),
    send_dedicated_bearers_update(rule_change, Contexts, [], Staged, AccessTunnel),
    RemovedEBIs0 = smf_gsn_lib:detect_removed_bearers(OldPCC, NewPCC, BearerMap),
    %% The default bearer's EBI can appear here (its {qci_arp,QCI,ARP} entry
    %% loses its last bound rule just like a dedicated bearer's would). Never
    %% name the LBI in a Delete Bearer Request -- that tears down the whole
    %% PDN connection (TS 23.401 §5.4.4.1).
    RemovedEBIs = lists:filter(fun(EBI) -> EBI =/= DefaultEBI end, RemovedEBIs0),
    case RemovedEBIs0 -- RemovedEBIs of
	[] -> ok;
	_  -> ?LOG(warning, "detect_removed_bearers named the default bearer ~p; "
		   "ignoring (never emit a Delete Bearer Request for the LBI)",
		   [DefaultEBI])
    end,
    send_dedicated_bearers_delete(RemovedEBIs, AccessTunnel),
    Data1.

initiate_create_dedicated_bearer(PTI, QCI, ARP, QoS, FlowInfo, DefaultEBI, AccessTunnel,
				 #{bearers := BearerMap0, pfcp := PCtx0,
				   pending_bearers := Pending0} = Data) ->
    %% Derive PGW GTP-U IP and VRF from the existing default Access bearer
    DefaultBearer = smf_gsn_lib:get_access_default_bearer(BearerMap0),
    case DefaultBearer of
	#bearer{vrf = VRF, local = #fq_teid{ip = PgwUIP}} when PgwUIP /= v4, PgwUIP /= v6 ->
	    %% Allocate a real TEID from the TEI manager
	    case smf_tei_mngr:alloc_tei(PCtx0) of
		{ok, DataTEI} ->
		    AccessBearer = #bearer{interface = 'Access',
					   vrf = VRF,
					   local = #fq_teid{ip = PgwUIP, teid = DataTEI}},
		    TFTBin = smf_tft:flow_info_to_tft(FlowInfo),
		    ChId = smf_gtp_c_socket:get_uniq_id(AccessTunnel#tunnel.socket),
		    create_dedicated_bearer(PTI, DefaultEBI, QoS, TFTBin, ChId, AccessBearer, AccessTunnel),
		    PgwFTEID = AccessBearer#bearer.local,
		    Pending = Pending0#{PgwFTEID => {QCI, ARP, AccessBearer, ChId}},
		    %% Retain the original request params so the Create Bearer
		    %% Request can be re-issued verbatim if the UE is temporarily
		    %% unreachable due to power saving (TS 23.401 5.4.1 step 12).
		    Retry0 = maps:get(retry_bearers, Data, #{}),
		    Retry = Retry0#{PgwFTEID =>
					{PTI, DefaultEBI, QoS, TFTBin, AccessBearer, ChId}},
		    Data#{pending_bearers := Pending, retry_bearers => Retry};
		_ ->
		    Data
	    end;
	_ ->
	    Data
    end.


%% Network-initiated single-bearer deactivation: a batch of one, no PTI.
initiate_delete_dedicated_bearer(EBI, AccessTunnel, Data) ->
    send_dedicated_bearers_delete([EBI], AccessTunnel),
    Data.

%% UE-requested single-bearer deactivation (bearer_resource_command
%% delete_existing_tft, TS 29.274 7.2.9.2): echoes the PTI and sends exactly one
%% EBI — NOT routed through the network-initiated batched send (§7.2.9.2 NOTE).
initiate_ue_delete_dedicated_bearer(PTI, EBI, Tunnel, Data) ->
    RequestIEs0 = [#v2_procedure_transaction_id{pti = PTI},
		   #v2_eps_bearer_id{instance = 1, eps_bearer_id = EBI}],
    RequestIEs = gtp_v2_c:build_recovery(delete_bearer_request, Tunnel, false, RequestIEs0),
    send_request(Tunnel, ?T3, ?N3, delete_bearer_request, RequestIEs,
		 {delete_dedicated_bearers, [EBI]}),
    Data.

%% ue_delete_filters_proc/4 — async_m procedure for a UE-requested
%% delete_packet_filters (Bearer Resource Command, TS 23.401 §5.4.5, #22 Inc2).
%% Reports the removed SDF filters to the PCRF over a Gx CCR-Update, awaits the
%% decision, applies the PCC delta, and — when the bearer's last bound rule is
%% gone — runs the single-bearer deactivation echoing the PTI. Correlation
%% (EBI/PTI/tunnel) rides the closure across the await; no separate map needed.
ue_delete_filters_proc(EBI, PfIds, PTI, AccessTunnel) ->
    do([async_m ||
	   #{pcf := PCF0, aaa_session := Session0, pcc := PCC0,
	     bearers := BearerMap, dedicated := Dedicated, pfcp := PCtx0} <- async_m:get_data(),
	   #ded_bearer{sdf_to_pf = SdfToPf} = maps:get(EBI, Dedicated),
	   SdfHandles <- async_m:lift(smf_tft:pf_ids_to_sdf(PfIds, SdfToPf)),
	   PFs = [#{'Packet-Filter-Identifier' => H} || H <- SdfHandles],
	   SOpts = #{'Event-Trigger' =>
			 ?'DIAMETER_GX_EVENT-TRIGGER_RESOURCE_MODIFICATION_REQUEST',
		     'Packet-Filter-Operation' =>
			 ?'DIAMETER_GX_PACKET-FILTER-OPERATION_DELETION',
		     'Packet-Filter-Information' => PFs},
	   Now = erlang:monotonic_time(),
	   {async, ReqId} =
	       smf_aaa_pcf:invoke(PCF0, Session0, SOpts, {gx, 'CCR-Update'},
				  #{pipeline_async => true, now => Now}),
	   {Result, PCF1, Session1, Events} <- await_pipeline(ReqId),
	   ok <- async_m:lift(ccr_result(Result)),
	   RuleBase = smf_charging:rulebase(),
	   %% Fold BOTH passes: a delete may also carry a PCRF-proposed replacement
	   %% rule in the same CCA -- this closed the Inc2 remove-only deferral (#22).
	   %% Remove-pass errors are dropped on purpose -- see report_pcc_failures/4.
	   {PCC1, _} = smf_pcc_context:gx_events_to_pcc_ctx(Events, remove, RuleBase, PCC0),
	   {PCC2, PCCErrors} =
	       smf_pcc_context:gx_events_to_pcc_ctx(Events, install, RuleBase, PCC1),
	   {PCF2, Session2} = report_pcc_failures(PCCErrors, PCF1, Session1, #{now => Now}),
	   %% Commit the Gx/PCC results (shared by both outcomes).
	   async_m:modify_data(
	     fun(D) -> D#{pcf := PCF2, aaa_session := Session2, pcc := PCC2} end),
	   %% One PTI-correlated single-bearer outcome.
	   ue_delete_outcome(
	     lists:member(EBI, smf_gsn_lib:detect_removed_bearers(PCC0, PCC2, BearerMap)),
	     EBI, PTI, AccessTunnel, PCC2, BearerMap, PCtx0, Dedicated)
       ]).

%% ue_add_filters_proc/4 — async_m procedure for a UE-requested add_packet_filters
%% (Bearer Resource Command, TS 23.401 §5.4.5, #22 Inc4). Reports the new filters'
%% content to the PCRF (Gx CCR-U ADDITION), awaits the install, applies the PCC
%% delta, and emits a PTI-echoing Update Bearer with the expanded TFT. An add never
%% empties a bearer -> always the Update outcome.
ue_add_filters_proc(EBI, FlowInfos, PTI, AccessTunnel) ->
    do([async_m ||
	   #{pcf := PCF0, aaa_session := Session0, pcc := PCC0,
	     bearers := BearerMap, dedicated := Dedicated, pfcp := PCtx0} <- async_m:get_data(),
	   Groups = [smf_tft:flow_info_to_pf_add_group(FI) || FI <- FlowInfos],
	   SOpts = #{'Event-Trigger' =>
			 ?'DIAMETER_GX_EVENT-TRIGGER_RESOURCE_MODIFICATION_REQUEST',
		     'Packet-Filter-Operation' =>
			 ?'DIAMETER_GX_PACKET-FILTER-OPERATION_ADDITION',
		     'Packet-Filter-Information' => Groups},
	   Now = erlang:monotonic_time(),
	   {async, ReqId} =
	       smf_aaa_pcf:invoke(PCF0, Session0, SOpts, {gx, 'CCR-Update'},
				  #{pipeline_async => true, now => Now}),
	   {Result, PCF1, Session1, Events} <- await_pipeline(ReqId),
	   ok <- async_m:lift(ccr_result(Result)),
	   RuleBase = smf_charging:rulebase(),
	   %% An add only installs (nothing to remove).
	   {PCC1, PCCErrors} =
	       smf_pcc_context:gx_events_to_pcc_ctx(Events, install, RuleBase, PCC0),
	   {PCF2, Session2} = report_pcc_failures(PCCErrors, PCF1, Session1, #{now => Now}),
	   async_m:modify_data(
	     fun(D) -> D#{pcf := PCF2, aaa_session := Session2, pcc := PCC1} end),
	   ue_update_outcome(EBI, PTI, AccessTunnel, PCC1, BearerMap, PCtx0, Dedicated)
       ]).

%% ue_qos_change_proc/4 — async_m procedure for a UE-requested QoS/GBR change
%% (Bearer Resource Command no_tft_operation, TS 23.401 §5.4.5, #22 Inc6).
%% Reports the requested QoS to the PCRF (Gx CCR-U with QoS-Information, no
%% packet-filter change), awaits the authorized rule (re)install, applies the
%% PCC delta, and emits a PTI-echoing Update Bearer carrying the new Bearer QoS.
%% A QoS change re-installs the affected rule -> install-only fold -> always the
%% Update outcome (never empties a bearer).
ue_qos_change_proc(EBI, ReqQoS, PTI, AccessTunnel) ->
    do([async_m ||
	   #{pcf := PCF0, aaa_session := Session0, pcc := PCC0,
	     bearers := BearerMap, dedicated := Dedicated, pfcp := PCtx0} <- async_m:get_data(),
	   SOpts = #{'Event-Trigger' =>
			 ?'DIAMETER_GX_EVENT-TRIGGER_RESOURCE_MODIFICATION_REQUEST',
		     'QoS-Information' => ReqQoS},
	   Now = erlang:monotonic_time(),
	   {async, ReqId} =
	       smf_aaa_pcf:invoke(PCF0, Session0, SOpts, {gx, 'CCR-Update'},
				  #{pipeline_async => true, now => Now}),
	   {Result, PCF1, Session1, Events} <- await_pipeline(ReqId),
	   ok <- async_m:lift(ccr_result(Result)),
	   RuleBase = smf_charging:rulebase(),
	   {PCC1, PCCErrors} =
	       smf_pcc_context:gx_events_to_pcc_ctx(Events, install, RuleBase, PCC0),
	   {PCF2, Session2} = report_pcc_failures(PCCErrors, PCF1, Session1, #{now => Now}),
	   async_m:modify_data(
	     fun(D) -> D#{pcf := PCF2, aaa_session := Session2, pcc := PCC1} end),
	   ue_update_outcome(EBI, PTI, AccessTunnel, PCC1, BearerMap, PCtx0, Dedicated)
       ]).

%% ue_replace_filters_proc/4 — async_m procedure for a UE-requested
%% replace_packet_filters (Bearer Resource Command, TS 23.401 §5.4.5, #22 Inc5).
%% A delete/add hybrid: names each replaced filter by its existing SDF handle
%% (inverting sdf_to_pf, like delete) AND carries the new content (like add), as a
%% Gx CCR-U MODIFICATION. Awaits, applies the PCC delta (remove+install), and
%% dispatches the shared outcome (empty -> Delete edge / non-empty -> Update).
ue_replace_filters_proc(EBI, FlowInfos, PTI, AccessTunnel) ->
    do([async_m ||
	   #{pcf := PCF0, aaa_session := Session0, pcc := PCC0,
	     bearers := BearerMap, dedicated := Dedicated, pfcp := PCtx0} <- async_m:get_data(),
	   #ded_bearer{sdf_to_pf = SdfToPf} = maps:get(EBI, Dedicated),
	   UEIds = [Id || #{'Packet-Filter-Identifier' := [<<Id:8>>]} <- FlowInfos],
	   SdfHandles <- async_m:lift(smf_tft:pf_ids_to_sdf(UEIds, SdfToPf)),
	   Groups = [smf_tft:flow_info_to_pf_modify_group(FI, H)
		     || {FI, H} <- lists:zip(FlowInfos, SdfHandles)],
	   SOpts = #{'Event-Trigger' =>
			 ?'DIAMETER_GX_EVENT-TRIGGER_RESOURCE_MODIFICATION_REQUEST',
		     'Packet-Filter-Operation' =>
			 ?'DIAMETER_GX_PACKET-FILTER-OPERATION_MODIFICATION',
		     'Packet-Filter-Information' => Groups},
	   Now = erlang:monotonic_time(),
	   {async, ReqId} =
	       smf_aaa_pcf:invoke(PCF0, Session0, SOpts, {gx, 'CCR-Update'},
				  #{pipeline_async => true, now => Now}),
	   {Result, PCF1, Session1, Events} <- await_pipeline(ReqId),
	   ok <- async_m:lift(ccr_result(Result)),
	   RuleBase = smf_charging:rulebase(),
	   %% A replace can drop the old rule and install the new -> apply both.
	   %% Remove-pass errors are dropped on purpose -- see report_pcc_failures/4.
	   {PCC1, _} = smf_pcc_context:gx_events_to_pcc_ctx(Events, remove, RuleBase, PCC0),
	   {PCC2, PCCErrors} =
	       smf_pcc_context:gx_events_to_pcc_ctx(Events, install, RuleBase, PCC1),
	   {PCF2, Session2} = report_pcc_failures(PCCErrors, PCF1, Session1, #{now => Now}),
	   async_m:modify_data(
	     fun(D) -> D#{pcf := PCF2, aaa_session := Session2, pcc := PCC2} end),
	   ue_delete_outcome(
	     lists:member(EBI, smf_gsn_lib:detect_removed_bearers(PCC0, PCC2, BearerMap)),
	     EBI, PTI, AccessTunnel, PCC2, BearerMap, PCtx0, Dedicated)
       ]).

%% Empty: the bearer's last bound rule is gone -> single-bearer deactivation
%% echoing the PTI (Increment 2 behaviour, unchanged).
ue_delete_outcome(true, EBI, PTI, AccessTunnel, _PCC2, _BearerMap, _PCtx0, _Dedicated) ->
    async_m:modify_data(
      fun(D) -> initiate_ue_delete_dedicated_bearer(PTI, EBI, AccessTunnel, D) end);
%% Non-empty: surviving rules -> the shared Update outcome (Increment 3).
ue_delete_outcome(false, EBI, PTI, AccessTunnel, PCC2, BearerMap, PCtx0, Dedicated) ->
    ue_update_outcome(EBI, PTI, AccessTunnel, PCC2, BearerMap, PCtx0, Dedicated).

%% The PTI-echoing Update Bearer outcome: re-provision PFCP, then emit the Update
%% Bearer with the recomputed TFT. Shared by delete-with-survivors (Inc3) and add
%% (Inc4) — an add is unconditionally this outcome (it never empties a bearer).
ue_update_outcome(EBI, PTI, AccessTunnel, PCC, BearerMap, PCtx0, Dedicated) ->
    do([async_m ||
	   Issued <- async_m:lift(
		       smf_pfcp_context:modify_session_async(PCC, [], #{}, BearerMap, PCtx0)),
	   {PCtx1, _, _} <- await_pfcp_modify(Issued),
	   async_m:modify_data(
	     fun(D) -> emit_ue_update_bearer(EBI, PTI, AccessTunnel, PCC, Dedicated, PCtx1, D) end)
       ]).

%% reprovision_proc/1 — re-provision the UPF for a bearer-table change that is
%% already committed to Data. Every batch-C path treats a failed PFCP
%% modification as non-fatal (it keeps the control-plane change and drops only
%% the new PCtx), so this never travels the error channel: await_pfcp_modify_opt/1
%% yields `undefined` on failure and the commit simply leaves `pfcp` alone.
reprovision_proc(BearerMap) ->
    do([async_m ||
	   #{pfcp := PCtx0, pcc := PCC} <- async_m:get_data(),
	   Issued <- async_m:lift(
		       smf_pfcp_context:modify_session_async(PCC, [], #{}, BearerMap, PCtx0)),
	   PCtx <- await_pfcp_modify_opt(Issued),
	   async_m:modify_data(
	     fun(D) when PCtx =:= undefined -> D;
		(D)                         -> D#{pfcp := PCtx}
	     end)
       ]).

%% Tolerant sibling of await_pfcp_modify/1: yields the new PCtx, or `undefined`
%% when the UPF refused, instead of short-circuiting down the error channel.
await_pfcp_modify_opt({request, ReqId, PCtx1}) ->
    do([async_m ||
	   Reply <- async_m:await(ReqId),
	   async_m:return(
	     case smf_pfcp_context:modify_session_result(Reply, PCtx1) of
		 {ok, {PCtx, _, _}} -> PCtx;
		 {error, _}         -> undefined
	     end)
       ]);
await_pfcp_modify_opt({no_request, PCtx1}) ->
    async_m:return(PCtx1).

%% Local mirror of gtp_context:await_modify/1 — await the async PFCP modify reply
%% (or short-circuit when no PFCP change was needed). A non-accepted reply makes
%% modify_session_result return {error, #ctx_err{FATAL}}, routed to br_err.
await_pfcp_modify({request, ReqId, PCtx1}) ->
    do([async_m || Reply <- async_m:await(ReqId),
		   async_m:lift(smf_pfcp_context:modify_session_result(Reply, PCtx1))]);
await_pfcp_modify({no_request, PCtx1}) ->
    async_m:return({PCtx1, undefined, #{}}).

%% Recompute the target bearer's surviving descriptor and emit the PTI-echoing
%% Update Bearer Request (reusing the network-initiated send path; PTI rides
%% ExtraIEs, NewDesc staged for commit on the Update Bearer response).
emit_ue_update_bearer(EBI, PTI, AccessTunnel, PCC2, Dedicated, PCtx1, D) ->
    TargetDesc = maps:get(EBI, Dedicated),
    case smf_gsn_lib:detect_modified_bearers(PCC2, #{EBI => TargetDesc}) of
	[{_, QoS, FlowInfo, NewDesc}] ->
	    PTIie = #v2_procedure_transaction_id{pti = PTI},
	    send_dedicated_bearers_update(rule_change, [{EBI, QoS, FlowInfo}],
					  [PTIie], #{EBI => NewDesc}, AccessTunnel),
	    D#{pfcp := PCtx1};
	[] ->
	    %% PCRF accepted but left this bearer's rules unchanged -> no TFT change
	    %% to signal (realistically unreachable for an accepted delete). Ack only.
	    D#{pfcp := PCtx1}
    end.

%% The PCRF accepted iff the pipeline reports a success Result. The worker's
%% smf_aaa_gx:invoke/6 (via handle_cca) yields the Result: a <3000 Result-Code
%% yields the bare atom `ok`; a rejection yields {fail, RC}; a diameter/transport
%% failure yields {error, _}. Anything but `ok` is a rejection -> Failure Indication.
ccr_result(ok)    -> ok;
ccr_result(Other) -> {error, {pcrf_rejected, Other}}.

%% Report the rule failures gx_events_to_pcc_ctx/4 collected while applying the
%% CCA: the PCRF named a predefined Charging-Rule / -Base this PGW has no local
%% configuration for, so the rule the PCRF believes is active was never installed.
%% TS 29.212 4.5.12 puts PULL-provisioned failures -- rules arriving in a CCA, as
%% they do here -- in a NEW CCR with PCC-Rule-Status INACTIVE; the answer that
%% could have carried them is the CCA we just processed. Fire-and-forget, exactly
%% like the establishment path in smf_gtp_gsn_lib:create_session_fun/13.
%%
%% Install pass only. 4.5.12 states removal never fails: a {not_found, {rule, _}}
%% from the remove pass means the requested end state (rule absent) already holds,
%% so there is nothing to report.
%% Nothing to report and a CCR that did not go through both leave the Gx context
%% untouched, so both land in the same else clause.
report_pcc_failures(PCCErrors, PCF0, Session0, ReqOpts) ->
    maybe
	GxReport = smf_gsn_lib:pcc_events_to_charging_rule_report(PCCErrors),
	true ?= map_size(GxReport) /= 0,
	{ok, PCF, Session, _} ?=
	    smf_aaa_pcf:ccr_update(PCF0, Session0, GxReport, ReqOpts#{async => true}),
	{PCF, Session}
    else
	_ -> {PCF0, Session0}
    end.

%% await a whole-pipeline worker (invoke(pipeline_async)). On success the worker
%% posts the folded {Result, Ctx1, Session1, Events}; on an unexpected crash
%% async_dispatch delivers {error, {worker_down, _}}. Turn the latter into a
%% procedure error (routed to br_err -> Bearer Resource Failure Indication)
%% rather than a badmatch that would crash the context gen_statem.
await_pipeline(ReqId) ->
    do([async_m || R <- async_m:await(ReqId),
                   async_m:lift(pipeline_ok(R))]).

pipeline_ok({_Result, _Ctx1, _Session1, _Events} = Ok) -> {ok, Ok};
pipeline_ok({error, _} = Err)                          -> Err.

%% The Update/Delete Bearer Request IS the follow-on procedure; ack the command
%% and return {next_state,...} so the drained async_pending re-delivers postponed
%% events. Shared by both outcomes.
br_ok(_V, State, Data, ReqKey, Context) ->
    gtp_context:request_finished(ReqKey),
    Actions = context_idle_action([], Context),
    {next_state, State, Data, Actions}.

%% A PFCP-modify FATAL failure surfaces as a #ctx_err VALUE (modify_session_result
%% returns {error, #ctx_err{}}); re-throw so async_dispatch's #ctx_err catch runs
%% handle_ctx_error -> {stop, normal, Data} (the pilot's behaviour; a PFCP failure
%% after the Gx commit is a genuine inconsistency, not a recoverable reject).
br_err(#ctx_err{} = E, _State, _Data, _ReqKey, _Request,
       _AccessTunnel, _LinkedEBI, _PTI, _Context) ->
    throw(E);
%% Recoverable (Gx reject / unknown or ambiguous filter) -> Bearer Resource Failure
%% Indication echoing the PTI (TS 29.274 7.2.14) — the exact IEs the old
%% synchronous reject branch built.
br_err(_Reason, State, Data, ReqKey, Request,
       AccessTunnel, LinkedEBI, PTI, Context) ->
    ResponseIEs = [#v2_cause{v2_cause = request_rejected},
		   #v2_eps_bearer_id{eps_bearer_id = LinkedEBI},
		   #v2_procedure_transaction_id{pti = PTI}],
    Response = response(bearer_resource_failure_indication,
			AccessTunnel, ResponseIEs, Request),
    gtp_context:send_response(ReqKey, Request, Response),
    Actions = context_idle_action([], Context),
    {next_state, State, Data, Actions}.

%% Build a descriptor for a dedicated bearer established directly from a Create
%% Session Request bearer context (TS 29.274 7.2.1). Its QoS is the Bearer Level
%% QoS carried in the CSR — there is no bound PCC rule and no TFT — so it is taken
%% straight from that IE rather than via smf_gsn_lib:normalize_bearer/5, which
%% derives from PCC. This keeps such bearers visible to the ARP fan-out (M5) and
%% modified-bearer detection (M3), which iterate the stored descriptors.
ded_bearer_from_blqos(EBI,
		      #v2_bearer_level_quality_of_service{
			 pl = PL, pci = PCI, pvi = PVI, label = QCI,
			 maximum_bit_rate_for_uplink      = MBRul,
			 maximum_bit_rate_for_downlink    = MBRdl,
			 guaranteed_bit_rate_for_uplink   = GBRul,
			 guaranteed_bit_rate_for_downlink = GBRdl}) ->
    ARP = {PL, PCI, PVI},
    %% The Bearer Level QoS record carries bit-rates in kbps; the QoS map keys are
    %% bps (as encode_bearer_level_qos/1 div-1000s back and extract_flow_qos/1
    %% *1000s), so scale up on the way in.
    QoS = #{'QoS-Class-Identifier'       => QCI,
	    'Allocation-Retention-Priority' => arp_to_map(ARP),
	    'Max-Requested-Bandwidth-UL'   => MBRul * 1000,
	    'Max-Requested-Bandwidth-DL'   => MBRdl * 1000,
	    'Guaranteed-Bitrate-UL'        => GBRul * 1000,
	    'Guaranteed-Bitrate-DL'        => GBRdl * 1000},
    #ded_bearer{ebi = EBI, qci = QCI, arp = ARP, bind_arp = ARP, qos = QoS,
		rules = [], tft = [], sdf_to_pf = #{}, charging_id = undefined}.

%% Extract the dedicated EPS Bearer ID(s) named in a Delete Bearer Command
%% Bearer Context IE (TS 29.274 7.2.17.1-2). gtplib may surface a single
%% Bearer Context or a list; handle both.
%% Fold Fun(Elem, Acc) over a grouped IE. gtplib decodes a grouped IE as a
%% single record when there is one instance at that instance id, and as a list
%% when there are several — this collapsing is decode-only, unlike encode.
ie_foldl(Fun, Acc, IEs) when is_list(IEs) ->
    lists:foldl(Fun, Acc, IEs);
ie_foldl(Fun, Acc, IE) ->
    Fun(IE, Acc).

%% Apply one Bearer Context's Cause from a batched Update Bearer Response
%% (M3 rule change / M5 subscribed-QoS fan-out) to the dedicated bearer state,
%% per the §8 failure matrix: request_accepted commits the staged descriptor;
%% a temporary cause holds the change; a terminal cause runs the failure
%% policy for the procedure Kind (handle_update_bearer_failure/4).
%% Accumulator is {Data, RuleNames, DeleteEBIs}: every clause is pure, so the
%% caller can re-provision the UPF once and report to the PCRF once for the whole
%% batch instead of per failed bearer (#81).
apply_bearer_update_result(_Kind,
			   #v2_bearer_context{group = #{
			       ?'EPS Bearer ID' := #v2_eps_bearer_id{eps_bearer_id = EBI},
			       ?'Cause' := #v2_cause{v2_cause = request_accepted}}},
			   Staged, {Data, Rules, DelEBIs}) ->
    {commit_staged_descriptor(EBI, Staged, Data), Rules, DelEBIs};
apply_bearer_update_result(Kind,
			   #v2_bearer_context{group = #{
			       ?'EPS Bearer ID' := #v2_eps_bearer_id{eps_bearer_id = EBI},
			       ?'Cause' := #v2_cause{v2_cause = Cause}}},
			   Staged, Acc) ->
    case smf_gsn_lib:bearer_update_cause_class(Cause) of
	temporary ->
	    %% TODO(#34): re-attempt the Update when the UE is next reachable
	    %% (mirroring the Create-path power-saving retry); for now hold the
	    %% change without removing the rule or deleting the bearer (dossier §8).
	    ?LOG(warning, "Update Bearer Request for dedicated bearer ~p temporarily "
		 "rejected (~p); change not applied this round", [EBI, Cause]),
	    Acc;
	terminal when is_map_key(EBI, Staged) ->
	    stage_update_bearer_failure(Kind, EBI, Cause, Acc);
	terminal ->
	    %% This EBI was never staged for the current batch -- a response
	    %% echoing an EBI we didn't ask to modify. Log and skip rather than
	    %% removing rules or deleting a bearer we have no staged change for.
	    ?LOG(warning, "Update Bearer Response named EBI ~p with terminal cause "
		 "~p, but it was not staged for this procedure; skipping",
		 [EBI, Cause]),
	    Acc
    end;
apply_bearer_update_result(_Kind, BearerContext, _Staged, Acc) ->
    %% A Bearer Context missing an EPS Bearer ID or Cause is malformed; skip it
    %% without aborting processing of the batch's remaining contexts.
    ?LOG(warning, "malformed Bearer Context in Update Bearer Response, skipping: ~p",
	 [BearerContext]),
    Acc.

commit_staged_descriptor(EBI, Staged, #{dedicated := Ded} = Data) ->
    case maps:find(EBI, Staged) of
	{ok, Desc} -> Data#{dedicated := Ded#{EBI => Desc}};
	error      -> Data
    end.

%% Terminal Update failure: report the affected PCC rule(s) to the PCRF
%% (TS 29.212 §4.5.6/§4.5.12). A failed subscribed-QoS Modify (M5) is not ignorable —
%% delete the concerned bearer (TS 23.401 §5.4.2.2 step 7); the bearer's rule(s) must
%% also come out of pcc.rules (like every other removal path) or PFCP gets
%% re-provisioned against an orphaned rule on the next unrelated change. A failed
%% rule-change Modify (M3) removes the offending rule(s), re-provisions PFCP, and
%% keeps the bearer on its previously confirmed descriptor.
%% Finish a batched Update Bearer failure round: ONE Gx Charging-Rule-Report for
%% every affected rule, the subscribed-QoS bearer deletions, and ONE async UPF
%% re-provision for the whole batch. All three response clauses (per-bearer
%% Causes, message-level Cause, timeout) funnel through here so none of them can
%% drift back to per-bearer PFCP/Gx round trips (#81).
finish_update_bearer_failures({Data0, RuleNames, DelEBIs}, AccessTunnel, State) ->
    Data1 = case RuleNames of
		[] -> Data0;
		_  -> report_bearer_failure(RuleNames, Data0)
	    end,
    %% A subscribed-QoS terminal failure also deletes the bearer (5.4.2.2 step 7).
    Data = lists:foldl(
	     fun(EBI, D) -> initiate_delete_dedicated_bearer(EBI, AccessTunnel, D) end,
	     Data1, DelEBIs),
    async_m:run_async(reprovision_proc(maps:get(bearers, Data)),
		      fun(_V, S, D) -> {next_state, S, D} end,
		      fun(_R, S, D) -> {next_state, S, D} end,
		      State, Data).

stage_update_bearer_failure(subscribed_qos, EBI, Cause, {Data, Rules, DelEBIs}) ->
    ?LOG(warning, "subscribed-QoS Update for bearer ~p failed with ~p; deleting bearer "
	 "(TS 23.401 5.4.2.2 step 7)", [EBI, Cause]),
    RuleNames = ebi_rule_names(EBI, Data),
    {strip_pcc_rules(RuleNames, Data), RuleNames ++ Rules, [EBI | DelEBIs]};
stage_update_bearer_failure(rule_change, EBI, Cause, {Data, Rules, DelEBIs}) ->
    ?LOG(warning, "rule-change Update for bearer ~p failed with ~p; removing rule(s) "
	 "and reporting to PCRF", [EBI, Cause]),
    RuleNames = ebi_rule_names(EBI, Data),
    {strip_pcc_rules(RuleNames, Data), RuleNames ++ Rules, DelEBIs}.

%% Drop RuleNames from the PCC context. Pure: the UPF is re-provisioned once for
%% the accumulated change, not per rule set (#79/#81).
strip_pcc_rules([], Data) ->
    Data;
strip_pcc_rules(RuleNames, #{pcc := PCC} = Data) ->
    Data#{pcc := PCC#pcc_ctx{rules = maps:without(RuleNames, PCC#pcc_ctx.rules)}}.

ebi_rule_names(EBI, #{bearers := BearerMap, pcc := PCC}) ->
    case ebi_qci_arp(EBI, BearerMap) of
	{QCI, ARP} -> affected_pcc_rules(QCI, ARP, PCC);
	undefined  -> []
    end.

%% Prep one dedicated bearer named in a Delete Bearer Command for deactivation:
%% remove its bound PCC rule(s) from the PCC context and accumulate both the EBI
%% and the rule names. Pure — no PFCP and no Gx here; the caller re-provisions
%% the UPF once, reports the whole rule set to the PCRF once, and emits ONE
%% network-initiated Delete Bearer Request for the accumulated batch. The default
%% bearer and unknown bearers are left untouched and not accumulated.
prep_commanded_deactivation(#v2_bearer_context{group = #{?'EPS Bearer ID' :=
				    #v2_eps_bearer_id{eps_bearer_id = EBI}}},
			     DefaultEBI, _AccessTunnel, {Data, EBIs, Rules})
  when EBI =:= DefaultEBI ->
    ?LOG(warning, "Delete Bearer Command targeted the default bearer ~p; ignored", [EBI]),
    {Data, EBIs, Rules};
prep_commanded_deactivation(#v2_bearer_context{group = #{?'EPS Bearer ID' :=
				    #v2_eps_bearer_id{eps_bearer_id = EBI}}},
			     _DefaultEBI, _AccessTunnel,
			     {#{bearers := BearerMap, pcc := PCC} = Data0, EBIs, Rules}) ->
    case maps:is_key({'Access', EBI}, BearerMap) of
	false ->
	    ?LOG(warning, "Delete Bearer Command for unknown bearer ~p; ignored", [EBI]),
	    {Data0, EBIs, Rules};
	true ->
	    RuleNames =
		case ebi_qci_arp(EBI, BearerMap) of
		    {QCI, ARP} -> affected_pcc_rules(QCI, ARP, PCC);
		    undefined  -> []
		end,
	    PCC1 = PCC#pcc_ctx{rules = maps:without(RuleNames, PCC#pcc_ctx.rules)},
	    {Data0#{pcc := PCC1}, [EBI | EBIs], RuleNames ++ Rules}
    end;
prep_commanded_deactivation(_BearerContext, _DefaultEBI, _AccessTunnel, DataAcc) ->
    %% A Bearer Context without an EPS Bearer ID: nothing to deactivate.
    DataAcc.

%% Reverse lookup of a bearer's {QCI, ARP} from its EBI via the bearer map's
%% {qci_arp, QCI, ARP} => EBI entries.
ebi_qci_arp(EBI, BearerMap) ->
    maps:fold(
      fun({qci_arp, QCI, ARP}, V, _Acc) when V =:= EBI -> {QCI, ARP};
	 (_, _, Acc)                                   -> Acc
      end, undefined, BearerMap).

%% Keep the default bearer's {qci_arp} binding key in sync with its
%% re-authorized ARP (#39) so a later PCC rule at the new default ARP binds to
%% the default instead of spawning a dedicated bearer. Rewrites on the actually
%% stored ARP; no-op if the default has no {qci_arp} entry.
%%
%% This asymmetry is intentional: the DEFAULT bearer's {qci_arp} key follows
%% its subscribed ARP and is rekeyed here on re-auth, whereas DEDICATED
%% bearers bind on their immutable bind_arp and are deliberately NOT rekeyed
%% when the subscribed QoS fans out (see fan_out_subscribed_arp_change/6) --
%% a dedicated bearer keeps the {qci_arp} key it was created with for its
%% whole lifetime.
%%
%% Only rewrite when the target {qci_arp, QCI, NewARP} key is free (absent, or
%% already the default's own). If some OTHER bearer already owns that key --
%% e.g. a dedicated bearer at the same QCI whose ARP happens to equal the
%% default's newly re-authorized ARP -- rewriting would silently steal that
%% bearer's binding registration. Leave the map unchanged in that case: the
%% default keeps its stale {qci_arp} entry, which is no worse than pre-#39.
rekey_default_qci_arp(DefaultEBI, NewARP, #{bearers := BearerMap} = Data) ->
    case ebi_qci_arp(DefaultEBI, BearerMap) of
	{QCI, StoredARP} when StoredARP =/= NewARP ->
	    NewKey = {qci_arp, QCI, NewARP},
	    case maps:get(NewKey, BearerMap, DefaultEBI) of
		DefaultEBI ->
		    BM = maps:remove({qci_arp, QCI, StoredARP}, BearerMap),
		    Data#{bearers := BM#{NewKey => DefaultEBI}};
		Other ->
		    ?LOG(warning, "default bearer ~p re-authorized to {QCI ~p, ARP ~p} "
			 "already bound by bearer ~p; skipping rekey to avoid collision",
			 [DefaultEBI, QCI, NewARP, Other]),
		    Data
	    end;
	_ ->
	    Data
    end.

%% TS 29.212 §4.5.2.0 / §5.3.7 value 22: confirm a successful network-initiated
%% resource allocation to the PCRF — but only for rules where the PCRF armed the
%% confirmation (Resource-Allocation-Notification). Report the bound rule(s) ACTIVE
%% with the SUCCESSFUL_RESOURCE_ALLOCATION event trigger; send nothing when unarmed.
%% Deliberately carries NO QoS-Information: that is the default bearer's session-level
%% QoS and would be clobbered by session_merge with the dedicated bearer's QoS.
report_successful_resource_allocation(QCI, ARP,
				      #{pcc := PCC, pcf := PCF0, aaa_session := S0} = Data) ->
    Armed = [N || N <- affected_pcc_rules(QCI, ARP, PCC),
		  rule_wants_alloc_notification(N, PCC)],
    case Armed of
	[] ->
	    Data;
	_ ->
	    Names = lists:flatmap(fun(N) when is_list(N) -> N; (N) -> [N] end, Armed),
	    Report = #{'Charging-Rule-Name' => Names,
		       'PCC-Rule-Status'    => [?'DIAMETER_GX_PCC-RULE-STATUS_ACTIVE']},
	    SOpts = #{'Charging-Rule-Report' => [Report],
		      'Event-Trigger' =>
			  ?'DIAMETER_GX_EVENT-TRIGGER_SUCCESSFUL_RESOURCE_ALLOCATION'},
	    Now = erlang:monotonic_time(),
	    case smf_aaa_pcf:ccr_update(PCF0, S0, SOpts, #{now => Now, async => true}) of
		{ok, PCF1, S1, _Events} -> Data#{pcf := PCF1, aaa_session := S1};
		_                       -> Data
	    end
    end.

%% True when the PCRF armed the allocation confirmation for this rule
%% (Resource-Allocation-Notification = ENABLE_NOTIFICATION, retained on the stored
%% rule by smf_pcc_context:update_pcc_rule/4). Name is a stored-rule map key.
rule_wants_alloc_notification(Name, #pcc_ctx{rules = Rules}) ->
    case maps:get(Name, Rules, undefined) of
	#{'Resource-Allocation-Notification' := V} when is_list(V) ->
	    lists:member(?'DIAMETER_GX_RESOURCE-ALLOCATION-NOTIFICATION_ENABLE_NOTIFICATION', V);
	_ ->
	    false
    end.

%% Inform the PCRF of an updated default-bearer EPS Bearer QoS / APN-AMBR
%% carried in a Modify Bearer Command (HSS Initiated Subscribed QoS
%% Modification, TS 23.401 5.4.2.2 step 4). This is a PCEF-initiated IP-CAN
%% Session Modification: a Gx CCR-Update reporting the updated 'QoS-Information'
%% (already folded into the session by update_session_from_gtp_req/4) with a
%% DEFAULT_EPS_BEARER_QOS_CHANGE event trigger.
%%
%% Per step 4 the PCRF may answer with an *overriding* decision -- a
%% Default-EPS-Bearer-QoS reshaping QCI/ARP and/or an APN-AMBR -- which the PGW
%% enforces in the Update Bearer Request in place of the command's own values.
%% smf_aaa_gx surfaces it as 'Authorized-QoS-Information' on the session.
subscribed_qos_change_proc(Cmd, AccessTunnel, Context) ->
    do([async_m ||
	   #{pcf := PCF0, aaa_session := S1} <- async_m:get_data(),
	   SOpts = (maps:with(['QoS-Information'], S1))
	       #{'Event-Trigger' =>
		     ?'DIAMETER_GX_EVENT-TRIGGER_DEFAULT_EPS_BEARER_QOS_CHANGE'},
	   Now = erlang:monotonic_time(),
	   {async, ReqId} =
	       smf_aaa_pcf:invoke(PCF0, S1, SOpts, {gx, 'CCR-Update'},
				  #{pipeline_async => true, now => Now}),
	   Reply <- async_m:await(ReqId),
	   {PCF1, S2} = qos_change_answer(Reply, PCF0, S1),
	   async_m:modify_data(fun(D) -> D#{pcf := PCF1, aaa_session := S2} end),
	   AuthQoS = maps:get('Authorized-QoS-Information', S2, #{}),
	   async_m:modify_data(
	     fun(D) -> emit_subscribed_qos_update(Cmd, AuthQoS, AccessTunnel, Context, D) end)
       ]).

%% The PCRF's answer only ever *refines* the Update Bearer Request. On any
%% failure -- a rejecting Result-Code, a transport error, a dead worker -- we keep
%% the command's own QoS and carry on, because a Modify Bearer Command has no
%% error response (the Update Bearer Request IS the follow-on, TS 29.274 7.2.14):
%% aborting would silently drop the HSS-initiated change rather than degrade to it.
%%
%% A rejecting CCA cannot smuggle an override in either -- TS 29.212 4.5.1 forbids
%% combining a rejection result code with provisioning -- so the authorized key is
%% simply absent and the fallback below applies.
qos_change_answer({ok, PCF1, S1, _Events}, _PCF0, _S0) ->
    {PCF1, S1};
qos_change_answer({Result, PCF1, S1, _Events}, _PCF0, _S0) ->
    ?LOG(warning, "Gx rejected the subscribed QoS modification (~p); "
	 "proceeding with the QoS from the Modify Bearer Command", [Result]),
    {PCF1, S1};
qos_change_answer(Other, PCF0, S0) ->
    ?LOG(warning, "Gx subscribed QoS modification failed (~p); "
	 "proceeding with the QoS from the Modify Bearer Command", [Other]),
    {PCF0, S0}.

%% Emit the Update Bearer Request and fan the ARP change out, both using the
%% authorized values where the PCRF supplied them and the command's otherwise.
emit_subscribed_qos_update(#{req_key := ReqKey, seq_no := SeqNo, src := Src,
			     ip := IP, port := Port, ambr := CmdAMBR,
			     bearer := Bearer, ebi := EBI, old_sopts := OldSOpts},
			   AuthQoS, AccessTunnel, Context, Data) ->
    AMBR = effective_apn_ambr(AuthQoS, CmdAMBR),
    Type = update_bearer_request,
    RequestIEs0 =
	[AMBR,
	 #v2_bearer_context{group = effective_bearer_group(AuthQoS, Bearer, EBI)}],
    RequestIEs = gtp_v2_c:build_recovery(Type, AccessTunnel, false, RequestIEs0),
    Msg = msg(AccessTunnel, Type, RequestIEs),
    send_request(
      AccessTunnel, Src, IP, Port, ?T3, ?N3, Msg#gtp{seq_no = SeqNo}, {ReqKey, OldSOpts}),

    %% TS 23.401 5.4.2.2 step 5: "If the subscribed ARP parameter has been
    %% changed, the PDN GW shall also modify all dedicated EPS bearers having
    %% the previously subscribed ARP value unless superseded by PCRF decision."
    %% The "unless superseded" half is what effective_arp/2 implements: the ARP
    %% fanned out is the authorized one when the PCRF provisioned it.
    fan_out_subscribed_arp_change(OldSOpts, effective_arp(AuthQoS, Bearer), AMBR,
				  Context, AccessTunnel, Data).

%% Authorized APN-AMBR wins over the command's. Session values are bps, the IE
%% is kbps (cf. copy_qos_to_session/2, which scales the other way).
effective_apn_ambr(#{'APN-Aggregate-Max-Bitrate-UL' := UL,
		     'APN-Aggregate-Max-Bitrate-DL' := DL}, _CmdAMBR) ->
    #v2_aggregate_maximum_bit_rate{uplink = UL div 1000, downlink = DL div 1000};
effective_apn_ambr(_AuthQoS, CmdAMBR) ->
    CmdAMBR.

%% Default-EPS-Bearer-QoS carries QCI and ARP only (the default bearer is non-GBR;
%% its bitrates come from the APN-AMBR), so overlay just those onto the command's
%% Bearer Level QoS, field by field, leaving anything the PCRF omitted alone.
effective_bearer_group(AuthQoS,
		       #{?'Bearer Level QoS' :=
			     #v2_bearer_level_quality_of_service{} = BLQoS}, EBI)
  when map_size(AuthQoS) =/= 0 ->
    ARP = maps:get('Allocation-Retention-Priority', AuthQoS, #{}),
    [EBI,
     BLQoS#v2_bearer_level_quality_of_service{
       label = maps:get('QoS-Class-Identifier', AuthQoS,
			BLQoS#v2_bearer_level_quality_of_service.label),
       pl  = maps:get('Priority-Level', ARP,
		      BLQoS#v2_bearer_level_quality_of_service.pl),
       pci = maps:get('Pre-emption-Capability', ARP,
		      BLQoS#v2_bearer_level_quality_of_service.pci),
       pvi = maps:get('Pre-emption-Vulnerability', ARP,
		      BLQoS#v2_bearer_level_quality_of_service.pvi)}];
effective_bearer_group(_AuthQoS, Bearer, EBI) ->
    copy_ies_to_response(Bearer, [EBI], [?'Bearer Level QoS']).

%% The ARP the fan-out compares against and installs: authorized if the PCRF
%% provisioned one, else the command's.
effective_arp(#{'Allocation-Retention-Priority' := #{'Priority-Level' := PL} = ARP},
	      _CommandBearer) ->
    {PL,
     maps:get('Pre-emption-Capability', ARP, 1),
     maps:get('Pre-emption-Vulnerability', ARP, 0)};
effective_arp(_AuthQoS, CommandBearer) ->
    command_bearer_arp(CommandBearer).

%% No direct response to a Modify Bearer Command -- the Update Bearer Request is
%% the follow-on. Thread the State back so the async_pending drain re-fires
%% whatever the gate postponed while we waited on the PCRF.
mbc_done(State, Data, Context) ->
    {next_state, State, Data, context_idle_action([], Context)}.

%% The Gx step cannot fail the procedure (qos_change_answer/3 absorbs every
%% failure), so reaching here means a #ctx_err{} or a bug. Still emit the Update
%% Bearer from the command's own QoS rather than dropping the HSS-initiated change.
%% Re-throw so async_dispatch's #ctx_err catch runs handle_ctx_error, exactly as
%% br_err/9 does on the UE bearer paths.
mbc_err(#ctx_err{} = E, _State, _Data, _Cmd, _AccessTunnel, _Context) ->
    throw(E);
mbc_err(Reason, State, Data, Cmd, AccessTunnel, Context) ->
    ?LOG(error, "subscribed QoS modification failed after the Gx step: ~p", [Reason]),
    Data1 = emit_subscribed_qos_update(Cmd, #{}, AccessTunnel, Context, Data),
    {next_state, State, Data1, context_idle_action([], Context)}.

%% Report dedicated bearer activation failure to PCRF via Gx CCR-Update
%% with a Charging-Rule-Report naming the affected PCC rule(s) as INACTIVE
%% with Rule-Failure-Code RESOURCE_ALLOCATION_FAILURE (TS 29.212 4.5.12).
report_bearer_failure(RuleNames,
		      #{pcf := PCF0, aaa_session := S0} = Data) ->
    %% Rule keys may be binaries or single-element lists; flatten to a plain
    %% list of name binaries for the repeated Charging-Rule-Name AVP.
    Names = lists:flatmap(fun(N) when is_list(N) -> N; (N) -> [N] end, RuleNames),
    Report = #{'Charging-Rule-Name' => Names,
	       'PCC-Rule-Status'    =>
		   [?'DIAMETER_GX_PCC-RULE-STATUS_INACTIVE'],
	       'Rule-Failure-Code'  =>
		   [?'DIAMETER_GX_RULE-FAILURE-CODE_RESOURCE_ALLOCATION_FAILURE']},
    SOpts = #{'Charging-Rule-Report' => [Report]},
    Now = erlang:monotonic_time(),
    case smf_aaa_pcf:ccr_update(PCF0, S0, SOpts, #{now => Now, async => true}) of
	{ok, PCF1, S1, _Events} ->
	    Data#{pcf := PCF1, aaa_session := S1};
	_ ->
	    Data
    end.

%% Report PCC rule(s) to the PCRF as INACTIVE via a Gx CCR-Update, without a
%% Rule-Failure-Code. Used when a bearer is deactivated on network request
%% (MME-Initiated Dedicated Bearer Deactivation, TS 23.401 5.4.4.2 /
%% TS 29.212 4.5.6) rather than because of a resource allocation failure.
report_rules_inactive(RuleNames,
		      #{pcf := PCF0, aaa_session := S0} = Data) ->
    Names = lists:flatmap(fun(N) when is_list(N) -> N; (N) -> [N] end, RuleNames),
    Report = #{'Charging-Rule-Name' => Names,
	       'PCC-Rule-Status'    =>
		   [?'DIAMETER_GX_PCC-RULE-STATUS_INACTIVE']},
    SOpts = #{'Charging-Rule-Report' => [Report]},
    Now = erlang:monotonic_time(),
    case smf_aaa_pcf:ccr_update(PCF0, S0, SOpts, #{now => Now, async => true}) of
	{ok, PCF1, S1, _Events} ->
	    Data#{pcf := PCF1, aaa_session := S1};
	_ ->
	    Data
    end.

%% Handle a Create Bearer Response that failed to activate the dedicated
%% bearer, whether the failure is signalled at the message level or in the
%% per-bearer Cause. Per TS 29.212 4.5.6/4.5.12 the PCEF shall remove the
%% affected PCC rule(s) and report them to the PCRF with PCC-Rule-Status
%% INACTIVE and Rule-Failure-Code RESOURCE_ALLOCATION_FAILURE.
handle_create_bearer_failure(PgwFTEID, State,
			     #{bearers := BearerMap, pcc := PCC,
			       pending_bearers := Pending0} = Data00) ->
    %% Terminal failure: drop any retained retry params for this bearer.
    Data0 = Data00#{retry_bearers =>
			maps:remove(PgwFTEID, maps:get(retry_bearers, Data00, #{}))},
    case maps:take(PgwFTEID, Pending0) of
	{{QCI, ARP, _AccessBearer, _ChId}, Pending} ->
	    case affected_pcc_rules(QCI, ARP, PCC) of
		[] ->
		    {keep_state, Data0#{pending_bearers := Pending}};
		RuleNames ->
		    PCC1 = PCC#pcc_ctx{
			     rules = maps:without(RuleNames, PCC#pcc_ctx.rules)},
		    Data1 = Data0#{pcc := PCC1, pending_bearers := Pending},
		    Data = report_bearer_failure(RuleNames, Data1),
		    %% Re-provision asynchronously (#65); the rule removal above
		    %% stands whether or not the UPF accepts it.
		    async_m:run_async(reprovision_proc(BearerMap),
				      fun(_V, S, D) -> {next_state, S, D} end,
				      fun(_R, S, D) -> {next_state, S, D} end,
				      State, Data)
	    end;
	error ->
	    {keep_state, Data0}
    end.

%% Handle a Create Bearer Response rejected with cause
%% ue_is_temporarily_not_reachable_due_to_power_saving. This is a *temporary*
%% condition, not a resource failure: per TS 29.274 8.4 and TS 23.401 5.4.1
%% step 12 the PGW must hold the network initiated procedure and re-attempt the
%% same Create Bearer Request once the UE is reachable again. The pending_bearers
%% and retry_bearers entries are therefore left intact so the retry (fired on the
%% next Modify Bearer Request) can proceed; no rule is removed and no failure is
%% reported to the PCRF.
handle_create_bearer_power_saving(PgwFTEID, Data) ->
    ?LOG(warning, "Create Bearer rejected: UE temporarily not reachable due to "
	 "power saving; holding bearer ~p for retry on next Modify Bearer Request",
	 [PgwFTEID]),
    {keep_state, Data}.

%% A Modify Bearer Request signals the UE is reachable again (TS 23.401 5.4.1
%% step 12). Re-issue any Create Bearer Request that was held because the UE was
%% temporarily unreachable due to power saving, then clear the retry set. The
%% matching pending_bearers entry is left in place so the retry response installs
%% the bearer as usual.
retry_pending_bearers(AccessTunnel, Data) ->
    Retry = maps:get(retry_bearers, Data, #{}),
    maps:foreach(
      fun(_PgwFTEID, {PTI, DefaultEBI, QoS, TFTBin, AccessBearer, ChId}) ->
	      create_dedicated_bearer(PTI, DefaultEBI, QoS, TFTBin, ChId,
				      AccessBearer, AccessTunnel)
      end, Retry),
    Data#{retry_bearers => #{}}.

%% Extract the per-bearer Cause from a Bearer Context group. The Cause is
%% mandatory in a Create Bearer Response (TS 29.274 Table 7.2.4-2); default to
%% request_accepted if it is absent so a well-formed accepted bearer installs.
bearer_context_cause(#{?'Cause' := #v2_cause{v2_cause = BearerCause}}) ->
    BearerCause;
bearer_context_cause(_) ->
    request_accepted.

%% Reverse-map a failed bearer's {QCI, ARP} to the installed PCC rule name(s)
%% that triggered it.
affected_pcc_rules(QCI, ARP, #pcc_ctx{rules = Rules}) ->
    maps:fold(
      fun(Name, Def, Acc) ->
	      case smf_gsn_lib:get_rule_qci_arp(Def) of
		  {QCI, ARP} -> [Name | Acc];
		  _          -> Acc
	      end
      end, [], Rules).

terminate(_Reason, _State, #{pfcp := PCtx, context := Context}) ->
    smf_pfcp_context:delete_session(terminate, PCtx),
    smf_gsn_lib:release_context_ips(Context),
    ok;
terminate(_Reason, _State, #{context := Context}) ->
    smf_gsn_lib:release_context_ips(Context),
    ok.

%%%===================================================================
%%% Helper functions
%%%===================================================================
ip2prefix({IP, Prefix}) ->
    <<Prefix:8, (smf_inet:ip2bin(IP))/binary>>.

%% response/3
response(Cmd, #tunnel{remote = #fq_teid{teid = TEID}}, Response) ->
    {Cmd, TEID, Response}.

%% response/4
response(Cmd, Tunnel, IEs0, #gtp{ie = ReqIEs})
  when is_record(Tunnel, tunnel) ->
    IEs = gtp_v2_c:build_recovery(Cmd, Tunnel, is_map_key(?'Recovery', ReqIEs), IEs0),
    response(Cmd, Tunnel, IEs).

match_tunnel(_Type, _Expected, undefined) ->
    ok;
match_tunnel(Type, #tunnel{remote = #fq_teid{ip = RemoteIP, teid = RemoteTEI} = Expected},
	     #v2_fully_qualified_tunnel_endpoint_identifier{
		instance       = 0,
		interface_type = Type,
		key            = RemoteTEI,
		ipv4           = RemoteIP4,
		ipv6           = RemoteIP6} = IE) ->
    case smf_inet:ip2bin(RemoteIP) of
	RemoteIP4 ->
	    ok;
	RemoteIP6 ->
	    ok;
	_ ->
	    ?LOG(error, "match_tunnel: IP address mismatch, ~p, ~p, ~p",
			[Type, Expected, IE]),
	    {error, [#v2_cause{v2_cause = invalid_peer}]}
    end;
match_tunnel(Type, Expected, IE) ->
    ?LOG(error, "match_tunnel: FqTEID not found, ~p, ~p, ~p",
		[Type, Expected, IE]),
    {error, [#v2_cause{v2_cause = invalid_peer}]}.

pdn_alloc(#v2_pdn_address_allocation{type = non_ip}) ->
    {'Non-IP', undefined, undefined};
pdn_alloc(#v2_pdn_address_allocation{type = ipv4v6,
				     address = << IP6PrefixLen:8, IP6Prefix:16/binary, IP4:4/binary>>}) ->
    {'IPv4v6', smf_inet:bin2ip(IP4), {smf_inet:bin2ip(IP6Prefix), IP6PrefixLen}};
pdn_alloc(#v2_pdn_address_allocation{type = ipv4,
				     address = << IP4:4/binary>>}) ->
    {'IPv4', smf_inet:bin2ip(IP4), undefined};
pdn_alloc(#v2_pdn_address_allocation{type = ipv6,
				     address = << IP6PrefixLen:8, IP6Prefix:16/binary>>}) ->
    {'IPv6', undefined, {smf_inet:bin2ip(IP6Prefix), IP6PrefixLen}}.

encode_paa(IPv4, undefined) when IPv4 /= undefined ->
    encode_paa(ipv4, smf_inet:ip2bin(smf_ip_pool:addr(IPv4)), <<>>);
encode_paa(undefined, IPv6) when IPv6 /= undefined ->
    encode_paa(ipv6, <<>>, ip2prefix(smf_ip_pool:ip(IPv6)));
encode_paa(IPv4, IPv6) when IPv4 /= undefined, IPv6 /= undefined ->
    encode_paa(ipv4v6, smf_inet:ip2bin(smf_ip_pool:addr(IPv4)),
	       ip2prefix(smf_ip_pool:ip(IPv6))).

encode_paa(Type, IPv4, IPv6) ->
    #v2_pdn_address_allocation{type = Type, address = <<IPv6/binary, IPv4/binary>>}.

close_context_proc(_Side, Reason, _Notify, _State, Data) ->
    smf_gtp_gsn_lib:close_context_proc(?API, Reason, Data).

map_attr('APN', #{?'Access Point Name' := #v2_access_point_name{apn = APN}}) ->
    iolist_to_binary(lists:join($., APN));
map_attr('IMSI', #{?'IMSI' := #v2_international_mobile_subscriber_identity{imsi = IMSI}}) ->
    IMSI;
map_attr('IMEI', #{?'ME Identity' := #v2_mobile_equipment_identity{mei = IMEI}}) ->
    IMEI;
map_attr('MSISDN', #{?'MSISDN' := #v2_msisdn{msisdn = MSISDN}}) ->
    MSISDN;
map_attr(Value, _) when is_binary(Value); is_list(Value) ->
    Value;
map_attr(Value, _) when is_atom(Value) ->
    atom_to_binary(Value, utf8);
map_attr(Value, _) ->
    io_lib:format("~w", [Value]).

map_username(_IEs, Username, _) when is_binary(Username) ->
    Username;
map_username(_IEs, [], Acc) ->
    iolist_to_binary(lists:reverse(Acc));
map_username(IEs, [H | Rest], Acc) ->
    Part = map_attr(H, IEs),
    map_username(IEs, Rest, [Part | Acc]).

%% init_session/4
init_session(IEs, #tunnel{local = #fq_teid{ip = LocalIP}},
	     #context{charging_identifier = ChargingId},
	     #{'Username' := #{default := Username},
	       'Password' := #{default := Password}}) ->
    MappedUsername = map_username(IEs, Username, []),
    {MCC, MNC} = smf_core:get_plmn_id(),
    Opts =
	case LocalIP of
	    {_,_,_,_,_,_,_,_} ->
		#{'3GPP-GGSN-IPv6-Address' => LocalIP};
	    _ ->
		#{'3GPP-GGSN-Address' => LocalIP}
	end,
    Opts#{'Username'		=> MappedUsername,
	  'Password'		=> Password,
	  'Service-Type'	=> 'Framed-User',
	  'Framed-Protocol'	=> 'GPRS-PDP-Context',
	  '3GPP-GGSN-MCC-MNC'	=> {MCC, MNC},
	  '3GPP-Charging-Id'	=> ChargingId
     }.

copy_ppp_to_session({pap, 'PAP-Authentication-Request', _Id, Username, Password}, Session0) ->
    Session = Session0#{'Username' => Username, 'Password' => Password},
    maps:without(['CHAP-Challenge', 'CHAP_Password'], Session);
copy_ppp_to_session({chap, 'CHAP-Challenge', _Id, Value, _Name}, Session) ->
    Session#{'CHAP_Challenge' => Value};
copy_ppp_to_session({chap, 'CHAP-Response', _Id, Value, Name}, Session0) ->
    Session = Session0#{'CHAP_Password' => Value, 'Username' => Name},
    maps:without(['Password'], Session);
copy_ppp_to_session(_, Session) ->
    Session.

non_empty_ip(_, {0,0,0,0}, Opts) ->
    Opts;
non_empty_ip(_, {{0,0,0,0,0,0,0,0}, _}, Opts) ->
    Opts;
non_empty_ip(Key, IP, Opts) ->
    maps:put(Key, IP, Opts).

copy_to_session(_, #v2_protocol_configuration_options{config = {0, Options}},
		#{'Username' := #{from_protocol_opts := true}}, Session) ->
    lists:foldr(fun copy_ppp_to_session/2, Session, Options);
copy_to_session(_, #v2_access_point_name{apn = APN}, _AAAopts, Session) ->
    {NI, _OI} = smf_node_selection:split_apn(APN),
    Session#{'APN' => APN,
	     'Called-Station-Id' =>
		 iolist_to_binary(lists:join($., NI))};
copy_to_session(_, #v2_msisdn{msisdn = MSISDN}, _AAAopts, Session) ->
    Session#{'Calling-Station-Id' => MSISDN, '3GPP-MSISDN' => MSISDN};
copy_to_session(_, #v2_international_mobile_subscriber_identity{imsi = IMSI}, _AAAopts, Session) ->
    case itu_e212:split_imsi(IMSI) of
	{MCC, MNC, _}
	  when is_binary(MCC), is_binary(MNC) ->
	    Session#{'3GPP-IMSI' => IMSI,
		     '3GPP-IMSI-MCC-MNC' => {MCC, MNC}};
	_ ->
	    Session#{'3GPP-IMSI' => IMSI}
    end;

copy_to_session(_, #v2_pdn_address_allocation{type = ipv4,
					      address = IP4}, _AAAopts, Session) ->
    IP4addr = smf_inet:bin2ip(IP4),
    S0 = Session#{'3GPP-PDP-Type' => 'IPv4'},
    S1 = non_empty_ip('Framed-IP-Address', IP4addr, S0),
    _S = non_empty_ip('Requested-IP-Address', IP4addr, S1);
copy_to_session(_, #v2_pdn_address_allocation{type = ipv6,
					      address = <<IP6PrefixLen:8,
							  IP6Prefix:16/binary>>},
		_AAAopts, Session) ->
    IP6addr = {smf_inet:bin2ip(IP6Prefix), IP6PrefixLen},
    S0 = Session#{'3GPP-PDP-Type' => 'IPv6'},
    S1 = non_empty_ip('Framed-IPv6-Prefix', IP6addr, S0),
    _S = non_empty_ip('Requested-IPv6-Prefix', IP6addr, S1);
copy_to_session(_, #v2_pdn_address_allocation{type = ipv4v6,
					      address = <<IP6PrefixLen:8,
							  IP6Prefix:16/binary,
							  IP4:4/binary>>},
		_AAAopts, Session) ->
    IP4addr = smf_inet:bin2ip(IP4),
    IP6addr = {smf_inet:bin2ip(IP6Prefix), IP6PrefixLen},
    S0 = Session#{'3GPP-PDP-Type' => 'IPv4v6'},
    S1 = non_empty_ip('Framed-IP-Address', IP4addr, S0),
    S2 = non_empty_ip('Requested-IP-Address', IP4addr, S1),
    S3 = non_empty_ip('Framed-IPv6-Prefix', IP6addr, S2),
    _S = non_empty_ip('Requested-IPv6-Prefix', IP6addr, S3);
copy_to_session(_, #v2_pdn_address_allocation{type = non_ip}, _AAAopts, Session) ->
    Session#{'3GPP-PDP-Type' => 'Non-IP'};

%% 3GPP TS 29.274, Rel 15, Table 7.2.1-1, Note 1:
%%   The conditional PDN Type IE is redundant on the S4/S11 and S5/S8 interfaces
%%   (as the PAA IE contains exactly the same field). The receiver may ignore it.
%%

copy_to_session(?'EPS Bearer ID', #v2_eps_bearer_id{eps_bearer_id = EBI},
		_AAAopts, Session) ->
    Session#{'3GPP-NSAPI' => EBI};
copy_to_session(?'Bearer Contexts to be created',
		#v2_bearer_context{
		   group =
		       #{?'EPS Bearer ID' := #v2_eps_bearer_id{eps_bearer_id = EBI}}},
		_AAAopts, Session) ->
    Session#{'3GPP-NSAPI' => EBI};
copy_to_session(_, #v2_selection_mode{mode = Mode}, _AAAopts, Session) ->
    Session#{'3GPP-Selection-Mode' => Mode};
copy_to_session(_, #v2_charging_characteristics{value = Value}, _AAAopts, Session) ->
    Session#{'3GPP-Charging-Characteristics' => Value};

copy_to_session(_, #v2_serving_network{plmn_id = PLMN}, _AAAopts, Session) ->
    Session#{'3GPP-SGSN-MCC-MNC' => PLMN};
copy_to_session(_, #v2_mobile_equipment_identity{mei = IMEI}, _AAAopts, Session) ->
    Session#{'3GPP-IMEISV' => IMEI};
copy_to_session(_, #v2_rat_type{rat_type = Type}, _AAAopts, Session) ->
    Session#{'3GPP-RAT-Type' => Type};
copy_to_session(_, #v2_user_location_information{} = Info, _AAAopts, Session) ->
    ULI = lists:foldl(
	    fun(X, S) when is_record(X, cgi)  -> S#{'CGI' => X};
	       (X, S) when is_record(X, sai)  -> S#{'SAI' => X};
	       (X, S) when is_record(X, rai)  -> S#{'RAI' => X};
	       (X, S) when is_record(X, tai)  -> S#{'TAI' => X};
	       (X, S) when is_record(X, ecgi) -> S#{'ECGI' => X};
	       (X, S) when is_record(X, lai)  -> S#{'LAI' => X};
	       (X, S) when is_record(X, macro_enb) -> S#{'macro-eNB' => X};
	       (X, S) when is_record(X, ext_macro_enb) -> S#{'ext-macro-eNB' => X};
	       (_, S) -> S
	    end, #{}, tl(tuple_to_list(Info))),
    Session#{'User-Location-Info' => ULI};
copy_to_session(_, #v2_ue_time_zone{timezone = TZ, dst = DST}, _AAAopts, Session) ->
    Session#{'3GPP-MS-TimeZone' => {TZ, DST}};
copy_to_session(_, _, _AAAopts, Session) ->
    Session.

copy_qos_to_session(#{?'APN-AMBR' :=
			  #v2_aggregate_maximum_bit_rate{
			     uplink = AMBR4ul, downlink = AMBR4dl}} = IEs,
		    Session) ->
    case get_default_bearer_ctx(IEs) of
	#v2_bearer_context{
	   group = #{?'Bearer Level QoS' :=
			 #v2_bearer_level_quality_of_service{
			    pci = PCI, pl = PL, pvi = PVI, label = Label,
			    maximum_bit_rate_for_uplink = MBR4ul,
			    maximum_bit_rate_for_downlink = MBR4dl,
			    guaranteed_bit_rate_for_uplink = GBR4ul,
			    guaranteed_bit_rate_for_downlink = GBR4dl}}} ->
	    ARP = #{
		    'Priority-Level' => PL,
		    'Pre-emption-Capability' => PCI,
		    'Pre-emption-Vulnerability' => PVI
		   },
	    Info = #{
		     'QoS-Class-Identifier' => Label,
		     'Max-Requested-Bandwidth-UL' => MBR4ul * 1000,
		     'Max-Requested-Bandwidth-DL' => MBR4dl * 1000,
		     'Guaranteed-Bitrate-UL' => GBR4ul * 1000,
		     'Guaranteed-Bitrate-DL' => GBR4dl * 1000,

		     %% TBD:
		     %%   [ Bearer-Identifier ]

		     'Allocation-Retention-Priority' => ARP,
		     'APN-Aggregate-Max-Bitrate-UL' => AMBR4ul * 1000,
		     'APN-Aggregate-Max-Bitrate-DL' => AMBR4dl * 1000

		     %%  *[ Conditional-APN-Aggregate-Max-Bitrate ]
		    },
	    Session#{'QoS-Information' => Info};
	_ ->
	    Session
    end;
copy_qos_to_session(_, Session) ->
    Session.

ip_to_session({_,_,_,_} = IP, #{ip4 := Key}, Session) ->
    Session#{Key => IP};
ip_to_session({_,_,_,_,_,_,_,_} = IP, #{ip6 := Key}, Session) ->
    Session#{Key => IP}.

copy_tunnel_to_session(#tunnel{version = Version, remote = #fq_teid{ip = IP}}, Session) ->
    ip_to_session(IP, #{ip4 => '3GPP-SGSN-Address',
			ip6 => '3GPP-SGSN-IPv6-Address'},
		  Session#{'GTP-Version' => Version});
copy_tunnel_to_session(_, Session) ->
    Session.

copy_bearer_to_session(#bearer{remote = #fq_teid{ip = IP}}, Session) ->
    ip_to_session(IP, #{ip4 => '3GPP-SGSN-UP-Address',
			ip6 => '3GPP-SGSN-UP-IPv6-Address'}, Session);
copy_bearer_to_session(_, Session) ->
    Session.

sec_rat_udr_to_report([], _, Reports) ->
    Reports;
sec_rat_udr_to_report(#v2_secondary_rat_usage_data_report{irpgw = false}, _, Reports) ->
    Reports;
sec_rat_udr_to_report(#v2_secondary_rat_usage_data_report{irpgw = true} = Report,
		      #context{charging_identifier = ChargingId}, Reports) ->
    [smf_gsn_lib:secondary_rat_usage_data_report_to_rf(ChargingId, Report)|Reports];
sec_rat_udr_to_report([H|T], Ctx, Reports) ->
    sec_rat_udr_to_report(H, Ctx, sec_rat_udr_to_report(T, Ctx, Reports)).

process_secondary_rat_usage_data_reports(
  #{?'Secondary RAT Usage Data Report' := SecRatUDR}, Context,
  #{charging := Charging, aaa_session := Session}) ->
    Report =
	#{'RAN-Secondary-RAT-Usage-Report' =>
	      sec_rat_udr_to_report(SecRatUDR, Context, [])},
    Now = erlang:monotonic_time(),
    SOpts = #{now => Now, async => true},
    smf_aaa_charging:rf_update(Charging, Session, Report, SOpts),
    ok;
process_secondary_rat_usage_data_reports(_, _, _) ->
    ok.

init_session_from_gtp_req(IEs, AAAopts, Tunnel, Bearer, Session0)
  when is_record(Tunnel, tunnel), is_record(Bearer, bearer) ->
    Session1 = copy_qos_to_session(IEs, Session0),
    Session2 = copy_tunnel_to_session(Tunnel, Session1),
    Session = copy_bearer_to_session(Bearer, Session2),
    maps:fold(copy_to_session(_, _, AAAopts, _), Session, IEs).

update_session_from_gtp_req(IEs, Session0, Tunnel, Bearer)
  when is_record(Tunnel, tunnel) ->
    NewSOpts0 = copy_qos_to_session(IEs, Session0),
    NewSOpts1 = copy_tunnel_to_session(Tunnel, NewSOpts0),
    NewSOpts2 = copy_bearer_to_session(Bearer, NewSOpts1),
    NewSOpts =
	maps:fold(copy_to_session(_, _, undefined, _), NewSOpts2, IEs),
    URRActions = gtp_context:collect_charging_events(Session0, NewSOpts),
    {URRActions, NewSOpts}.

get_context_from_bearer(?'EPS Bearer ID', #v2_eps_bearer_id{eps_bearer_id = EBI},
			#context{default_bearer_id = undefined} = Context) ->
    Context#context{default_bearer_id =  EBI};
get_context_from_bearer(_K, _, Context) ->
    Context.

%% EPS Bearer Id (EBI):
%%
%% From TS 29.274:
%% > This IE shall be included on S4/S11 in RAU/TAU/HO except in the Gn/Gp SGSN to MME/S4-SGSN
%% > RAU/TAU/HO procedures with SGW change to identify the default bearer of the PDN Connection
%%
%% So, we either get a list of bearer and the Linked EPS Bearer ID tell us which on is the
%% default bearer, or we get only on bearer and that is the default bearer
get_context_from_req(?'Linked EPS Bearer ID', #v2_eps_bearer_id{eps_bearer_id = EBI}, Context) ->
    Context#context{default_bearer_id =  EBI};
get_context_from_req(_K, #v2_bearer_context{instance = 0, group = Bearer}, Context) ->
    maps:fold(fun get_context_from_bearer/3, Context, Bearer);

get_context_from_req(?'Access Point Name', #v2_access_point_name{apn = APN}, Context) ->
    Context#context{apn = APN};
get_context_from_req(?'IMSI', #v2_international_mobile_subscriber_identity{imsi = IMSI}, Context) ->
    Context#context{imsi = IMSI};
get_context_from_req(?'ME Identity', #v2_mobile_equipment_identity{mei = IMEI}, Context) ->
    Context#context{imei = IMEI};
get_context_from_req(?'MSISDN', #v2_msisdn{msisdn = MSISDN}, Context) ->
    Context#context{msisdn = MSISDN};
get_context_from_req(?'PDN Address Allocation', #v2_pdn_address_allocation{type = Type}, Context) ->
    Context#context{pdn_type = Type};
get_context_from_req(_, _, Context) ->
    Context.

update_context_from_gtp_req(#gtp{ie = IEs} = Req, Context0) ->
    Context1 = gtp_v2_c:update_context_id(Req, Context0),
    maps:fold(fun get_context_from_req/3, Context1, IEs).

get_tunnel_from_bearer(none, _, Bearer) ->
    {ok, Bearer};
get_tunnel_from_bearer({_, #v2_fully_qualified_tunnel_endpoint_identifier{
			      interface_type = Interface,
			      key = TEI, ipv4 = IP4, ipv6 = IP6}, Next}, Tunnel, Bearer)
  when Interface =:= ?'S5/S8-U SGW';
       Interface =:= ?'S5/S8-U PGW' ->
    do([error_m ||
	   IP <- smf_gsn_lib:choose_ip_by_tunnel(Tunnel, IP4, IP6),
	   begin
	       FqTEID = #fq_teid{ip = smf_inet:bin2ip(IP), teid = TEI},
	       get_tunnel_from_bearer(maps:next(Next), Tunnel, Bearer#bearer{remote = FqTEID})
	   end]);
get_tunnel_from_bearer({_, _, Next}, Tunnel, Bearer) ->
    get_tunnel_from_bearer(maps:next(Next), Tunnel, Bearer).

get_tunnel_from_req(none, Tunnel, Bearer) ->
    {ok, {Tunnel, Bearer}};
get_tunnel_from_req({_, #v2_fully_qualified_tunnel_endpoint_identifier{
			   interface_type = Interface,
			   key = TEI, ipv4 = IP4, ipv6 = IP6}, Next},
		    Tunnel, Bearer)
  when Interface =:= ?'S5/S8-C SGW';
       Interface =:= ?'S5/S8-C PGW' ->
    do([error_m ||
	   IP <- smf_gsn_lib:choose_ip_by_tunnel(Tunnel, IP4, IP6),
	   begin
	       FqTEID = #fq_teid{ip = smf_inet:bin2ip(IP), teid = TEI},
	       get_tunnel_from_req(
		 maps:next(Next), Tunnel#tunnel{remote = FqTEID}, Bearer)
	   end]);
get_tunnel_from_req({_, #v2_bearer_context{instance = 0, group = Group}, Next},
		    Tunnel, Bearer0) ->
    do([error_m ||
	   Bearer <- get_tunnel_from_bearer(maps:next(maps:iterator(Group)), Tunnel, Bearer0),
	   get_tunnel_from_req(maps:next(Next), Tunnel, Bearer)
       ]);
get_tunnel_from_req({_, _, Next}, Tunnel, Bearer) ->
   get_tunnel_from_req(maps:next(Next), Tunnel, Bearer).

%% update_tunnel_from_gtp_req/3
update_tunnel_from_gtp_req(#gtp{ie = IEs}, Tunnel, Bearer) ->
    get_tunnel_from_req(maps:next(maps:iterator(IEs)), Tunnel, Bearer).

%% update_tunnel_from_gtp_req/4 - extract control-plane F-TEID from IEs,
%% user-plane F-TEID from the given default bearer context group.
update_tunnel_from_gtp_req(#gtp{ie = IEs}, BearerGroup, Tunnel0, Bearer0) ->
    do([error_m ||
	   {Tunnel, _} <- get_tunnel_from_req(
			    maps:next(maps:iterator(IEs)), Tunnel0, Bearer0),
	   Bearer <- get_tunnel_from_bearer(
		       maps:next(maps:iterator(BearerGroup)), Tunnel, Bearer0),
	   return({Tunnel, Bearer})]).

enter_ie(_Key, Value, IEs)
  when is_list(IEs) ->
    [Value|IEs].
%% enter_ie(Key, Value, IEs)
%%   when is_map(IEs) ->
%%     IEs#{Key := Value}.

copy_ies_to_response(_, ResponseIEs, []) ->
    ResponseIEs;
copy_ies_to_response(RequestIEs, ResponseIEs0, [H|T]) ->
    ResponseIEs =
	case RequestIEs of
	    #{H := Value} ->
		enter_ie(H, Value, ResponseIEs0);
	    _ ->
		ResponseIEs0
	end,
    copy_ies_to_response(RequestIEs, ResponseIEs, T).


msg(#tunnel{remote = #fq_teid{teid = RemoteCntlTEI}}, Type, RequestIEs) ->
    #gtp{version = v2, type = Type, tei = RemoteCntlTEI, ie = RequestIEs}.

%% send_request/5
send_request(#tunnel{remote = #fq_teid{ip = RemoteCntlIP}} = Tunnel, T3, N3, Msg, ReqInfo) ->
    send_request(Tunnel, any, RemoteCntlIP, ?GTP2c_PORT, T3, N3, Msg, ReqInfo).

%% send_request/6
send_request(Tunnel, T3, N3, Type, RequestIEs, ReqInfo) ->
    send_request(Tunnel, T3, N3, msg(Tunnel, Type, RequestIEs), ReqInfo).

%% send_request/8
send_request(Tunnel, Src, DstIP, DstPort, T3, N3, Msg, ReqInfo) ->
    gtp_context:send_request(Tunnel, Src, DstIP, DstPort, T3, N3, Msg, ReqInfo).

map_term_cause(TermCause)
  when TermCause =:= cp_inactivity_timeout;
       TermCause =:= up_inactivity_timeout ->
    pdn_connection_inactivity_timer_expires;
map_term_cause(_TermCause) ->
    reactivation_requested.

delete_context(From, TermCause, #{session := connected} = State,
	       #{tunnels := #{'Access' := Tunnel}, context :=
		     #context{default_bearer_id = EBI}} = Data) ->
    Type = delete_bearer_request,
    RequestIEs0 = [#v2_cause{v2_cause = map_term_cause(TermCause)},
		   #v2_eps_bearer_id{eps_bearer_id = EBI}],
    RequestIEs = gtp_v2_c:build_recovery(Type, Tunnel, false, RequestIEs0),
    send_request(Tunnel, ?T3, ?N3, Type, RequestIEs, {From, TermCause}),
    {next_state, State#{session := shutdown_initiated}, Data};
delete_context(undefined, _, _, _) ->
    keep_state_and_data;
delete_context(From, _, _, _) ->
    {keep_state_and_data, [{reply, From, ok}]}.

ppp_ipcp_conf_resp(Verdict, Opt, IPCP) ->
    maps:update_with(Verdict, fun(O) -> [Opt|O] end, [Opt], IPCP).

ppp_ipcp_conf(#{'MS-Primary-DNS-Server' := DNS}, {ms_dns1, <<0,0,0,0>>}, IPCP) ->
    ppp_ipcp_conf_resp('CP-Configure-Nak', {ms_dns1, smf_inet:ip2bin(DNS)}, IPCP);
ppp_ipcp_conf(#{'MS-Secondary-DNS-Server' := DNS}, {ms_dns2, <<0,0,0,0>>}, IPCP) ->
    ppp_ipcp_conf_resp('CP-Configure-Nak', {ms_dns2, smf_inet:ip2bin(DNS)}, IPCP);
ppp_ipcp_conf(#{'MS-Primary-NBNS-Server' := DNS}, {ms_wins1, <<0,0,0,0>>}, IPCP) ->
    ppp_ipcp_conf_resp('CP-Configure-Nak', {ms_wins1, smf_inet:ip2bin(DNS)}, IPCP);
ppp_ipcp_conf(#{'MS-Secondary-NBNS-Server' := DNS}, {ms_wins2, <<0,0,0,0>>}, IPCP) ->
    ppp_ipcp_conf_resp('CP-Configure-Nak', {ms_wins2, smf_inet:ip2bin(DNS)}, IPCP);

ppp_ipcp_conf(_SessionOpts, Opt, IPCP) ->
    ppp_ipcp_conf_resp('CP-Configure-Reject', Opt, IPCP).

pdn_ppp_pco(SessionOpts, {pap, 'PAP-Authentication-Request', Id, _Username, _Password}, Opts) ->
    [{pap, 'PAP-Authenticate-Ack', Id, maps:get('Reply-Message', SessionOpts, <<>>)}|Opts];
pdn_ppp_pco(SessionOpts, {chap, 'CHAP-Response', Id, _Value, _Name}, Opts) ->
    [{chap, 'CHAP-Success', Id, maps:get('Reply-Message', SessionOpts, <<>>)}|Opts];
pdn_ppp_pco(SessionOpts, {ipcp,'CP-Configure-Request', Id, CpReqOpts}, Opts) ->
    CpRespOpts = lists:foldr(ppp_ipcp_conf(SessionOpts, _, _), #{}, CpReqOpts),
    maps:fold(fun(K, V, O) -> [{ipcp, K, Id, V} | O] end, Opts, CpRespOpts);

pdn_ppp_pco(SessionOpts, {?'PCO-DNS-Server-IPv6-Address', <<>>}, Opts) ->
    [{?'PCO-DNS-Server-IPv6-Address', smf_inet:ip2bin(DNS)}
     || DNS <- maps:get('DNS-Server-IPv6-Address', SessionOpts, [])]
	++ [{?'PCO-DNS-Server-IPv6-Address', smf_inet:ip2bin(DNS)}
	    || DNS <- maps:get('3GPP-IPv6-DNS-Servers', SessionOpts, [])]
	++ Opts;
pdn_ppp_pco(SessionOpts, {?'PCO-DNS-Server-IPv4-Address', <<>>}, Opts) ->
    lists:foldr(fun(Key, O) ->
			case maps:find(Key, SessionOpts) of
			    {ok, DNS} ->
				[{?'PCO-DNS-Server-IPv4-Address', smf_inet:ip2bin(DNS)} | O];
			    _ ->
				O
			end
		end, Opts, ['MS-Secondary-DNS-Server', 'MS-Primary-DNS-Server']);
pdn_ppp_pco(SessionOpts, {?'PCO-Bearer-Control-Mode', <<>>}, Opts) ->
    case maps:get('Bearer-Control-Mode', SessionOpts, undefined) of
	BCM when is_integer(BCM) ->
	    [{?'PCO-Bearer-Control-Mode', <<BCM:8>>} | Opts];
	_ ->
	    Opts
    end;
pdn_ppp_pco(_SessionOpts, PPPReqOpt, Opts) ->
    ?LOG(debug, "Apply PPP Opt: ~p", [PPPReqOpt]),
    Opts.

pdn_pco(SessionOpts, #{?'Protocol Configuration Options' :=
			   #v2_protocol_configuration_options{config = {0, PPPReqOpts}}}, IE) ->
    case lists:foldr(pdn_ppp_pco(SessionOpts, _, _), [], PPPReqOpts) of
	[]   -> IE;
	Opts -> [#v2_protocol_configuration_options{config = {0, Opts}} | IE]
    end;
pdn_pco(_SessionOpts, _RequestIEs, IE) ->
    IE.

context_charging_id(#context{charging_identifier = ChargingId}) ->
    #v2_charging_id{id = <<ChargingId:32>>}.

bearer_qos_profile(#{'QoS-Information' :=
			 #{'QoS-Class-Identifier' := Label,
			   'Max-Requested-Bandwidth-UL' := MBR4ul,
			   'Max-Requested-Bandwidth-DL' := MBR4dl,
			   'Guaranteed-Bitrate-UL' := GBR4ul,
			   'Guaranteed-Bitrate-DL' := GBR4dl,

			   'Allocation-Retention-Priority' :=
			       #{'Priority-Level' := PL,
				 'Pre-emption-Capability' := PCI,
				 'Pre-emption-Vulnerability' := PVI}}}, IE) ->
    QoS = #v2_bearer_level_quality_of_service{
	     pci = PCI, pl = PL, pvi = PVI, label = Label,
	     maximum_bit_rate_for_uplink = MBR4ul div 1000,
	     maximum_bit_rate_for_downlink = MBR4dl div 1000,
	     guaranteed_bit_rate_for_uplink = GBR4ul div 1000,
	     guaranteed_bit_rate_for_downlink = GBR4dl div 1000
	    },
    [QoS | IE];
bearer_qos_profile(_SessionOpts, IE) ->
    IE.

bearer_context(SessionOpts, BearerMap, Context, IEs) ->
    AccessBearers =
        lists:sort(maps:fold(fun({'Access', N}, #bearer{} = Bearer, Acc) ->
                                     [{N, Bearer} | Acc];
                                (_, _, Acc) ->
                                     Acc
                             end, [], BearerMap)),
    {BearerIEs, _} =
        lists:foldl(fun({N, Bearer}, {Acc, Inst}) ->
                            BearerCtx0 =
                                [#v2_cause{v2_cause = request_accepted},
                                 context_charging_id(Context),
                                 #v2_eps_bearer_id{eps_bearer_id = N},
                                 s5s8_pgw_gtp_u_tei(Bearer)],
                            BearerCtx = bearer_qos_profile(SessionOpts, BearerCtx0),
                            {[#v2_bearer_context{instance = Inst,
                                                 group = BearerCtx} | Acc],
                             Inst}
                    end, {IEs, 0}, AccessBearers),
    BearerIEs.

fq_teid(Instance, Type, TEI, {_,_,_,_} = IP) ->
    #v2_fully_qualified_tunnel_endpoint_identifier{
       instance = Instance, interface_type = Type,
       key = TEI, ipv4 = smf_inet:ip2bin(IP)};
fq_teid(Instance, Type, TEI, {_,_,_,_,_,_,_,_} = IP) ->
    #v2_fully_qualified_tunnel_endpoint_identifier{
       instance = Instance, interface_type = Type,
       key = TEI, ipv6 = smf_inet:ip2bin(IP)}.

s5s8_pgw_gtp_c_tei(#tunnel{local = #fq_teid{ip = IP, teid = TEI}}) ->
    %% PGW S5/S8/ S2a/S2b F-TEID for PMIP based interface
    %% or for GTP based Control Plane interface
    fq_teid(1, ?'S5/S8-C PGW', TEI, IP).

s5s8_pgw_gtp_u_tei(Bearer) ->
    s5s8_pgw_gtp_u_tei(2, Bearer).

s5s8_pgw_gtp_u_tei(Instance, #bearer{local = #fq_teid{ip = IP, teid = TEI}}) ->
    fq_teid(Instance, ?'S5/S8-U PGW', TEI, IP).

cr_ran_type(1)  -> 'UTRAN';
cr_ran_type(2)  -> 'UTRAN';
cr_ran_type(6)  -> 'EUTRAN';
cr_ran_type(8)  -> 'EUTRAN';
cr_ran_type(9)  -> 'EUTRAN';
cr_ran_type(10) -> 'NR';
cr_ran_type(_)  -> undefined.

%% it is unclear from TS 29.274 if the CRA IE can only be included when the
%% SGSN/MME has indicated support for it in the Indication IE.
%% Some comments in Modify Bearer Request suggest that it might be possbile
%% to unconditionally set it, other places state that is should only be sent
%% when the SGSN/MME indicated support for it.
%% For the moment only include it when the CRSI flag was set.

change_reporting_action(true, ENBCRSI, #{?'RAT Type' :=
					     #v2_rat_type{rat_type = Type}}, Trigger, IE) ->
    change_reporting_action(ENBCRSI, cr_ran_type(Type), Trigger, IE);
change_reporting_action(_, _, _, _, IE) ->
    IE.

change_reporting_action(true, 'EUTRAN', #{'tai-change' := true,
					  'user-location-info-change' := true}, IE) ->
    [#v2_change_reporting_action{
	action = start_reporting_tai__macro_enodeb_id_and_extended_macro_enodeb_id}|IE];
change_reporting_action(true, 'EUTRAN', #{'user-location-info-change' := true}, IE) ->
    [#v2_change_reporting_action{
	action = start_reporting_macro_enodeb_id_and_extended_macro_enodeb_id}|IE];
change_reporting_action(_, 'EUTRAN', #{'tai-change' := true, 'ecgi-change' := true}, IE) ->
    [#v2_change_reporting_action{action = start_reporting_tai_and_ecgi}|IE];
change_reporting_action(_, 'EUTRAN', #{'tai-change' := true}, IE) ->
    [#v2_change_reporting_action{action = start_reporting_tai}|IE];
change_reporting_action(_, 'EUTRAN', #{'ecgi-change' := true}, IE) ->
    [#v2_change_reporting_action{action = start_reporting_ecgi}|IE];
change_reporting_action(_, 'UTRAN', #{'user-location-info-change' := true}, IE) ->
    [#v2_change_reporting_action{action = start_reporting_cgi_sai_and_rai}|IE];
change_reporting_action(_, 'UTRAN', #{'cgi-sai-change' := true, 'rai-change' := true}, IE) ->
    [#v2_change_reporting_action{action = start_reporting_cgi_sai_and_rai}|IE];
change_reporting_action(_, 'UTRAN', #{'cgi-sai-change' := true}, IE) ->
    [#v2_change_reporting_action{action = start_reporting_cgi_sai}|IE];
change_reporting_action(_, 'UTRAN', #{'rai-change' := true}, IE) ->
    [#v2_change_reporting_action{action = start_reporting_rai}|IE];
change_reporting_action(_, _, _Triggers, IE) ->
    IE.

%% A bearer the request asked for that policy/charging did not authorize is
%% reported as not created. TS 29.274 7.2.2 (Table 7.2.2-2) makes the per-bearer
%% Cause mandatory, so the peer learns which bearers it may keep -- TS 23.401
%% Annex D states the same principle from the MME side: establish the bearers it
%% can and deactivate those it cannot. No F-TEID is returned: there is no PDR and
%% the UPF was never told about the bearer.
rejected_bearer_contexts(EBIs) ->
    [#v2_bearer_context{
	instance = 1,
	group = [#v2_cause{v2_cause = no_resources_available},
		 #v2_eps_bearer_id{eps_bearer_id = EBI}]} || EBI <- EBIs].

change_reporting_actions(RequestIEs, IE0) ->
    Indications = gtp_v2_c:get_indication_flags(RequestIEs),
    Triggers = smf_charging:reporting_triggers(),

    CRSI = proplists:get_bool('CRSI', Indications),
    ENBCRSI = proplists:get_bool('ENBCRSI', Indications),
    _IE = change_reporting_action(CRSI, ENBCRSI, RequestIEs, Triggers, IE0).

create_session_response(Cause, SessionOpts, RequestIEs,
			Tunnel, BearerMap, Rejected,
			#context{ms_ip = #ue_ip{v4 = MSv4, v6 = MSv6}} = Context) ->

    IE0 = bearer_context(SessionOpts, BearerMap, Context, rejected_bearer_contexts(Rejected)),
    IE1 = pdn_pco(SessionOpts, RequestIEs, IE0),
    IE2 = change_reporting_actions(RequestIEs, IE1),

    [Cause,
     #v2_apn_restriction{restriction_type_value = 0},
     context_charging_id(Context),
     s5s8_pgw_gtp_c_tei(Tunnel),
     encode_paa(MSv4, MSv6) | IE2].

%% Wrapper for gen_statem state_callback_result Actions argument
%% Timeout set in the context of a prolonged idle gtpv2 session
context_idle_action(Actions, #context{inactivity_timeout = Timeout})
  when is_integer(Timeout) orelse Timeout =:= infinity ->
    [{{timeout, context_idle}, Timeout, check_session_liveness} | Actions];
context_idle_action(Actions, _) ->
    Actions.
