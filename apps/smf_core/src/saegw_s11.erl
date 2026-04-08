%% Copyright 2018-2020, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(saegw_s11).

-behaviour(gtp_api).

-compile([{parse_transform, do},
	  {parse_transform, cut}]).

-export([validate_options/1, init/2, request_spec/3,
	 handle_pdu/4,
	 handle_request/5, handle_response/5,
	 handle_event/4, terminate/3]).

-export([delete_context/4, close_context/5]).

%% PFCP context API's
%%-export([defered_usage_report/3]).

-include_lib("kernel/include/logger.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include_lib("pfcplib/include/pfcp_packet.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").
-include_lib("smf_aaa/include/diameter_3gpp_ts29_212.hrl").
-include_lib("smf_aaa/include/smf_aaa_session.hrl").
-include("include/smf.hrl").

-import(smf_aaa_session, [to_session/1]).

-define(API, 's11').
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
-define('Protocol Configuration Options',		{v2_protocol_configuration_options, 0}).
-define('ME Identity',					{v2_mobile_equipment_identity, 0}).
-define('APN-AMBR',					{v2_aggregate_maximum_bit_rate, 0}).
-define('Bearer Level QoS',				{v2_bearer_level_quality_of_service, 0}).
-define('EPS Bearer ID',                                {v2_eps_bearer_id, 0}).
-define('Indication',                                   {v2_indication, 0}).

-define('S1-U eNode-B', 0).
-define('S1-U SGW',     1).
-define('S5/S8-U SGW',  4).
-define('S5/S8-U PGW',  5).
-define('S5/S8-C SGW',  6).
-define('S5/S8-C PGW',  7).
-define('S11-C MME',    10).
-define('S11/S4-C SGW', 11).

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
     {?'Bearer Contexts to be created',				mandatory}];
request_spec(v2, delete_session_request, _) ->
    [];
request_spec(v2, modify_bearer_request, _) ->
    [];
request_spec(v2, modify_bearer_command, _) ->
    [{?'APN-AMBR' ,						mandatory},
     {?'Bearer Contexts to be modified',			mandatory}];
request_spec(v2, _, _) ->
    [].

-define(HandlerDefaults, [{protocol, undefined}]).

validate_options(Options) ->
    ?LOG(debug, "SAEGW S11 Options: ~p", [Options]),
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
    Data = Data0#{aaa_session => AAASession, pcf => PCF,
		  charging => Charging, aaa_auth => AAAAuth, pcc => PCC},
    {ok, smf_context:init_state(), Data}.

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
	     bearer := #{left := LeftBearer, right := RightBearer}} = Data) ->
    ?LOG(debug, "GTP-U SAE-GW: ~p, ~p", [ReqKey, gtp_c_lib:fmt_gtp(Msg)]),

    smf_gsn_lib:ip_pdu(PDU, LeftBearer, RightBearer, Context, PCtx),
    {keep_state, Data}.

handle_request(_ReqKey, _Msg, true, _State, _Data) ->
    %% resent request
    keep_state_and_data;

handle_request(ReqKey,
	       #gtp{type = create_session_request,
		    ie = #{?'Access Point Name' := #v2_access_point_name{apn = APN},
			   ?'Bearer Contexts to be created' :=
			       #v2_bearer_context{group = #{?'EPS Bearer ID' := EBI}}
			  } = IEs} = Request,
	       _Resent, State,
	       #{context := Context0, aaa_opts := AAAopts, node_selection := NodeSelect,
		  left_tunnel := LeftTunnel0, bearer := #{left := LeftBearer0},
		 aaa_session := S0, pcf := PCF0, charging := C0, aaa_auth := A0,
		 pcc := PCC0} = Data) ->

    Services = [{'x-3gpp-upf', 'x-sxb'}],

    {ok, UpSelInfo} =
	smf_gtp_gsn_lib:connect_upf_candidates(APN, Services, NodeSelect, []),

    PAA = maps:get(?'PDN Address Allocation', IEs, undefined),
    DAF = proplists:get_bool('DAF', gtp_v2_c:get_indication_flags(IEs)),

    Context1 = update_context_from_gtp_req(Request, Context0),

    {LeftTunnel1, LeftBearer1} =
	case update_tunnel_from_gtp_req(Request, LeftTunnel0, LeftBearer0) of
	    {ok, Result1} -> Result1;
	    {error, Err1} -> throw(Err1#ctx_err{context = Context1, tunnel = LeftTunnel0})
	end,

    LeftTunnel =
	case gtp_path:bind_tunnel(LeftTunnel1) of
	    {ok, LT} -> LT;
	    {error, Err2} -> throw(Err2#ctx_err{context = Context1, tunnel = LeftTunnel1})
	end,

    gtp_context:terminate_colliding_context(LeftTunnel, Context1),

    SessionOpts0 = pgw_s5s8:init_session(IEs, LeftTunnel, Context1, AAAopts),
    SessionOpts1 = pgw_s5s8:init_session_from_gtp_req(IEs, AAAopts, LeftTunnel, LeftBearer1, SessionOpts0),
    %% SessionOpts = init_session_qos(ReqQoSProfile, SessionOpts1),

    {Verdict, Cause, SessionOpts, Context, Bearer, PCC4, PCtx,
     S1, PCF1, C1, A1} =
       case smf_gtp_gsn_lib:create_session(APN, pdn_alloc(PAA), DAF, UpSelInfo,
					    S0, PCF0, C0, A0,
					    SessionOpts1, Context1, LeftTunnel, LeftBearer1, PCC0) of
	   {ok, Result} -> Result;
	   {error, Err} -> throw(Err)
       end,

    FinalData =
	Data#{context => Context, pfcp => PCtx, pcc => PCC4,
	      left_tunnel => LeftTunnel, bearer => Bearer,
	      aaa_session => S1, pcf => PCF1, charging => C1, aaa_auth => A1},

    ResponseIEs = create_session_response(Cause, SessionOpts, IEs, EBI, LeftTunnel, Bearer, Context),
    Response = response(create_session_response, LeftTunnel, ResponseIEs, Request),
    gtp_context:send_response(ReqKey, Request, Response),

    case Verdict of
	ok ->
	    Actions = context_idle_action([], Context),
	    {next_state, State#{session := connected}, FinalData, Actions};
	_ ->
	    {next_state, State#{session := shutdown}, FinalData}
    end;

handle_request(ReqKey,
	       #gtp{type = modify_bearer_request,
		    ie = #{?'Bearer Contexts to be modified' :=
			       #v2_bearer_context{group = #{?'EPS Bearer ID' := EBI}}
			  } = IEs} = Request,
	       _Resent, #{session := connected} = _State,
	       #{context := Context, pfcp := PCtx0,
		 left_tunnel := LeftTunnelOld,
		 bearer := #{left := LeftBearerOld} = Bearer0,
		 aaa_session := S0, pcc := PCC} = Data) ->
    {LeftTunnel0, LeftBearer} =
	case update_tunnel_from_gtp_req(
	       Request, LeftTunnelOld#tunnel{version = v2}, LeftBearerOld) of
	    {ok, Result1} -> Result1;
	    {error, Err1} -> throw(Err1#ctx_err{context = Context, tunnel = LeftTunnelOld})
	end,
    Bearer = Bearer0#{left => LeftBearer},

    LeftTunnel = smf_gtp_gsn_lib:update_tunnel_endpoint(LeftTunnelOld, LeftTunnel0),
    {URRActions, S1} = pgw_s5s8:update_session_from_gtp_req(IEs, S0, LeftTunnel, LeftBearer),
    {PCtx, S2} =
	if LeftBearer /= LeftBearerOld ->
		case smf_gtp_gsn_lib:apply_bearer_change(
		       Bearer, URRActions, true, PCtx0, PCC) of
		    {ok, {RPCtx, SessionInfo}} ->
			{RPCtx, maps:merge(S1, SessionInfo)};
		    {error, Err2} -> throw(Err2#ctx_err{context = Context, tunnel = LeftTunnel})
		end;
	   true ->
		gtp_context:trigger_usage_report(self(), URRActions, PCtx0),
		{PCtx0, S1}
	end,

    ResponseIEs = [#v2_cause{v2_cause = request_accepted},
		    #v2_bearer_context{
		       group=[#v2_cause{v2_cause = request_accepted},
			      EBI]}],
    Response = response(modify_bearer_response, LeftTunnel, ResponseIEs, Request),
    gtp_context:send_response(ReqKey, Request, Response),

    DataNew = Data#{pfcp => PCtx, left_tunnel => LeftTunnel, bearer => Bearer, aaa_session => S2},
    Actions = context_idle_action([], Context),
    {keep_state, DataNew, Actions};

handle_request(ReqKey,
	       #gtp{type = modify_bearer_request, ie = IEs} = Request,
	       _Resent, #{session := connected} = _State,
	       #{context := Context, pfcp := PCtx,
		 left_tunnel := LeftTunnelOld, bearer := #{left := LeftBearerOld},
		 aaa_session := S0} = Data)
  when not is_map_key(?'Bearer Contexts to be modified', IEs) ->
    {LeftTunnel0, LeftBearer} =
	case update_tunnel_from_gtp_req(
	       Request, LeftTunnelOld#tunnel{version = v2}, LeftBearerOld) of
	    {ok, Result1} -> Result1;
	    {error, Err1} -> throw(Err1#ctx_err{context = Context, tunnel = LeftTunnelOld})
	end,

    LeftTunnel = smf_gtp_gsn_lib:update_tunnel_endpoint(LeftTunnelOld, LeftTunnel0),
    {URRActions, S1} = pgw_s5s8:update_session_from_gtp_req(IEs, S0, LeftTunnel, LeftBearer),
    gtp_context:trigger_usage_report(self(), URRActions, PCtx),

    DataNew =
	Data#{pfcp => PCtx, left_tunnel => LeftTunnel, aaa_session => S1},

    ResponseIEs = [#v2_cause{v2_cause = request_accepted}],
    Response = response(modify_bearer_response, LeftTunnel, ResponseIEs, Request),
    gtp_context:send_response(ReqKey, Request, Response),

    Actions = context_idle_action([], Context),
    {keep_state, DataNew, Actions};

handle_request(#request{src = Src, ip = IP, port = Port} = ReqKey,
	       #gtp{type = modify_bearer_command,
		    seq_no = SeqNo,
		    ie = #{?'APN-AMBR' := AMBR,
			   ?'Bearer Contexts to be modified' :=
			       #v2_bearer_context{
				  group = #{?'EPS Bearer ID' := EBI} = Bearer}} = IEs},
	       _Resent, #{session := connected},
	       #{context := Context, left_tunnel := LeftTunnel,
		 bearer := #{left := LeftBearer}, aaa_session := S0} = Data) ->
    OldSOpts = S0,
    {_URRActions, S1} = pgw_s5s8:update_session_from_gtp_req(IEs, S0, LeftTunnel, LeftBearer),

    Type = update_bearer_request,
    RequestIEs0 = [AMBR,
		   #v2_bearer_context{
		      group = copy_ies_to_response(Bearer, [EBI], [?'Bearer Level QoS'])}],
    RequestIEs = gtp_v2_c:build_recovery(Type, LeftTunnel, false, RequestIEs0),
    Msg = msg(LeftTunnel, Type, RequestIEs),
    send_request(
      LeftTunnel, Src, IP, Port, ?T3, ?N3, Msg#gtp{seq_no = SeqNo}, {ReqKey, OldSOpts}),

    Actions = context_idle_action([], Context),
    {keep_state, Data#{aaa_session => S1}, Actions};

handle_request(ReqKey,
	       #gtp{type = release_access_bearers_request} = Request,
	       _Resent, #{session := connected} = _State,
	       #{context := Context, pfcp := PCtx0,
		 left_tunnel := LeftTunnel,
		 bearer := #{left := LeftBearer0} = Bearer0,
		 pcc := PCC} = Data) ->
    LeftBearer = LeftBearer0#bearer{remote = undefined},
    Bearer = Bearer0#{left => LeftBearer},

    PCtx =
	case smf_gtp_gsn_lib:apply_bearer_change(Bearer, [], true, PCtx0, PCC) of
	    {ok, {RPCtx, _}} -> RPCtx;
	    {error, Err2} -> throw(Err2#ctx_err{context = Context, tunnel = LeftTunnel})
	end,

    ResponseIEs = [#v2_cause{v2_cause = request_accepted}],
    Response = response(release_access_bearers_response, LeftTunnel, ResponseIEs, Request),
    gtp_context:send_response(ReqKey, Request, Response),

    DataNew = Data#{context => Context, pfcp => PCtx, bearer => Bearer},
    Actions = context_idle_action([], Context),
    {keep_state, DataNew, Actions};

handle_request(ReqKey,
	       #gtp{type = delete_session_request, ie = IEs} = Request,
	       _Resent, #{session := connected} = State,
	       #{left_tunnel := LeftTunnel} = Data0) ->
    FqTEID = maps:get(?'Sender F-TEID for Control Plane', IEs, undefined),

    case match_tunnel(?'S11-C MME', LeftTunnel, FqTEID) of
	ok ->
	    Data = smf_gtp_gsn_lib:close_context(?API, normal, Data0),
	    Response = response(delete_session_response, LeftTunnel, request_accepted),
	    gtp_context:send_response(ReqKey, Request, Response),
	    {next_state, State#{session := shutdown}, Data};

	{error, ReplyIEs} ->
	    Response = response(delete_session_response, LeftTunnel, ReplyIEs),
	    gtp_context:send_response(ReqKey, Request, Response),
	    keep_state_and_data
    end;

handle_request(ReqKey, _Msg, _Resent, _State, _Data) ->
    gtp_context:request_finished(ReqKey),
    keep_state_and_data.

handle_response({CommandReqKey, OldSOpts},
		#gtp{type = update_bearer_response,
		     ie = #{?'Cause' := #v2_cause{v2_cause = Cause},
			    ?'Bearer Contexts to be modified' :=
				#v2_bearer_context{
				   group = #{?'Cause' := #v2_cause{v2_cause = BearerCause}}
				  }} = IEs},
		_Request, #{session := connected} = State,
		#{pfcp := PCtx, left_tunnel := LeftTunnel0, bearer := #{left := LeftBearer},
		  aaa_session := S0} = Data) ->
    gtp_context:request_finished(CommandReqKey),

    {ok, LeftTunnel} = gtp_path:bind_tunnel(LeftTunnel0),
    DataNew = Data#{left_tunnel => LeftTunnel},

    if Cause =:= request_accepted andalso BearerCause =:= request_accepted ->
	    {_URRActions, S1} = pgw_s5s8:update_session_from_gtp_req(IEs, S0, LeftTunnel, LeftBearer),
	    URRActions = gtp_context:collect_charging_events(OldSOpts, S1),
	    gtp_context:trigger_usage_report(self(), URRActions, PCtx),
	    {keep_state, DataNew#{aaa_session => S1}};
       true ->
	    ?LOG(error, "Update Bearer Request failed with ~p/~p",
			[Cause, BearerCause]),
	    delete_context(undefined, link_broken, State, DataNew)
    end;

handle_response({CommandReqKey, _}, timeout, #gtp{type = update_bearer_request},
		#{session := connected} = State, Data) ->
    ?LOG(error, "Update Bearer Request failed with timeout"),
    gtp_context:request_finished(CommandReqKey),
    delete_context(undefined, link_broken, State, Data);

handle_response({From, TermCause}, timeout, #gtp{type = delete_bearer_request},
		State, Data0) ->
    Data = smf_gtp_gsn_lib:close_context(?API, TermCause, Data0),
    if is_tuple(From) -> gen_statem:reply(From, {error, timeout});
       true -> ok
    end,
    {next_state, State#{session := shutdown}, Data};

handle_response({From, TermCause},
		#gtp{type = delete_bearer_response,
		     ie = #{?'Cause' := #v2_cause{v2_cause = Cause}}},
		_Request, State, #{left_tunnel := LeftTunnel0} = Data0) ->
    {ok, LeftTunnel} = gtp_path:bind_tunnel(LeftTunnel0),

    Data1 = Data0#{left_tunnel => LeftTunnel},

    Data = smf_gtp_gsn_lib:close_context(?API, TermCause, Data1),
    if is_tuple(From) -> gen_statem:reply(From, {ok, Cause});
       true -> ok
    end,
    {next_state, State#{session := shutdown}, Data};

handle_response(_CommandReqKey, _Response, _Request, #{session := SState}, _Data)
  when SState =/= connected ->
    keep_state_and_data.

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
match_tunnel(Type, #fq_teid{ip = RemoteCntlIP, teid = RemoteCntlTEI} = Expected,
	     #v2_fully_qualified_tunnel_endpoint_identifier{
		instance       = 0,
		interface_type = Type,
		key            = RemoteCntlTEI,
		ipv4           = RemoteCntlIP4,
		ipv6           = RemoteCntlIP6} = IE) ->
    case smf_inet:ip2bin(RemoteCntlIP) of
	RemoteCntlIP4 ->
	    ok;
	RemoteCntlIP6 ->
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

close_context(_Side, Reason, _Notify, _State, Data) ->
    smf_gtp_gsn_lib:close_context(?API, Reason, Data).

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
			      interface_type = ?'S1-U eNode-B',
			      key = TEI, ipv4 = IP4, ipv6 = IP6}, Next}, Tunnel, Bearer) ->
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
get_tunnel_from_req({?'Sender F-TEID for Control Plane',
		     #v2_fully_qualified_tunnel_endpoint_identifier{
			key = TEI, ipv4 = IP4, ipv6 = IP6}, Next},
		    Tunnel, Bearer) ->
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
	       #{left_tunnel := Tunnel} = Data) ->
    Type = delete_bearer_request,
    EBI = 5,
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

bearer_context(EBI, Bearer, Context, IEs) ->
    maps:fold(bearer_context(EBI, _, _, Context, _), IEs, Bearer).

bearer_context(EBI, left, Bearer, _Context, IEs) ->
    IE = #v2_bearer_context{
	    group=[#v2_cause{v2_cause = request_accepted},
		   EBI,
		   #v2_bearer_level_quality_of_service{
		      pl=15,
		      pvi=0,
		      label=9,maximum_bit_rate_for_uplink=0,
		      maximum_bit_rate_for_downlink=0,
		      guaranteed_bit_rate_for_uplink=0,
		      guaranteed_bit_rate_for_downlink=0},
		   %% F-TEID for S1-U SGW GTP-U ???
		   s1_sgw_gtp_u_tei(Bearer),
		   s5s8_pgw_gtp_u_tei(Bearer)]},
    [IE | IEs];
bearer_context(_, _, _, _, IEs) ->
    IEs.

fq_teid(Instance, Type, TEI, {_,_,_,_} = IP) ->
    #v2_fully_qualified_tunnel_endpoint_identifier{
       instance = Instance, interface_type = Type,
       key = TEI, ipv4 = smf_inet:ip2bin(IP)};
fq_teid(Instance, Type, TEI, {_,_,_,_,_,_,_,_} = IP) ->
    #v2_fully_qualified_tunnel_endpoint_identifier{
       instance = Instance, interface_type = Type,
       key = TEI, ipv6 = smf_inet:ip2bin(IP)}.

s11_sender_f_teid(#tunnel{local = #fq_teid{ip = IP, teid = TEI}}) ->
    fq_teid(0, ?'S11/S4-C SGW', TEI, IP).

s1_sgw_gtp_u_tei(#bearer{local = #fq_teid{ip = IP, teid = TEI}}) ->
    fq_teid(0, ?'S1-U SGW', TEI, IP).

s5s8_pgw_gtp_c_tei(#tunnel{local = #fq_teid{ip = IP, teid = TEI}}) ->
    %% PGW S5/S8/ S2a/S2b F-TEID for PMIP based interface
    %% or for GTP based Control Plane interface
    fq_teid(1, ?'S5/S8-C PGW', TEI, IP).

s5s8_pgw_gtp_u_tei(#bearer{local = #fq_teid{ip = IP, teid = TEI}}) ->
    %% S5/S8 F-TEI Instance
    fq_teid(2, ?'S5/S8-U PGW', TEI, IP).

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

change_reporting_actions(RequestIEs, IE0) ->
    Indications = gtp_v2_c:get_indication_flags(RequestIEs),
    Triggers = smf_charging:reporting_triggers(),

    CRSI = proplists:get_bool('CRSI', Indications),
    ENBCRSI = proplists:get_bool('ENBCRSI', Indications),
    _IE = change_reporting_action(CRSI, ENBCRSI, RequestIEs, Triggers, IE0).

create_session_response(Result, SessionOpts, RequestIEs, EBI,
			Tunnel, Bearer,
			#context{ms_ip = #ue_ip{v4 = MSv4, v6 = MSv6}} = Context) ->

    IE0 = bearer_context(EBI, Bearer, Context, []),
    IE1 = pdn_pco(SessionOpts, RequestIEs, IE0),
    IE2 = change_reporting_actions(RequestIEs, IE1),

    [Result,
     %% Sender F-TEID for Control Plane
     s11_sender_f_teid(Tunnel),
     s5s8_pgw_gtp_c_tei(Tunnel),
     #v2_apn_restriction{restriction_type_value = 0},
     encode_paa(MSv4, MSv6) | IE2].

%% Wrapper for gen_statem state_callback_result Actions argument
%% Timeout set in the context of a prolonged idle gtpv2 session
context_idle_action(Actions, #context{inactivity_timeout = Timeout})
  when is_integer(Timeout) orelse Timeout =:= infinity ->
    [{{timeout, context_idle}, Timeout, check_session_liveness} | Actions];
context_idle_action(Actions, _) ->
    Actions.
