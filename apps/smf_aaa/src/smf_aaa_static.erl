%% Copyright 2016-2019 Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(smf_aaa_static).

-behaviour(smf_aaa).

%% AAA API
-export([validate_handler/1, validate_service/3, validate_procedure/5,
	 initialize_handler/1, initialize_service/2, invoke/6, handle_response/6]).

%% async_m mock API
-export([ccr_initial_issue/3, ccr_update_issue/3]).

-export([get_state_atom/1]).
-ignore_xref([get_state_atom/1]).

-import(smf_aaa_session, [to_session/1]).

-include_lib("kernel/include/logger.hrl").
-include_lib("diameter/include/diameter.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").

-define(OptKeys, [answer, answers]).

%%===================================================================
%% API
%%===================================================================

initialize_handler(_Opts) ->
    {ok, []}.

initialize_service(_ServiceId, _Opts) ->
    {ok, []}.

validate_handler(Opts) ->
    smf_aaa_config:validate_options(fun validate_option/2, Opts, []).

validate_service(_Service, HandlerOpts, Opts) ->
    smf_aaa_config:validate_options(fun validate_option/2, Opts, HandlerOpts).

validate_procedure(_Application, _Procedure, _Service, ServiceOpts, Opts) ->
    smf_aaa_config:validate_options(fun validate_option/2, Opts, ServiceOpts).

invoke(_Service, Procedure, Session, Events, #{answers := Answers, answer := Answer}, State) ->
    AVPs =
	case Answers of
	    #{Answer := #{avps := A}} -> A;
	    _ -> #{}
	end,
    handle_response(Procedure, AVPs, Session, Events, State);
invoke(_Service, _Procedure, Session, Events, Opts, State) ->
    SOpts = maps:get(defaults, Opts, #{}),
    {ok, maps:merge(Session, SOpts), Events, State}.

%% handle_response/6
handle_response(_Promise, _Msg, Session, Events, _Opts, State) ->
    {ok, Session, Events, State}.

%% ccr_initial_issue/3 — async_m mock counterpart of invoke/6: resolves the
%% canned answer exactly as invoke/6 does, but instead of processing it
%% inline, hands back a Promise and delivers the raw CCA to Owner
%% (self() at call time), the same way a real Gx handler's issue/3 would.
-spec ccr_initial_issue(map(), map(), term()) -> {reference(), map(), term()}.
ccr_initial_issue(Session, Opts, State) ->
    issue(Session, Opts, State).

%% ccr_update_issue/3 — see ccr_initial_issue/3.
-spec ccr_update_issue(map(), map(), term()) -> {reference(), map(), term()}.
ccr_update_issue(Session, Opts, State) ->
    issue(Session, Opts, State).

%% issue/3 — shared by ccr_initial_issue/3 and ccr_update_issue/3: resolve
%% the canned answer's AVP map exactly as invoke/6 does (#{answers :=
%% Answers, answer := Answer}), shape it as a raw ['CCA' | Avps] matching
%% smf_aaa_gx:handle_cca/5's pattern, and deliver it to Owner.
issue(Session, #{answers := Answers, answer := Answer} = Opts, State) ->
    AVPs =
	case Answers of
	    #{Answer := #{avps := A}} -> A;
	    _ -> #{}
	end,
    Promise = make_ref(),
    Owner = self(),
    Owner ! {'$reply', Promise, smf_aaa_gx, ['CCA' | to_raw_cca_avps(AVPs)], Opts},
    {Promise, Session, State}.

%% to_raw_cca_avps/1 — shape a canned answer's AVP map as the raw CCA AVPs
%% smf_aaa_gx:handle_cca/5 pattern-matches: 'Result-Code' list-wrapped
%% ([RC]); everything else (including repeated AVPs like
%% Charging-Rule-Install/-Remove) passes through unchanged, since the
%% static config already list-wraps those.
to_raw_cca_avps(#{'Result-Code' := RC} = AVPs) when is_integer(RC) ->
    AVPs#{'Result-Code' => [RC]};
to_raw_cca_avps(AVPs) ->
    AVPs.

%%%===================================================================
%%% Options Validation
%%%===================================================================

-define(is_opts(X), (is_list(X) orelse is_map(X))).

validate_option(handler, Value) ->
    Value;
validate_option(service, Value) ->
    Value;
validate_option(answers, Value) when is_map(Value) ->
    smf_aaa_config:validate_answers(Value);
validate_option(answer, Value) ->
    Value;
validate_option(defaults, Opts) when ?is_opts(Opts) ->
    smf_aaa_config:validate_options(fun validate_session_default/2, Opts, []);
validate_option(Opt, Value) ->
    erlang:error(badarg, [Opt, Value]).

validate_session_default(Opt, Value) when is_atom(Opt) ->
    Value;
validate_session_default(Opt, Value) ->
    erlang:error(badarg, [Opt, Value]).

%%===================================================================
%% internal helpers
%%===================================================================

%% to_session/3
to_session({rf, _} = Procedure, SessEvs, Avps) ->
    smf_aaa_rf:to_session(Procedure, SessEvs, Avps);
to_session({gx, _} = Procedure, SessEvs, Avps) ->
    smf_aaa_gx:to_session(Procedure, SessEvs, Avps);
to_session({gy, _} = Procedure, SessEvs, Avps) ->
    smf_aaa_ro:to_session(Procedure, SessEvs, Avps);
to_session(Procedure, SessEvs, #{handler := Handler} = Avps) ->
    Handler:to_session(Procedure, SessEvs, maps:remove(handler, Avps));
to_session(_Procedure, {Session, Events}, Avps) ->
    {maps:merge(Session, Avps), Events}.

handle_response(Procedure, #{'Result-Code' := Code} = Avps,
		Session0, Events0, State)
  when Code < 3000 ->
    {Session, Events} = to_session(Procedure, {Session0, Events0}, Avps),
    {ok, Session, Events, State};
handle_response({API, _}, #{'Result-Code' := Code}, Session, Events, State) ->
    {{fail, Code}, Session, [{stop, {API, peer_reject}} | Events], State};
handle_response(Procedure, #{'Result-Code' := Code}, Session, Events, State) ->
    {{fail, Code}, Session, [{stop, {Procedure, peer_reject}} | Events], State};
handle_response(_Procedure, Response, Session, Events, State) ->
    ?LOG(alert, "unexpected Diameter response, something important might have been missed: ~p",
         [Response]),
    {Response, Session, Events, State}.

get_state_atom(_) ->
    stopped.
