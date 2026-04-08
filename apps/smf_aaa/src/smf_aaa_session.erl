%% Copyright 2016-2019, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(smf_aaa_session).

-compile({parse_transform, cut}).

%% Functional API (operates on #aaa_state{})
-export([new/1,
	 call/4,
	 handle_reply/4,
	 send_request/4,
	 aaa_reply/4,
	 get_session/1, set_session/2, merge_session/2,
	 get_handler/2, set_handler/3,
	 terminate_action/1]).

%% Session Object API
-export([to_session/1, native_to_seconds/1]).

%% Shared helpers for per-protocol modules
-export([new_session/1,
	 invoke_handler/6,
	 handle_handler_reply/5,
	 session_merge/2,
	 update_accounting_state/3,
	 prepare_next_session_id/1]).

%% Event helpers
-export([ev_add/2, ev_del/2, ev_set/2]).
-export([trigger/4, trigger/5]).

-include_lib("kernel/include/logger.hrl").
-include("include/smf_aaa_session.hrl").

-define(DEFAULT_INTERIM_ACCT, 600).
-define(DEFAULT_SERVICE_TYPE, 'Framed-User').
-define(DEFAULT_FRAMED_PROTO, 'PPP').

%%===================================================================
%% Event helpers
%%===================================================================

ev_add({K, Ev}, A) ->
    [{add, {K, Ev}}|A].
ev_del({K, Ev}, A) ->
    [{del, {K, Ev}}|A].
ev_set({K, Ev}, A) ->
    [{set, {K, Ev}}|A].

trigger(SubSys, Level, Type, Value) ->
    trigger(SubSys, Level, Type, Value, []).

trigger(SubSys, Level, Type, Value, Opts) ->
    {{SubSys, Level, Type}, {Type, Level, Value, Opts}}.

%%===================================================================
%% Functional API
%%===================================================================

new(SessionOpts) ->
    AppId = maps:get('AAA-Application-Id', SessionOpts, default),
    SessionId = smf_aaa_session_seq:inc(AppId),

    App = smf_aaa:get_application(AppId),
    OriginHost = maps:get('Origin-Host', App, net_adm:localhost()),
    DiamSessionId =
	iolist_to_binary(smf_aaa_session_seq:diameter_session_id(OriginHost, SessionId)),

    DefaultSessionOpts =
	#{'Session-Start'       => erlang:monotonic_time(),
	  'Session-Id'          => SessionId,
	  'Multi-Session-Id'    => SessionId,
	  'Diameter-Session-Id' => DiamSessionId
	 },

    smf_aaa_session_reg:register(SessionId),
    smf_aaa_session_reg:register(DiamSessionId),

    AAA0 = #aaa_state{
	       application = AppId,
	       handlers    = #{},
	       session     = DefaultSessionOpts
	      },
    {_Reply, AAA1, _Events} = call(AAA0, SessionOpts, init, #{}),
    AAA1.

call(#aaa_state{} = AAA0, SessionOpts, Procedure, Opts) when is_list(Opts) ->
    call(AAA0, SessionOpts, Procedure, normalize_opts(Opts));
call(#aaa_state{session = SessionIn} = AAA0, SessionOpts, Procedure, Opts0) when is_map(Opts0) ->
    Opts = Opts0#{now => maps:get(now, Opts0, erlang:monotonic_time())},
    Session0 = session_merge(SessionIn, SessionOpts),
    Session1 = maps:fold(fun handle_session_opts/3, Session0, Opts),
    Session2 = update_accounting_state(Procedure, Session1, Opts),
    action(Procedure, Opts, AAA0#aaa_state{session = Session2}).

handle_reply(Promise, Handler, Msg, #aaa_state{handlers = HandlersS, session = Session} = AAA) ->
    Opts = #{},
    State = maps:get(Handler, HandlersS, undefined),
    {_, SessOut, EvsOut, StateOut} =
	Handler:handle_response(Promise, Msg, Session, [], Opts, State),
    aaa_state_stats(Handler, State, StateOut),
    {AAA#aaa_state{handlers = maps:put(Handler, StateOut, HandlersS), session = SessOut}, EvsOut}.

%% send_request/4 — for protocol handlers (diameter/radius callbacks).
%% Sends #aaa_request{} to the GTP context (Owner) and blocks for reply.
send_request(Owner, Handler, Procedure, Avps) when is_pid(Owner) ->
    Ref = make_ref(),
    Request = #aaa_request{
		 from = {self(), Ref},
		 handler = Handler,
		 procedure = Procedure,
		 session = Avps,
		 events = []},
    Owner ! Request,
    receive
	{Ref, Reply} -> Reply
    after 10000 ->
	    {{error, timeout}, #{}}
    end;
send_request(_, _Handler, _Procedure, _Avps) ->
    {{error, unknown_session}, #{}}.

%% aaa_reply/4 — for gtp_context to reply to server-initiated requests.
aaa_reply(#aaa_request{from = {Pid, Ref}, handler = Handler},
	  Result, Avps, #aaa_state{session = Session}) ->
    ReplyAvps = Handler:from_session(Session, Avps),
    Pid ! {Ref, {Result, ReplyAvps}},
    ok;
aaa_reply(#aaa_request{from = Fun, handler = Handler} = Request, Result, Avps,
	  #aaa_state{session = Session}) when is_function(Fun, 4) ->
    ReplyAvps = case Handler of
		    undefined -> Avps;
		    _ -> Handler:from_session(Session, Avps)
		end,
    Fun(Request, Result, ReplyAvps, #{}),
    ok.

get_session(#aaa_state{session = Session}) -> Session.

set_session(Values, #aaa_state{session = Session} = AAA) when is_map(Values) ->
    AAA#aaa_state{session = maps:merge(Session, Values)}.

merge_session(SessionOpts, #aaa_state{session = Session} = AAA) ->
    AAA#aaa_state{session = session_merge(Session, SessionOpts)}.

get_handler(Handler, #aaa_state{handlers = Handlers}) ->
    maps:get(Handler, Handlers, undefined).

set_handler(Handler, State, #aaa_state{handlers = Handlers} = AAA) ->
    AAA#aaa_state{handlers = maps:put(Handler, State, Handlers)}.

terminate_action(#aaa_state{} = AAA) ->
    call(AAA, #{'Termination-Cause' => error}, terminate, #{}).

%%===================================================================
%% Shared helpers for per-protocol modules
%%===================================================================

%% Create a new session map with IDs and register in session registry.
%% Does NOT create handler state — that's done by each protocol module.
new_session(SessionOpts) ->
    AppId = maps:get('AAA-Application-Id', SessionOpts, default),
    SessionId = smf_aaa_session_seq:inc(AppId),

    App = smf_aaa:get_application(AppId),
    OriginHost = maps:get('Origin-Host', App, net_adm:localhost()),
    DiamSessionId =
	iolist_to_binary(smf_aaa_session_seq:diameter_session_id(OriginHost, SessionId)),

    DefaultSessionOpts =
	#{'Session-Start'       => erlang:monotonic_time(),
	  'Session-Id'          => SessionId,
	  'Multi-Session-Id'    => SessionId,
	  'Diameter-Session-Id' => DiamSessionId
	 },

    smf_aaa_session_reg:register(SessionId),
    smf_aaa_session_reg:register(DiamSessionId),

    maps:merge(DefaultSessionOpts, SessionOpts).

%% Invoke a single handler on a session. Used by per-protocol modules.
%% Returns {Result, Session1, Events, HandlerState1}.
invoke_handler(Handler, Service, Procedure, Session0, Events, Opts) ->
    Svc = smf_aaa:get_service(Service),
    StepOpts = maps:merge(Opts, Svc),
    State = maps:get(handler_state, Opts, undefined),
    SessionT = termination_cause_mapping(Session0, StepOpts),
    {Result, SessOut, EvsOut, StateOut} =
	Handler:invoke(Service, Procedure, SessionT, Events, StepOpts, State),
    aaa_state_stats(Handler, State, StateOut),
    {Result, SessOut, EvsOut, StateOut}.

%% Handle an async reply for a single handler. Used by per-protocol modules.
%% Returns {Session1, Events, HandlerState1}.
handle_handler_reply(Promise, Handler, Msg, Session, HandlerState) ->
    Opts = #{},
    {_, SessOut, EvsOut, StateOut} =
	Handler:handle_response(Promise, Msg, Session, [], Opts, HandlerState),
    aaa_state_stats(Handler, HandlerState, StateOut),
    {SessOut, EvsOut, StateOut}.

%%===================================================================
%% Session Object API
%%===================================================================

to_session(Session) when is_list(Session) ->
    maps:from_list(Session);
to_session(Session) when is_map(Session) ->
    Session.

native_to_seconds(Native) ->
    round(Native / erlang:convert_time_unit(1, second, native)).

%%===================================================================
%% Internal helpers
%%===================================================================

prepare_next_session_id(Session) ->
    AcctAppId = maps:get('AAA-Application-Id', Session, default),
    NewSessionId = smf_aaa_session_seq:inc(AcctAppId),
    smf_aaa_session_reg:register(NewSessionId),
    Session#{'Session-Id' => NewSessionId}.

maps_merge_with(K, Fun, V, Map) ->
    maps:update_with(K, maps:fold(Fun, V, _), V, Map).

monitor_merge(K, V, M)
  when is_map(V) ->
    maps_merge_with(K, fun monitor_merge/3, V, M);
monitor_merge(K, V, Values)
  when is_integer(V) ->
    maps:update_with(K, (_ + V), V, Values).

session_merge(monitors = K, V, Session) ->
    monitor_merge(K, V, Session);
session_merge(K, V, Session) ->
    Session#{K => V}.

session_merge(Session, Opts) ->
    maps:fold(fun session_merge/3, Session, Opts).

normalize_opts(Opts) when is_list(Opts) ->
    maps:from_list(proplists:unfold(Opts));
normalize_opts(Opts) when is_map(Opts) ->
    Opts.

handle_session_opts(inc_session_id, true, Session) ->
    prepare_next_session_id(Session);
handle_session_opts(_K, _V, Session) ->
    Session.

accounting_start(#{'Accounting-Start' := Start}) ->
    Start;
accounting_start(#{'Session-Start' := Start}) ->
    Start.

update_accounting_state(start, Session, #{now := Now}) ->
    Session#{'Accounting-Start' => Now};
update_accounting_state(interim, Session, #{now := Now}) ->
    Start = accounting_start(Session),
    Session#{'Acct-Session-Time' => native_to_seconds(Now - Start),
	     'Last-Interim-Update' => Now};
update_accounting_state(stop, Session, #{now := Now}) ->
    Start = accounting_start(Session),
    Session#{'Acct-Session-Time' => native_to_seconds(Now - Start),
	     'Accounting-Stop' => Now};
update_accounting_state(_Procedure, Session, _Opts) ->
    Session.

services(Procedure, App)
  when Procedure =:= init;
       Procedure =:= terminate ->
    Procedures =
	maps:fold(
	  fun(_, Svcs, S0) ->
		  lists:foldl(fun(#{service := Svc}, S1) -> S1#{Svc => #{service => Svc}} end, S0, Svcs)
	  end, #{}, maps:remove(Procedure, App)),
    Session = maps:get(Procedure, App, []),
    Keys = lists:foldl(fun(#{service := Svc}, Acc) -> [Svc | Acc] end, [], Session),
    maps:fold(
      fun(_, #{service := Svc} = V, S) ->
	      [maps:merge(smf_aaa:get_service(Svc), V) | S]
      end, Session, maps:without(Keys, Procedures));
services(Procedure, App) ->
    maps:get(Procedure, App, []).

action(Procedure, Opts, #aaa_state{application = AppId} = AAA) ->
    #{procedures := Procedures} = smf_aaa:get_application(AppId),
    Pipeline = services(Procedure, Procedures),
    pipeline(Procedure, AAA, [], Opts, Pipeline).

pipeline(_, AAA, Events, _Opts, []) ->
    {ok, AAA, Events};
pipeline(Procedure, AAAIn, EventsIn, Opts, [Head|Tail]) ->
    case step(Head, Procedure, AAAIn, EventsIn, Opts) of
	{ok, AAAOut, EventsOut} ->
	    pipeline(Procedure, AAAOut, EventsOut, Opts, Tail);
	Other ->
	    Other
    end.

step(#{service := Service} = SvcOpts, Procedure,
     #aaa_state{handlers = HandlersS, session = Session0} = AAA, Events, Opts) ->
    Svc = smf_aaa:get_service(Service),
    StepOpts = maps:merge(Opts, SvcOpts),
    Handler = maps:get(handler, Svc),
    Session = termination_cause_mapping(Session0, StepOpts),
    State = maps:get(Handler, HandlersS, undefined),
    {Result, SessOut, EvsOut, StateOut} =
	Handler:invoke(Service, Procedure, Session, Events, StepOpts, State),
    aaa_state_stats(Handler, State, StateOut),
    {Result, AAA#aaa_state{handlers = maps:put(Handler, StateOut, HandlersS),
			   session = SessOut}, EvsOut}.

aaa_state_stats_dec(_, From)
    when From =:= undefined; From =:= stopped ->
	ok;
aaa_state_stats_dec(Handler, From) ->
    prometheus_gauge:dec(aaa_sessions_total, [Handler, From]).

aaa_state_stats_inc(_, To)
    when To =:= undefined; To =:= stopped ->
	ok;
aaa_state_stats_inc(Handler, To) ->
    prometheus_gauge:inc(aaa_sessions_total, [Handler, To]).

aaa_state_stats(Handler, CurrentState, NewState) ->
    From = get_handler_state(Handler, CurrentState),
    To = get_handler_state(Handler, NewState),
    if From /= To ->
	    aaa_state_stats_dec(Handler, From),
	    aaa_state_stats_inc(Handler, To);
       From == To ->
	       ok
    end.

get_handler_state(_, undefined) ->
    undefined;
get_handler_state(Handler, State) ->
    Handler:get_state_atom(State).

termination_cause_mapping(#{'Termination-Cause' := Cause} = Session, #{termination_cause_mapping := Config})
  when is_atom(Cause), is_map_key(Cause, Config) ->
    Session#{'Termination-Cause' := maps:get(Cause, Config)};
termination_cause_mapping(#{'Termination-Cause' := Cause} = Session, _)
  when is_integer(Cause) andalso Cause > 0 ->
    Session#{'Termination-Cause' := Cause};
termination_cause_mapping(#{'Termination-Cause' := Cause} = Session, #{termination_cause_mapping := Config}) ->
    ?LOG(notice, "Termination cause ~p not present in the mapping table, mapping to error", [Cause]),
    Session#{'Termination-Cause' := maps:get(error, Config)};
termination_cause_mapping(Session, _) ->
    Session.
