%% Copyright 2024, Next-NF

%% NASREQ/RADIUS authentication and accounting AAA interface.

-module(smf_aaa_auth).

-export([new/1,
	 authenticate/4, authorize/4,
	 start/4, interim/4, stop/4,
	 terminate/3,
	 handle_reply/4]).

-include("include/smf_aaa_session.hrl").

%%===================================================================
%% API
%%===================================================================

new(AppId) ->
    #{procedures := Procedures} = smf_aaa:get_application(AppId),
    Service = case maps:get(authenticate, Procedures, []) of
		  [#{service := S} | _] -> S;
		  _ ->
		      %% try start procedure for accounting-only
		      case maps:get(start, Procedures, []) of
			  [#{service := S2} | _] -> S2;
			  _ -> undefined
		      end
	      end,
    Handler = case Service of
		  undefined -> undefined;
		  _ -> maps:get(handler, smf_aaa:get_service(Service))
	      end,
    HState = case Handler of
		 undefined -> undefined;
		 _ ->
		     {_, _, _, HS} = Handler:invoke(Service, init, #{}, [], #{}, undefined),
		     HS
	     end,
    #aaa_auth_ctx{handler = Handler, handler_state = HState,
		  service = Service, app_id = AppId}.

authenticate(Ctx, Session0, SOpts, Opts) ->
    Session = smf_aaa_session:prepare_next_session_id(Session0),
    invoke(Ctx, Session, SOpts, authenticate, Opts).

authorize(Ctx, Session, SOpts, Opts) ->
    invoke(Ctx, Session, SOpts, authorize, Opts).

start(Ctx, Session0, SOpts, Opts) ->
    Session = smf_aaa_session:update_accounting_state(start, Session0, Opts),
    invoke(Ctx, Session, SOpts, start, Opts).

interim(Ctx, Session0, SOpts, Opts) ->
    Session = smf_aaa_session:update_accounting_state(interim, Session0, Opts),
    invoke(Ctx, Session, SOpts, interim, Opts).

stop(Ctx, Session0, SOpts, Opts) ->
    Session = smf_aaa_session:update_accounting_state(stop, Session0, Opts),
    invoke(Ctx, Session, SOpts, stop, Opts).

terminate(Ctx, Session, Opts) ->
    invoke(Ctx, Session, #{'Termination-Cause' => error}, terminate, Opts).

handle_reply(Promise, Msg, Session,
	     #aaa_auth_ctx{handler = Handler, handler_state = HState0} = Ctx) ->
    {Session1, Events, HState1} =
	smf_aaa_session:handle_handler_reply(Promise, Handler, Msg, Session, HState0),
    {Ctx#aaa_auth_ctx{handler_state = HState1}, Session1, Events}.

%%===================================================================
%% Internal
%%===================================================================

invoke(#aaa_auth_ctx{handler = undefined}, Session, _SOpts, _Procedure, _Opts) ->
    {ok, Session, []};
invoke(#aaa_auth_ctx{handler = Handler, handler_state = HState0,
		     service = Service} = Ctx,
       Session0, SOpts, Procedure, Opts0) ->
    Opts = Opts0#{now => maps:get(now, Opts0, erlang:monotonic_time()),
		  handler_state => HState0},
    Session = smf_aaa_session:session_merge(Session0, SOpts),
    {Result, Session1, Events, HState1} =
	smf_aaa_session:invoke_handler(Handler, Service, Procedure, Session, [], Opts),
    {Result, Ctx#aaa_auth_ctx{handler_state = HState1}, Session1, Events}.
