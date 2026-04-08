%% Copyright 2024, Next-NF

%% Online (Gy/Ro) and Offline (Rf) charging AAA interface.

-module(smf_aaa_charging).

-export([new/1,
	 gy_ccr_initial/4, gy_ccr_update/4, gy_ccr_terminate/4,
	 rf_initial/4, rf_update/4, rf_terminate/4,
	 terminate/3,
	 handle_reply/4]).

-include("include/smf_aaa_session.hrl").

%%===================================================================
%% API
%%===================================================================

new(AppId) ->
    #{procedures := Procedures} = smf_aaa:get_application(AppId),
    GySvc = lookup_service({gy, 'CCR-Initial'}, Procedures),
    RfSvc = lookup_service({rf, 'Initial'}, Procedures),
    GyHandler = handler_for(GySvc),
    RfHandler = handler_for(RfSvc),
    GyHState = init_handler(GyHandler, GySvc),
    RfHState = init_handler(RfHandler, RfSvc),
    #charging_ctx{gy_handler = GyHandler, gy_handler_state = GyHState, gy_service = GySvc,
		  rf_handler = RfHandler, rf_handler_state = RfHState, rf_service = RfSvc,
		  app_id = AppId}.

gy_ccr_initial(Ctx, Session, SOpts, Opts) ->
    invoke_gy(Ctx, Session, SOpts, 'CCR-Initial', Opts).

gy_ccr_update(Ctx, Session, SOpts, Opts) ->
    invoke_gy(Ctx, Session, SOpts, 'CCR-Update', Opts).

gy_ccr_terminate(Ctx, Session, SOpts, Opts) ->
    invoke_gy(Ctx, Session, SOpts, 'CCR-Terminate', Opts).

rf_initial(Ctx, Session, SOpts, Opts) ->
    invoke_rf(Ctx, Session, SOpts, 'Initial', Opts).

rf_update(Ctx, Session, SOpts, Opts) ->
    invoke_rf(Ctx, Session, SOpts, 'Update', Opts).

rf_terminate(Ctx, Session, SOpts, Opts) ->
    invoke_rf(Ctx, Session, SOpts, 'Terminate', Opts).

terminate(Ctx, Session, Opts) ->
    SOpts = #{'Termination-Cause' => error},
    {_, Ctx1, Session1, _} = invoke_gy(Ctx, Session, SOpts, terminate, Opts),
    {_, Ctx2, Session2, _} = invoke_rf(Ctx1, Session1, SOpts, terminate, Opts),
    {Ctx2, Session2}.

handle_reply(Promise, Msg, Session,
	     #charging_ctx{gy_handler = GyH, gy_handler_state = GyHS0,
			   rf_handler = RfH, rf_handler_state = RfHS0} = Ctx) ->
    %% dispatch to the right handler by checking which one has the pending promise
    case handler_has_pending(GyH, GyHS0, Promise) of
	true ->
	    {Session1, Events, GyHS1} =
		smf_aaa_session:handle_handler_reply(Promise, GyH, Msg, Session, GyHS0),
	    {Ctx#charging_ctx{gy_handler_state = GyHS1}, Session1, Events};
	false ->
	    {Session1, Events, RfHS1} =
		smf_aaa_session:handle_handler_reply(Promise, RfH, Msg, Session, RfHS0),
	    {Ctx#charging_ctx{rf_handler_state = RfHS1}, Session1, Events}
    end.

%%===================================================================
%% Internal
%%===================================================================

lookup_service(Procedure, Procedures) ->
    case maps:get(Procedure, Procedures, []) of
	[#{service := S} | _] -> S;
	_ -> undefined
    end.

handler_for(undefined) -> undefined;
handler_for(Service) ->
    maps:get(handler, smf_aaa:get_service(Service)).

init_handler(undefined, _) -> undefined;
init_handler(Handler, Service) ->
    {_, _, _, HState} = Handler:invoke(Service, init, #{}, [], #{}, undefined),
    HState.

handler_has_pending(Handler, State, Promise) ->
    try Handler:get_state_atom(State) of
	_ ->
	    %% check if this handler's state contains the promise
	    element(2, State) =:= Promise  %% #state.pending is element 2
    catch _:_ -> false
    end.

invoke_gy(#charging_ctx{gy_handler = undefined} = Ctx, Session, _SOpts, _Proc, _Opts) ->
    {ok, Ctx, Session, []};
invoke_gy(#charging_ctx{gy_handler = Handler, gy_handler_state = HState0,
			gy_service = Service} = Ctx,
	  Session0, SOpts, Procedure, Opts0) ->
    Opts = Opts0#{now => maps:get(now, Opts0, erlang:monotonic_time()),
		  handler_state => HState0},
    Session = smf_aaa_session:session_merge(Session0, SOpts),
    {Result, Session1, Events, HState1} =
	smf_aaa_session:invoke_handler(Handler, Service, {gy, Procedure}, Session, [], Opts),
    {Result, Ctx#charging_ctx{gy_handler_state = HState1}, Session1, Events}.

invoke_rf(#charging_ctx{rf_handler = undefined} = Ctx, Session, _SOpts, _Proc, _Opts) ->
    {ok, Ctx, Session, []};
invoke_rf(#charging_ctx{rf_handler = Handler, rf_handler_state = HState0,
			rf_service = Service} = Ctx,
	  Session0, SOpts, Procedure, Opts0) ->
    Opts = Opts0#{now => maps:get(now, Opts0, erlang:monotonic_time()),
		  handler_state => HState0},
    Session = smf_aaa_session:session_merge(Session0, SOpts),
    {Result, Session1, Events, HState1} =
	smf_aaa_session:invoke_handler(Handler, Service, {rf, Procedure}, Session, [], Opts),
    {Result, Ctx#charging_ctx{rf_handler_state = HState1}, Session1, Events}.
