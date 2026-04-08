%% Copyright 2024, Next-NF

%% Policy Control Function (Gx) AAA interface.

-module(smf_aaa_pcf).

-export([new/1,
	 ccr_initial/4, ccr_update/4, ccr_terminate/4,
	 terminate/3,
	 handle_reply/4]).

-include("include/smf_aaa_session.hrl").

%%===================================================================
%% API
%%===================================================================

new(AppId) ->
    #{procedures := Procedures} = smf_aaa:get_application(AppId),
    Service = case maps:get({gx, 'CCR-Initial'}, Procedures, []) of
		  [#{service := S} | _] -> S;
		  _ -> undefined
	      end,
    Handler = case Service of
		  undefined -> undefined;
		  _ -> maps:get(handler, smf_aaa:get_service(Service))
	      end,
    %% run init for the handler
    {_, _, _, HState} =
	case Handler of
	    undefined -> {ok, #{}, [], undefined};
	    _ -> Handler:invoke(Service, init, #{}, [], #{}, undefined)
	end,
    #pcf_ctx{handler = Handler, handler_state = HState,
	     service = Service, app_id = AppId}.

ccr_initial(PCF, Session, SOpts, Opts) ->
    invoke(PCF, Session, SOpts, 'CCR-Initial', Opts).

ccr_update(PCF, Session, SOpts, Opts) ->
    invoke(PCF, Session, SOpts, 'CCR-Update', Opts).

ccr_terminate(PCF, Session, SOpts, Opts) ->
    invoke(PCF, Session, SOpts, 'CCR-Terminate', Opts).

terminate(PCF, Session, Opts) ->
    invoke(PCF, Session, #{'Termination-Cause' => error}, terminate, Opts).

handle_reply(Promise, Msg, Session,
	     #pcf_ctx{handler = Handler, handler_state = HState0} = PCF) ->
    {Session1, Events, HState1} =
	smf_aaa_session:handle_handler_reply(Promise, Handler, Msg, Session, HState0),
    {PCF#pcf_ctx{handler_state = HState1}, Session1, Events}.

%%===================================================================
%% Internal
%%===================================================================

invoke(#pcf_ctx{handler = undefined}, Session, _SOpts, _Procedure, _Opts) ->
    {ok, Session, []};
invoke(#pcf_ctx{handler = Handler, handler_state = HState0,
		service = Service} = PCF,
       Session0, SOpts, Procedure, Opts0) ->
    Opts = Opts0#{now => maps:get(now, Opts0, erlang:monotonic_time()),
		  handler_state => HState0},
    Session = smf_aaa_session:session_merge(Session0, SOpts),
    {Result, Session1, Events, HState1} =
	smf_aaa_session:invoke_handler(Handler, Service, {gx, Procedure}, Session, [], Opts),
    {Result, PCF#pcf_ctx{handler_state = HState1}, Session1, Events}.
