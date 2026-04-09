%% Copyright 2024, Next-NF

%% Policy Control Function (Gx) AAA interface.

-module(smf_aaa_pcf).

-export([new/2,
	 ccr_initial/4, ccr_update/4, ccr_terminate/4,
	 terminate/3,
	 handle_reply/4]).
-ignore_xref([terminate/3]).

-include("include/smf_aaa_session.hrl").

%%===================================================================
%% API
%%===================================================================

new(AppId, Session) ->
    Ctx = #pcf_ctx{app_id = AppId, handlers = #{}},
    case invoke(Ctx, Session, #{}, init, #{}) of
	{ok, Ctx1, Session1, _} -> {Ctx1, Session1};
	{_, Ctx1, Session1, _} -> {Ctx1, Session1}
    end.

ccr_initial(Ctx, Session, SOpts, Opts) ->
    invoke(Ctx, Session, SOpts, {gx, 'CCR-Initial'}, Opts).

ccr_update(Ctx, Session, SOpts, Opts) ->
    invoke(Ctx, Session, SOpts, {gx, 'CCR-Update'}, Opts).

ccr_terminate(Ctx, Session, SOpts, Opts) ->
    invoke(Ctx, Session, SOpts, {gx, 'CCR-Terminate'}, Opts).

terminate(Ctx, Session, Opts) ->
    invoke(Ctx, Session, #{'Termination-Cause' => error}, terminate, Opts).

handle_reply(Promise, Msg, Session,
	     #pcf_ctx{handlers = Handlers0} = Ctx) ->
    %% find which handler has this promise
    {Handler, HState0} = find_pending_handler(Promise, Handlers0),
    {Session1, Events, HState1} =
	smf_aaa_session:handle_handler_reply(Promise, Handler, Msg, Session, HState0),
    {Ctx#pcf_ctx{handlers = maps:put(Handler, HState1, Handlers0)}, Session1, Events}.

%%===================================================================
%% Internal
%%===================================================================

invoke(#pcf_ctx{app_id = AppId, handlers = Handlers0} = Ctx,
       Session0, SOpts, Procedure, Opts0) ->
    Opts = Opts0#{now => maps:get(now, Opts0, erlang:monotonic_time())},
    Session1 = smf_aaa_session:session_merge(Session0, SOpts),
    #{procedures := Procedures} = smf_aaa:get_application(AppId),
    Pipeline = smf_aaa_session:get_services(Procedure, Procedures),
    case run_pipeline(Procedure, Pipeline, Session1, [], Opts, Handlers0) of
	{ok, Session2, Events, Handlers1} ->
	    {ok, Ctx#pcf_ctx{handlers = Handlers1}, Session2, Events};
	{Result, Session2, Events, Handlers1} ->
	    {Result, Ctx#pcf_ctx{handlers = Handlers1}, Session2, Events}
    end.

run_pipeline(_Procedure, [], Session, Events, _Opts, Handlers) ->
    {ok, Session, Events, Handlers};
run_pipeline(Procedure, [#{service := Service} = SvcOpts | Tail], Session0, Events0, Opts, Handlers0) ->
    Svc = smf_aaa:get_service(Service),
    StepOpts = maps:merge(Opts, maps:merge(Svc, SvcOpts)),
    Handler = maps:get(handler, Svc),
    HState0 = maps:get(Handler, Handlers0, undefined),
    {Result, Session1, Events1, HState1} =
	smf_aaa_session:invoke_handler(Handler, Service, Procedure, Session0, Events0,
				       StepOpts#{handler_state => HState0}),
    Handlers1 = maps:put(Handler, HState1, Handlers0),
    case Result of
	ok -> run_pipeline(Procedure, Tail, Session1, Events1, Opts, Handlers1);
	_ -> {Result, Session1, Events1, Handlers1}
    end.

find_pending_handler(Promise, Handlers) ->
    maps:fold(
      fun(H, S, undefined) ->
	      try element(2, S) of
		  Promise -> {H, S};
		  _ -> undefined
	      catch _:_ -> undefined
	      end;
	 (_, _, Found) -> Found
      end, undefined, Handlers).
