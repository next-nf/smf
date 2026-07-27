%% Whole-pipeline async invoke loop: smf_aaa_pcf:invoke(#{pipeline_async => true})
%% spawns a worker that runs the ENTIRE handler pipeline and posts the
%% ctx-wrapped, fully-folded result back as {'$async_reply', ReqId, _} — the
%% same message contract gtp_context routes into async_m. This suite drives
%% that loop against the smf_aaa_static mock and asserts the worker ran the
%% whole pipeline (mock invoke/6 -> fold), not just the first step.
-module(smf_aaa_pcf_async_SUITE).

-compile([nowarn_export_all, export_all]).

-include_lib("common_test/include/ct.hrl").
-include("../include/smf_aaa_session.hrl").

-define(APP, default).

%% Minimal smf_aaa config: the static mock only, a CCR-Update that removes a
%% rule (smf_aaa_gx:to_session turns the Charging-Rule-Remove into a
%% {pcc, remove, _} event during the fold).
-define(CONFIG,
	#{handlers =>
	      #{smf_aaa_static => #{}},
	  services =>
	      #{<<"Default">> =>
		    #{handler => smf_aaa_static,
		      answers =>
			  #{'Update-Gx-Remove' =>
				#{avps =>
				      #{'Result-Code' => 2001,
					'Charging-Rule-Remove' =>
					    [#{'Charging-Rule-Name' => [<<"m2m">>]}]
				       }}}}},
	  apps =>
	      #{?APP =>
		    #{procedures =>
			  #{init => [#{service => <<"Default">>}],
			    {gx, 'CCR-Update'} =>
				[#{service => <<"Default">>, answer => 'Update-Gx-Remove'}]}}}
	 }).

all() ->
    [ccr_update_whole_pipeline_async, ccr_update_sync_unchanged].

init_per_suite(Config) ->
    application:load(smf_aaa),
    smf_aaa_test_lib:clear_app_env(),
    {ok, _} = application:ensure_all_started(smf_aaa),
    smf_aaa_test_lib:smf_aaa_init(?CONFIG),
    Config.

end_per_suite(_Config) ->
    application:stop(smf_aaa),
    application:unload(smf_aaa),
    ok.

%% The whole-pipeline-async loop: invoke(async) returns {async, ReqId}, the
%% worker posts {'$async_reply', ReqId, {Result, Ctx1, Session1, Events}} with
%% the FULLY FOLDED pipeline output (proves the worker ran mock invoke/6 -> fold,
%% not just a first pre-send step).
ccr_update_whole_pipeline_async(_Config) ->
    {Ctx0, Session0} = smf_aaa_pcf:new(?APP, #{}),
    {async, ReqId} =
	smf_aaa_pcf:invoke(Ctx0, Session0, #{}, {gx, 'CCR-Update'}, #{pipeline_async => true}),
    true = is_reference(ReqId),
    {Result, Ctx1, Session1, Events} =
	receive
	    {'$async_reply', RId, R} when RId =:= ReqId -> R;
	    {{'$async_down', RId}, _MRef, process, _Pid, Reason} when RId =:= ReqId ->
		ct:fail({worker_down, Reason})
	after 2000 ->
		ct:fail(no_async_reply)
	end,
    ok = Result,
    true = is_record(Ctx1, pcf_ctx),
    true = is_map(Session1),
    true = lists:any(fun({pcc, remove, _}) -> true; (_) -> false end, Events),
    ok.

%% Same procedure without async => the classic sync tuple, unchanged.
ccr_update_sync_unchanged(_Config) ->
    {Ctx0, Session0} = smf_aaa_pcf:new(?APP, #{}),
    {Result, Ctx1, _Session1, Events} =
	smf_aaa_pcf:invoke(Ctx0, Session0, #{}, {gx, 'CCR-Update'}, #{}),
    ok = Result,
    true = is_record(Ctx1, pcf_ctx),
    true = lists:any(fun({pcc, remove, _}) -> true; (_) -> false end, Events),
    ok.
