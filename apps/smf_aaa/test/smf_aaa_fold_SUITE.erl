%% Copyright 2026, Next-NF

%% Tests for smf_aaa_gx:fold_cca/5 and smf_aaa_ro:fold_cca/5 — the async_m
%% counterpart of the blocking handle_cca fold done by await_response/5.

-module(smf_aaa_fold_SUITE).

-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").
-include("../include/smf_aaa_session.hrl").

all() ->
    [gx_install, gx_timeout, gy_update_credits, gy_timeout].

%%%===================================================================
%%% Gx (smf_aaa_gx)
%%%===================================================================

gx_install(_Config) ->
    {ok, Session0, [], State0} = smf_aaa_gx:invoke(gx, init, #{}, [], #{}, undefined),
    CCA = ['CCA' | #{'Result-Code' => [2001],
		      'Charging-Rule-Install' =>
			  [#{'Charging-Rule-Base-Name' => [<<"m2m0001">>]}]}],
    {ok, _Session1, Events, #pcf_ctx{}} =
	smf_aaa_gx:fold_cca(CCA, Session0, [], #{}, State0),
    {pcc, install, _} = lists:keyfind(pcc, 1, Events),
    ok.

gx_timeout(_Config) ->
    {ok, Session0, [], State0} = smf_aaa_gx:invoke(gx, init, #{}, [], #{}, undefined),
    {{error, timeout}, _Session1, _Events, #pcf_ctx{}} =
	smf_aaa_gx:fold_cca({error, timeout}, Session0, [], #{}, State0),
    ok.

%%%===================================================================
%%% Gy (smf_aaa_ro)
%%%===================================================================

gy_update_credits(_Config) ->
    {ok, Session0a, [], State0} = smf_aaa_ro:invoke(gy, init, #{}, [], #{}, undefined),
    Session0 = Session0a#{credits => #{1000 => empty}},
    CCA = ['CCA' | #{'Result-Code' => 2001,
		      'Multiple-Services-Credit-Control' =>
			  [#{'Rating-Group' => [1000],
			     'Granted-Service-Unit' => [#{'CC-Time' => [3600]}],
			     'Result-Code' => [2001]}]}],
    {ok, _Session1, Events, #charging_ctx{}} =
	smf_aaa_ro:fold_cca(CCA, Session0, [], #{}, State0),
    {update_credits, _} = lists:keyfind(update_credits, 1, Events),
    ok.

gy_timeout(_Config) ->
    {ok, Session0, [], State0} = smf_aaa_ro:invoke(gy, init, #{}, [], #{}, undefined),
    {{error, timeout}, _Session1, _Events, #charging_ctx{}} =
	smf_aaa_ro:fold_cca({error, timeout}, Session0, [], #{}, State0),
    ok.
