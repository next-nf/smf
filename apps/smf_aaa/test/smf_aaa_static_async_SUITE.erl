-module(smf_aaa_static_async_SUITE).
-compile([export_all, nowarn_export_all]).
-include_lib("common_test/include/ct.hrl").

all() -> [ccr_update_async_loop].

ccr_update_async_loop(_Config) ->
    %% a canned CCR-U answer that removes a rule (the Charging-Rule-Remove shape fold_cca turns into
    %% a {pcc, remove, _} event). Build Opts/Session/State the way smf_aaa_pcf:issue/5 hands them to
    %% the handler (read smf_aaa_static:invoke/6 + smf_aaa_pcf:issue/5 for the exact shapes).
    {Session0, State0, Opts} = setup_ccru_remove(),
    {Promise, _Session1, _State1} = smf_aaa_static:ccr_update_issue(Session0, Opts, State0),
    RawCCA = receive
                 {'$reply', Promise, _Handler, Msg, _Opts} -> Msg
             after 2000 -> ct:fail(no_reply)
             end,
    %% the delivered Msg is a raw ['CCA' | AVPs] that fold_cca consumes.
    %% fold_cca/5 -> {Result, Session1, Events1, Ctx1} (see smf_aaa_gx.erl);
    %% the brief's skeleton had Events/Ctx swapped, fixed here to match.
    {ok, _Session2, Events, _Ctx} = smf_aaa_gx:fold_cca(RawCCA, Session0, [], Opts, State0),
    true = lists:any(fun({pcc, remove, _}) -> true; (_) -> false end, Events),
    ok.

%% setup_ccru_remove/0 — build the {Session0, State0, Opts} triple the way
%% smf_aaa_pcf:issue/5 hands them to Handler:ccr_update_issue/3:
%%   Session1 = the (merged) session map
%%   StepOpts = Opts, including the canned #{answers, answer} that
%%              smf_aaa_static:invoke/6 (and now issue/3) reads
%%   HState0  = maps:get(Handler, Handlers0, undefined) — the mock has no
%%              internal state of its own, so `undefined` is exactly what
%%              a real pcf_ctx with no handler state yet would hand over.
setup_ccru_remove() ->
    Session0 = #{},
    State0 = undefined,
    Answers =
        #{'Update-Gx-Remove' =>
              #{avps =>
                    #{'Result-Code' => 2001,
                      'Charging-Rule-Remove' =>
                          [#{'Charging-Rule-Name' => [<<"m2m">>]}]
                     }}},
    Opts = #{answers => Answers, answer => 'Update-Gx-Remove'},
    {Session0, State0, Opts}.
