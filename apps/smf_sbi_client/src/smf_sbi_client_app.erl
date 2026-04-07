%%%-------------------------------------------------------------------
%% @doc smf_sbi_client public API
%% @end
%%%-------------------------------------------------------------------

-module(smf_sbi_client_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    smf_sbi_client_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
