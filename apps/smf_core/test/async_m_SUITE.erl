-module(async_m_SUITE).
-compile([export_all, nowarn_export_all]).
-compile({parse_transform, do}).   %% required: the tests use do([async_m || ...])
-include_lib("common_test/include/ct.hrl").

all() ->
    [return_wraps, bind_sequences, fail_short_circuits, bind_threads_state].

%% run a do-block against a trivial (State, Data) = (st, dt)
return_wraps(_Config) ->
    M = async_m:return(41),
    {{ok, 41}, st, dt} = async_m:run(M, st, dt),
    ok.

bind_sequences(_Config) ->
    M = do([async_m || X <- async_m:return(20),
                        Y <- async_m:return(22),
                        async_m:return(X + Y)]),
    {{ok, 42}, st, dt} = async_m:run(M, st, dt),
    ok.

fail_short_circuits(_Config) ->
    M = do([async_m || _ <- async_m:fail(boom),
                        async_m:return(unreachable)]),
    {{error, boom}, st, dt} = async_m:run(M, st, dt),
    ok.

bind_threads_state(_Config) ->
    %% get_data/put_data defined in Task 2; here just prove run passes State/Data through
    M = async_m:return(ok),
    {{ok, ok}, s1, d1} = async_m:run(M, s1, d1),
    ok.
