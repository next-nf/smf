-module(async_m_SUITE).
-compile([export_all, nowarn_export_all]).
-compile({parse_transform, do}).   %% required: the tests use do([async_m || ...])
-include_lib("common_test/include/ct.hrl").

all() ->
    [return_wraps, bind_sequences, fail_short_circuits, bind_threads_state,
     accessors_read_write, await_captures_rest, lift_injects].

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

accessors_read_write(_Config) ->
    M = do([async_m || D  <- async_m:get_data(),
                       ok <- async_m:put_data(D + 1),
                       S  <- async_m:get_state(),
                       async_m:return({S, D})]),
    {{ok, {st, 10}}, st, 11} = async_m:run(M, st, 10),
    ok.

await_captures_rest(_Config) ->
    %% A FLAT do-block right-associates, so the await is enclosed by exactly
    %% one bind: Conts has length 1, and that single fun IS the rest of the block.
    M = do([async_m || R  <- async_m:await(req1),
                       R2 <- async_m:return(R + 1),
                       async_m:return(R2 + 1)]),
    {{await, req1, [Cont]}, st, dt} = async_m:run(M, st, dt),
    %% applying the captured continuation to a reply runs the remainder
    {{ok, 12}, st, dt} = async_m:run(Cont(10), st, dt),
    ok.

lift_injects(_Config) ->
    {{ok, 7}, st, dt}      = async_m:run(async_m:lift({ok, 7}), st, dt),
    {{ok, ok}, st, dt}     = async_m:run(async_m:lift(ok), st, dt),
    {{error, bad}, st, dt} = async_m:run(async_m:lift({error, bad}), st, dt),
    ok.
