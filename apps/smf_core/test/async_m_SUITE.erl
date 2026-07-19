-module(async_m_SUITE).
-compile([export_all, nowarn_export_all]).
-compile({parse_transform, do}).   %% required: the tests use do([async_m || ...])
-include_lib("common_test/include/ct.hrl").

all() ->
    [return_wraps, bind_sequences, fail_short_circuits, bind_threads_state,
     accessors_read_write, await_captures_rest, lift_injects,
     run_async_complete, run_async_error, run_async_parks, resume_completes,
     resume_multiple_suspends, resume_nested_ordering].

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

run_async_complete(_Config) ->
    M = async_m:return(5),
    Ok = fun(V, _S, D) -> {done, V, D} end,
    Err = fun(R, _S, _D) -> {err, R} end,
    {done, 5, #{}} = async_m:run_async(M, Ok, Err, st, #{}),
    ok.

run_async_error(_Config) ->
    M = async_m:fail(nope),
    Ok = fun(V, _S, _D) -> {done, V} end,
    Err = fun(R, _S, _D) -> {err, R} end,
    {err, nope} = async_m:run_async(M, Ok, Err, st, #{}),
    ok.

run_async_parks(_Config) ->
    M = do([async_m || R <- async_m:await(req1),
                       async_m:return(R)]),
    Ok = fun(V, _S, D) -> {done, V, D} end,
    Err = fun(R, _S, _D) -> {err, R} end,
    {next_state, st, Data1} = async_m:run_async(M, Ok, Err, st, #{}),
    true = is_map_key(req1, maps:get(async_pending, Data1)),
    ok.

resume_completes(_Config) ->
    M = do([async_m || R <- async_m:await(req1),
                       async_m:return(R * 10)]),
    Ok = fun(V, _S, D) -> {done, V, D} end,
    Err = fun(R, _S, _D) -> {err, R} end,
    {next_state, st, Data1} = async_m:run_async(M, Ok, Err, st, #{}),
    %% reply 4 arrives -> 4 * 10 = 40, and the entry is removed
    {done, 40, Data2} = async_m:handle_reply(req1, 4, st, Data1),
    #{} = maps:get(async_pending, Data2),
    no_entry = async_m:handle_reply(req1, 4, st, Data2),
    ok.

resume_multiple_suspends(_Config) ->
    %% suspends twice; the second await parks again, then completes
    M = do([async_m || A <- async_m:await(reqA),
                       B <- async_m:await(reqB),
                       async_m:return(A + B)]),
    Ok = fun(V, _S, D) -> {done, V, D} end,
    Err = fun(R, _S, _D) -> {err, R} end,
    {next_state, st, D1} = async_m:run_async(M, Ok, Err, st, #{}),
    {next_state, st, D2} = async_m:handle_reply(reqA, 1, st, D1),
    true = is_map_key(reqB, maps:get(async_pending, D2)),
    {done, 3, _} = async_m:handle_reply(reqB, 2, st, D2),
    ok.

resume_nested_ordering(_Config) ->
    %% a nested monadic value bound on the LHS produces Conts of length 2,
    %% ordered outermost-first; resume must feed the reply to the INNERMOST
    %% continuation first, then outward.
    Inner = fun() -> do([async_m || C <- async_m:await(req1),
                                    async_m:return(C + 1)]) end,
    M = do([async_m || A <- Inner(),
                       async_m:return(A * 2)]),
    Ok = fun(V, _S, D) -> {done, V, D} end,
    Err = fun(R, _S, _D) -> {err, R} end,
    {next_state, st, D1} = async_m:run_async(M, Ok, Err, st, #{}),
    %% reply 10 -> inner 10+1=11 -> outer 11*2=22
    {done, 22, _} = async_m:handle_reply(req1, 10, st, D1),
    ok.
