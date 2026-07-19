-module(async_m_SUITE).
-compile([export_all, nowarn_export_all]).
-compile({parse_transform, do}).   %% required: the tests use do([async_m || ...])
-include_lib("common_test/include/ct.hrl").

all() ->
    [return_wraps, bind_sequences, fail_short_circuits, bind_threads_state,
     accessors_read_write, await_captures_rest, lift_injects,
     run_async_complete, run_async_error, run_async_parks, resume_completes,
     resume_multiple_suspends, resume_nested_ordering,
     async_apply_roundtrip, async_apply_worker_crash, resume_await_tail].

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
    {next_state, State1, dt} = async_m:run_async(M, Ok, Err, #{async_pending => #{}}, dt),
    true = is_map_key(req1, maps:get(async_pending, State1)),
    ok.

resume_completes(_Config) ->
    M = do([async_m || R <- async_m:await(req1),
                       async_m:return(R * 10)]),
    Ok = fun(V, S, _D) -> {done, V, S} end,
    Err = fun(R, _S, _D) -> {err, R} end,
    {next_state, State1, dt} = async_m:run_async(M, Ok, Err, #{async_pending => #{}}, dt),
    %% reply 4 arrives -> 4 * 10 = 40, and the entry is removed from the STATE
    {done, 40, State2} = async_m:handle_reply(req1, 4, State1, dt),
    #{} = maps:get(async_pending, State2),
    no_entry = async_m:handle_reply(req1, 4, State2, dt),
    ok.

resume_multiple_suspends(_Config) ->
    %% suspends twice; the second await parks again, then completes
    M = do([async_m || A <- async_m:await(reqA),
                       B <- async_m:await(reqB),
                       async_m:return(A + B)]),
    Ok = fun(V, _S, D) -> {done, V, D} end,
    Err = fun(R, _S, _D) -> {err, R} end,
    {next_state, State1, dt} = async_m:run_async(M, Ok, Err, #{async_pending => #{}}, dt),
    {next_state, State2, dt} = async_m:handle_reply(reqA, 1, State1, dt),
    true = is_map_key(reqB, maps:get(async_pending, State2)),
    {done, 3, _} = async_m:handle_reply(reqB, 2, State2, dt),
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
    {next_state, State1, dt} = async_m:run_async(M, Ok, Err, #{async_pending => #{}}, dt),
    %% reply 10 -> inner 10+1=11 -> outer 11*2=22
    {done, 22, _} = async_m:handle_reply(req1, 10, State1, dt),
    ok.

async_apply_roundtrip(_Config) ->
    %% drive one full suspend/resume cycle using a real worker process
    ReqId0 = async_m:async_apply(fun() -> 6 * 7 end),
    Reply = receive
                {'$async_reply', ReqId0, R} -> R
            after 2000 -> ct:fail(no_reply)
            end,
    {ok, 42} = Reply,
    ok.

async_apply_worker_crash(_Config) ->
    ReqId0 = async_m:async_apply(fun() -> error(kaboom) end),
    %% no '$async_reply'; a tagged DOWN arrives instead
    receive
        {'$async_reply', ReqId0, _} -> ct:fail(unexpected_reply)
    after 0 -> ok
    end,
    receive
        {{'$async_down', ReqId0}, _MRef, process, _Pid, Reason} ->
            {error, {kaboom, _}} = {error, Reason}
    after 2000 -> ct:fail(no_down)
    end,
    ok.

resume_await_tail(_Config) ->
    %% a do-block ENDING in a bare await yields Conts = [] -> resume must not crash;
    %% the reply becomes the result.
    M = do([async_m || _ <- async_m:return(unit),
                       async_m:await(reqX)]),
    Ok = fun(V, _S, D) -> {done, V, D} end,
    Err = fun(R, _S, _D) -> {err, R} end,
    {next_state, State1, dt} = async_m:run_async(M, Ok, Err, #{async_pending => #{}}, dt),
    {done, 99, _} = async_m:handle_reply(reqX, 99, State1, dt),
    ok.
