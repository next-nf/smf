%% async_m: a state + error + suspension monad for non-blocking gen_statem procedures.
%% See docs/superpowers/async-statem-design.md and
%% docs/superpowers/specs/2026-07-19-async-context-io-architecture-design.md
-module(async_m).
-compile({parse_transform, do}).

-behaviour(monad).
-export(['>>='/2, return/1, fail/1]).
-export([run/3]).
-export([get_state/0, put_state/1, modify_state/1,
         get_data/0, put_data/1, modify_data/1,
         await/1, lift/1]).

-export_type([async_m/0, result/0]).

%% a monadic value: threads the gen_statem State and Data, yields a result
-type async_m() :: fun((State :: term(), Data :: term()) -> {result(), term(), term()}).
-type result()  :: {ok, term()} | {error, term()} | {await, term(), [fun()]}.

-spec '>>='(async_m(), fun((term()) -> async_m())) -> async_m().
'>>='(X, Fun) ->
    fun(S, D) ->
            case X(S, D) of
                {{ok, A}, S1, D1} ->
                    (Fun(A))(S1, D1);
                {{error, _} = Err, S1, D1} ->
                    {Err, S1, D1};
                {{await, ReqId, Conts}, S1, D1} ->
                    %% do NOT run Fun; capture it as the next continuation
                    {{await, ReqId, [Fun | Conts]}, S1, D1}
            end
    end.

-spec return(term()) -> async_m().
return(A) ->
    fun(S, D) -> {{ok, A}, S, D} end.

-spec fail(term()) -> async_m().
fail(E) ->
    fun(S, D) -> {{error, E}, S, D} end.

-spec run(async_m(), term(), term()) -> {result(), term(), term()}.
run(M, S, D) ->
    M(S, D).

-spec get_state() -> async_m().
get_state() -> fun(S, D) -> {{ok, S}, S, D} end.

-spec put_state(term()) -> async_m().
put_state(S1) -> fun(_S, D) -> {{ok, ok}, S1, D} end.

-spec modify_state(fun((term()) -> term())) -> async_m().
modify_state(F) -> fun(S, D) -> {{ok, ok}, F(S), D} end.

-spec get_data() -> async_m().
get_data() -> fun(S, D) -> {{ok, D}, S, D} end.

-spec put_data(term()) -> async_m().
put_data(D1) -> fun(S, _D) -> {{ok, ok}, S, D1} end.

-spec modify_data(fun((term()) -> term())) -> async_m().
modify_data(F) -> fun(S, D) -> {{ok, ok}, S, F(D)} end.

-spec await(term()) -> async_m().
await(ReqId) -> fun(S, D) -> {{await, ReqId, []}, S, D} end.

-spec lift(ok | {ok, term()} | {error, term()} | term()) -> async_m().
lift(ok)          -> return(ok);
lift({ok, V})     -> return(V);
lift({error, E})  -> fail(E);
lift(V)           -> return(V).
