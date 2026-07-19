%% async_m: a state + error + suspension monad for non-blocking gen_statem procedures.
%% See docs/superpowers/async-statem-design.md and
%% docs/superpowers/specs/2026-07-19-async-context-io-architecture-design.md
-module(async_m).
-compile({parse_transform, do}).

-behaviour(monad).
-export(['>>='/2, return/1, fail/1]).
-export([run/3]).

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
