%% Copyright 2026, Nathan Foster

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(ergw_db).

%% API
-export([init/0, backend/0]).
-export([create/2, delete_table/1]).
-export([insert/2, insert_new/2, delete/2, delete_object/2]).
-export([lookup/2, take/2, update_element/3]).
-export([select/1, select/2, select/3]).
-export([tab2list/1]).
-export([fold/5]).

%% Types
-export_type([table/0, table_opts/0, cursor/0]).

-type table()      :: atom().
-type key()        :: term().
-type object()     :: tuple().
-type cursor()     :: term().
-type table_opts() :: #{type  := set | ordered_set | bag,
			scope := local | global,
			keypos => pos_integer(),
			read_concurrency => boolean(),
			write_concurrency => boolean() | auto,
			decentralized_counters => boolean(),
			_ => _}.

%% Table lifecycle
-callback create(table(), table_opts()) -> ok.
-callback delete_table(table()) -> ok.

%% Write
-callback insert(table(), object() | [object()]) -> ok.
-callback insert_new(table(), object() | [object()]) -> boolean().
-callback delete(table(), key()) -> ok.
-callback delete_object(table(), object()) -> ok.

%% Read
-callback lookup(table(), key()) -> [object()].
-callback take(table(), key()) -> [object()].
-callback update_element(table(), key(),
			 {pos_integer(), term()} | [{pos_integer(), term()}]) -> boolean().

%% Iteration — cursor-based
-callback select(table(), ets:match_spec()) -> [term()].
-callback select(table(), ets:match_spec(), pos_integer()) ->
    {[term()], cursor()} | '$end_of_table'.
-callback select(cursor()) ->
    {[term()], cursor()} | '$end_of_table'.

%% Full scan
-callback tab2list(table()) -> [object()].

-define(PT_KEY, {?MODULE, backend}).

%%%===================================================================
%%% API
%%%===================================================================

-spec init() -> ok.
init() ->
    Mod = application:get_env(ergw_core, db_backend, ergw_db_ets),
    persistent_term:put(?PT_KEY, Mod),
    ok.

-spec backend() -> module().
backend() ->
    persistent_term:get(?PT_KEY).

%% Table lifecycle

-spec create(table(), table_opts()) -> ok.
create(Tab, Opts) ->
    (backend()):create(Tab, Opts).

-spec delete_table(table()) -> ok.
delete_table(Tab) ->
    (backend()):delete_table(Tab).

%% Write operations

-spec insert(table(), object() | [object()]) -> ok.
insert(Tab, Obj) ->
    (backend()):insert(Tab, Obj).

-spec insert_new(table(), object() | [object()]) -> boolean().
insert_new(Tab, Obj) ->
    (backend()):insert_new(Tab, Obj).

-spec delete(table(), key()) -> ok.
delete(Tab, Key) ->
    (backend()):delete(Tab, Key).

-spec delete_object(table(), object()) -> ok.
delete_object(Tab, Obj) ->
    (backend()):delete_object(Tab, Obj).

%% Read operations

-spec lookup(table(), key()) -> [object()].
lookup(Tab, Key) ->
    (backend()):lookup(Tab, Key).

-spec take(table(), key()) -> [object()].
take(Tab, Key) ->
    (backend()):take(Tab, Key).

-spec update_element(table(), key(),
		     {pos_integer(), term()} | [{pos_integer(), term()}]) -> boolean().
update_element(Tab, Key, Update) ->
    (backend()):update_element(Tab, Key, Update).

%% Iteration

-spec select(table(), ets:match_spec()) -> [term()].
select(Tab, MatchSpec) ->
    (backend()):select(Tab, MatchSpec).

-spec select(table(), ets:match_spec(), pos_integer()) ->
	  {[term()], cursor()} | '$end_of_table'.
select(Tab, MatchSpec, Limit) ->
    (backend()):select(Tab, MatchSpec, Limit).

-spec select(cursor()) -> {[term()], cursor()} | '$end_of_table'.
select(Cursor) ->
    (backend()):select(Cursor).

%% Full scan

-spec tab2list(table()) -> [object()].
tab2list(Tab) ->
    (backend()):tab2list(Tab).

%% Convenience: fold over table using cursors

-spec fold(fun((term(), Acc) -> Acc), Acc, table(), ets:match_spec(), pos_integer()) -> Acc.
fold(Fun, Acc0, Tab, MatchSpec, PageSize) ->
    fold_1(Fun, Acc0, select(Tab, MatchSpec, PageSize)).

%%%===================================================================
%%% Internal functions
%%%===================================================================

fold_1(_Fun, Acc, '$end_of_table') ->
    Acc;
fold_1(Fun, Acc0, {Objects, Cursor}) ->
    Acc = lists:foldl(Fun, Acc0, Objects),
    fold_1(Fun, Acc, select(Cursor)).
