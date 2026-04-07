%% Copyright 2026, Nathan Foster

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(ergw_db_ets).

-behaviour(ergw_db).

%% ergw_db callbacks
-export([create/2, delete_table/1]).
-export([insert/2, insert_new/2, delete/2, delete_object/2]).
-export([lookup/2, take/2, update_element/3]).
-export([select/1, select/2, select/3]).
-export([tab2list/1]).

%%%===================================================================
%%% ergw_db callbacks
%%%===================================================================

create(Name, Opts) ->
    Type = maps:get(type, Opts),
    KeyPos = maps:get(keypos, Opts, 1),
    EtsOpts = [Type, named_table, public, {keypos, KeyPos}]
	++ bool_opt(read_concurrency, Opts)
	++ bool_opt(write_concurrency, Opts)
	++ bool_opt(decentralized_counters, Opts),
    ets:new(Name, EtsOpts),
    ok.

delete_table(Name) ->
    ets:delete(Name),
    ok.

insert(Tab, Obj) ->
    ets:insert(Tab, Obj),
    ok.

insert_new(Tab, Obj) ->
    ets:insert_new(Tab, Obj).

delete(Tab, Key) ->
    ets:delete(Tab, Key),
    ok.

delete_object(Tab, Obj) ->
    ets:delete_object(Tab, Obj),
    ok.

lookup(Tab, Key) ->
    ets:lookup(Tab, Key).

take(Tab, Key) ->
    ets:take(Tab, Key).

update_element(Tab, Key, Update) ->
    ets:update_element(Tab, Key, Update).

select(Tab, MatchSpec) ->
    ets:select(Tab, MatchSpec).

select(Tab, MatchSpec, Limit) ->
    case ets:select(Tab, MatchSpec, Limit) of
	{Objects, Continuation} -> {Objects, Continuation};
	'$end_of_table' -> '$end_of_table'
    end.

select(Continuation) ->
    case ets:select(Continuation) of
	{Objects, NewContinuation} -> {Objects, NewContinuation};
	'$end_of_table' -> '$end_of_table'
    end.

tab2list(Tab) ->
    ets:tab2list(Tab).

%%%===================================================================
%%% Internal functions
%%%===================================================================

bool_opt(Key, Opts) ->
    case maps:find(Key, Opts) of
	{ok, Val} -> [{Key, Val}];
	error -> []
    end.
