%% Copyright 2021, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(ergw_global).

-compile({no_auto_import,[put/2]}).

%% API
-export([create/0, put/2, get/1, find/1]).

-define(TAB, ?MODULE).

%%%===================================================================
%%% API
%%%===================================================================

create() ->
    ergw_db:create(?TAB, #{type => set, scope => global}).

put(Key, Value) ->
    ergw_db:insert(?TAB, {Key, Value}),
    ok.

get(Key) ->
    case ergw_db:lookup(?TAB, Key) of
	[{_, Value}] -> Value;
	[] -> undefined
    end.

find(Query) ->
    find_query(Query).

%%%===================================================================
%%% Internal functions
%%%===================================================================

find_query([Key|Rest]) ->
    case ergw_db:lookup(?TAB, Key) of
	[{_, Value}] -> find_nested(Rest, Value);
	[] -> false
    end;
find_query([]) ->
    false.

find_nested([], Value) ->
    {ok, Value};
find_nested([K|Next], Config) when is_map_key(K, Config) ->
    find_nested(Next, maps:get(K, Config));
find_nested(_, _) ->
    false.
