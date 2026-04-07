%% Copyright 2026, Nathan Foster

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

%% @doc Mnesia backend for ergw_db.
%%
%% Local tables (scope => local) delegate to ergw_db_ets.
%% Global tables (scope => global) use Mnesia ram_copies replicated
%% across all connected nodes.
%%
%% Global tables use a fixed 2-attribute record {key, val}.
%% ETS tuples {K, V} map to Mnesia records {Tab, K, V}.

-module(ergw_db_mnesia).

-behaviour(ergw_db).

%% ergw_db callbacks
-export([create/2, delete_table/1]).
-export([insert/2, insert_new/2, delete/2, delete_object/2]).
-export([lookup/2, take/2, update_element/3]).
-export([select/1, select/2, select/3]).
-export([tab2list/1]).

-define(SCOPE_KEY(Tab), {?MODULE, scope, Tab}).

%%%===================================================================
%%% ergw_db callbacks
%%%===================================================================

create(Name, #{scope := global, type := Type}) ->
    persistent_term:put(?SCOPE_KEY(Name), global),
    create_global(Name, Type);
create(Name, #{scope := local} = Opts) ->
    persistent_term:put(?SCOPE_KEY(Name), local),
    ergw_db_ets:create(Name, Opts).

delete_table(Tab) ->
    case is_global(Tab) of
	true ->
	    mnesia:delete_table(Tab),
	    ok;
	false ->
	    ergw_db_ets:delete_table(Tab)
    end.

insert(Tab, Obj) ->
    case is_global(Tab) of
	true ->
	    mnesia:dirty_write(Tab, to_mnesia(Tab, Obj)),
	    ok;
	false ->
	    ergw_db_ets:insert(Tab, Obj)
    end.

insert_new(Tab, Obj) ->
    case is_global(Tab) of
	true ->
	    Rec = to_mnesia(Tab, Obj),
	    Key = element(2, Rec),
	    F = fun() ->
			case mnesia:read(Tab, Key) of
			    [] -> mnesia:write(Tab, Rec, write), true;
			    _  -> false
			end
		end,
	    {atomic, Result} = mnesia:transaction(F),
	    Result;
	false ->
	    ergw_db_ets:insert_new(Tab, Obj)
    end.

delete(Tab, Key) ->
    case is_global(Tab) of
	true ->
	    mnesia:dirty_delete(Tab, Key),
	    ok;
	false ->
	    ergw_db_ets:delete(Tab, Key)
    end.

delete_object(Tab, Obj) ->
    case is_global(Tab) of
	true ->
	    mnesia:dirty_delete_object(to_mnesia(Tab, Obj)),
	    ok;
	false ->
	    ergw_db_ets:delete_object(Tab, Obj)
    end.

lookup(Tab, Key) ->
    case is_global(Tab) of
	true ->
	    [from_mnesia(R) || R <- mnesia:dirty_read(Tab, Key)];
	false ->
	    ergw_db_ets:lookup(Tab, Key)
    end.

take(Tab, Key) ->
    case is_global(Tab) of
	true ->
	    F = fun() ->
			Recs = mnesia:read(Tab, Key),
			mnesia:delete(Tab, Key, write),
			Recs
		end,
	    {atomic, Recs} = mnesia:transaction(F),
	    [from_mnesia(R) || R <- Recs];
	false ->
	    ergw_db_ets:take(Tab, Key)
    end.

update_element(Tab, Key, {Pos, Val}) ->
    case is_global(Tab) of
	true ->
	    case mnesia:dirty_read(Tab, Key) of
		[Rec] ->
		    %% Pos is ETS-relative (1-based), Mnesia has tab name at pos 1
		    NewRec = setelement(Pos + 1, Rec, Val),
		    mnesia:dirty_write(Tab, NewRec),
		    true;
		[] ->
		    false
	    end;
	false ->
	    ergw_db_ets:update_element(Tab, Key, {Pos, Val})
    end;
update_element(Tab, Key, Updates) when is_list(Updates) ->
    case is_global(Tab) of
	true ->
	    case mnesia:dirty_read(Tab, Key) of
		[Rec0] ->
		    Rec = lists:foldl(
			    fun({Pos, Val}, R) -> setelement(Pos + 1, R, Val) end,
			    Rec0, Updates),
		    mnesia:dirty_write(Tab, Rec),
		    true;
		[] ->
		    false
	    end;
	false ->
	    ergw_db_ets:update_element(Tab, Key, Updates)
    end.

select(Tab, MatchSpec) ->
    case is_global(Tab) of
	true ->
	    MS = transform_match_spec(Tab, MatchSpec),
	    mnesia:dirty_select(Tab, MS);
	false ->
	    ergw_db_ets:select(Tab, MatchSpec)
    end.

select(Tab, MatchSpec, Limit) ->
    case is_global(Tab) of
	true ->
	    MS = transform_match_spec(Tab, MatchSpec),
	    mnesia:activity(
	      async_dirty,
	      fun() ->
		      case mnesia:select(Tab, MS, Limit, read) of
			  {Objs, Cont} -> {Objs, {mnesia, Cont}};
			  '$end_of_table' -> '$end_of_table'
		      end
	      end);
	false ->
	    ergw_db_ets:select(Tab, MatchSpec, Limit)
    end.

select({mnesia, Cont}) ->
    mnesia:activity(
      async_dirty,
      fun() ->
	      case mnesia:select(Cont) of
		  {Objs, NewCont} -> {Objs, {mnesia, NewCont}};
		  '$end_of_table' -> '$end_of_table'
	      end
      end);
select(Cont) ->
    ergw_db_ets:select(Cont).

tab2list(Tab) ->
    case is_global(Tab) of
	true ->
	    [from_mnesia(R) || R <- mnesia:dirty_select(Tab, [{'_', [], ['$_']}])];
	false ->
	    ergw_db_ets:tab2list(Tab)
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

is_global(Tab) ->
    persistent_term:get(?SCOPE_KEY(Tab), local) =:= global.

%% Convert ETS tuple {K, V} to Mnesia record {Tab, K, V}
to_mnesia(Tab, Obj) when is_tuple(Obj) ->
    erlang:insert_element(1, Obj, Tab).

%% Convert Mnesia record {Tab, K, V} to ETS tuple {K, V}
from_mnesia(Rec) when is_tuple(Rec) ->
    erlang:delete_element(1, Rec).

%% Transform ETS match specs to Mnesia match specs.
%% Prepends table name to each match head tuple.
%% Match spec bodies that return '$_' need post-processing since
%% Mnesia '$_' includes the table name. We leave them as-is —
%% callers using select/2,3 on global tables get Mnesia records
%% in body results. For tab2list we strip explicitly.
transform_match_spec(Tab, MatchSpec) ->
    [{transform_head(Tab, Head), Guards, Body}
     || {Head, Guards, Body} <- MatchSpec].

transform_head(_Tab, '_') -> '_';
transform_head(Tab, Head) when is_tuple(Head) ->
    erlang:insert_element(1, Head, Tab).

create_global(Name, Type) ->
    Opts = [{ram_copies, [node() | nodes()]},
	    {type, Type},
	    {attributes, [key, val]}],
    case mnesia:create_table(Name, Opts) of
	{atomic, ok} ->
	    ok;
	{aborted, {already_exists, Name}} ->
	    case lists:member(node(), mnesia:table_info(Name, ram_copies)) of
		true ->
		    ok;
		false ->
		    {atomic, ok} = mnesia:add_table_copy(Name, node(), ram_copies),
		    ok
	    end,
	    mnesia:wait_for_tables([Name], 5000),
	    ok
    end.
