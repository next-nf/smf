%% Copyright 2026, Nathan Foster

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

%% @doc GTP path database — cluster-wide path state.
%%
%% Replaces gtp_path_db_vnode. Stores path restart counters, node
%% membership, and state. Uses ergw_db for raw storage.

-module(gtp_path_db).

-compile({no_auto_import,[put/2]}).

%% API
-export([create/0]).
-export([get/1, put/2, cas_restart_counter/3]).
-export([state/3, attach/2, detach/2]).
-export([all/0]).

-define(TAB, ?MODULE).

%%%===================================================================
%%% API
%%%===================================================================

create() ->
    ergw_db:create(?TAB, #{type => set, scope => global}).

get(Key) ->
    case ergw_db:lookup(?TAB, Key) of
	[{_, Value}] -> {ok, Value};
	[] -> {error, not_found}
    end.

put(Key, Value) ->
    ergw_db:insert(?TAB, {Key, Value}).

cas_restart_counter(Key, Counter, Time) ->
    Obj = case ergw_db:lookup(?TAB, Key) of
	      [{_, V}] -> V;
	      [] -> init_obj(undefined, #{}, Time)
	  end,
    {Result, New, ObjTime} = do_cas(Counter, Time, Obj),
    ergw_db:insert(?TAB, {Key, Obj#{restart_counter => New, time => ObjTime}}),
    {Result, New, ObjTime}.

state(Key, State, Node) ->
    case ergw_db:lookup(?TAB, Key) of
	[{_, Obj0}] ->
	    Obj1 = Obj0#{state => State},
	    Obj = update_nodes(fun(M) -> M#{Node => true} end, Obj1),
	    ergw_db:insert(?TAB, {Key, Obj});
	[] ->
	    ok
    end.

attach(Key, Node) ->
    case ergw_db:lookup(?TAB, Key) of
	[{_, Obj0}] ->
	    Obj = update_nodes(fun(M) -> M#{Node => true} end, Obj0),
	    ergw_db:insert(?TAB, {Key, Obj});
	[] ->
	    Obj = init_obj(undefined, #{Node => true}, 0),
	    ergw_db:insert(?TAB, {Key, Obj})
    end.

detach(Key, Node) ->
    case ergw_db:lookup(?TAB, Key) of
	[{_, Obj0}] ->
	    case update_nodes(fun(M) -> maps:remove(Node, M) end, Obj0) of
		#{nodes := Nodes} when map_size(Nodes) == 0 ->
		    ergw_db:delete(?TAB, Key);
		Obj ->
		    ergw_db:insert(?TAB, {Key, Obj})
	    end;
	[] ->
	    ok
    end.

all() ->
    [{K, V} || {K, V} <- ergw_db:tab2list(?TAB)].

%%%===================================================================
%%% Internal functions
%%%===================================================================

init_obj(RC, Nodes, Time) ->
    #{restart_counter => RC, nodes => Nodes, time => Time, state => init}.

update_nodes(Fun, Obj) ->
    maps:update_with(nodes, Fun, Obj).

do_cas(Counter, Time, #{time := ObjTime0} = Obj) ->
    {Result, New} = update_restart_counter(Counter, Obj),
    ObjTime = max(Time, ObjTime0) + 1,
    {Result, New, ObjTime}.

%% 3GPP TS 23.007, Sect. 18 GTP-C-based restart procedures:
%%
%% The GTP-C entity that receives a Recovery Information Element in an Echo
%% Response or in another GTP-C message from a peer, shall compare the received
%% remote Restart counter value with the previous Restart counter value stored
%% for that peer entity.
%%
%%   - If no previous value was stored the Restart counter value received shall
%%     be stored for the peer.
%%
%%   - If the previous value is smaller than the received value (with integer
%%     roll-over), this indicates a peer restart. The new value replaces the old.
%%
%%   - If the previous value is larger than the received value (with roll-over),
%%     this indicates a possible race condition. The new value is discarded.

-define(SMALLER(S1, S2),
	((S1 < S2 andalso (S2 - S1) < 128) orelse
	 (S1 > S2 andalso (S1 - S2) > 128))).

update_restart_counter(Counter, #{restart_counter := undefined}) ->
    {initial, Counter};
update_restart_counter(Counter, #{restart_counter := Counter}) ->
    {current, Counter};
update_restart_counter(New, #{restart_counter := Old})
  when ?SMALLER(Old, New) ->
    {peer_restart, New};
update_restart_counter(_New, #{restart_counter := Old}) ->
    {old, Old}.
