%% Copyright 2021, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(ergw_cluster).

-behavior(gen_statem).

-compile({parse_transform, do}).

%% API
-export([start_link/0, start/1,
	 validate_options/1,
	 wait_till_ready/0,
	 is_ready/0]).

-ignore_xref([start_link/0, validate_options/1]).

-ifdef(TEST).
-export([start/2, wait_till_running/0, is_running/0]).
-endif.

%% gen_statem callbacks
-export([callback_mode/0, init/1, handle_event/4,
	 terminate/3, code_change/4]).

-include_lib("kernel/include/logger.hrl").

-define(SERVER, ?MODULE).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_statem:start_link({local, ?SERVER}, ?MODULE, [], []).

start(Config) ->
    start(Config, infinity).

start(Config, Timeout) ->
    Cnf = validate_options(Config),
    gen_statem:call(?SERVER, {start, Cnf}, Timeout).

wait_till_ready() ->
    ok = gen_statem:call(?SERVER, wait_till_ready, infinity).

is_ready() ->
    gen_statem:call(?SERVER, is_ready).

-ifdef(TEST).
wait_till_running() ->
    ok = gen_statem:call(?SERVER, wait_till_running, infinity).

is_running() ->
    gen_statem:call(?SERVER, is_running).
-endif.

%%%===================================================================
%%% Options Validation
%%%===================================================================

-define(ClusterDefaults, [{enabled, false},
			  {seed_nodes, {erlang, nodes, [known]}}]).

validate_options(Values) ->
    ergw_core_config:validate_options(fun validate_option/2, Values, ?ClusterDefaults).

validate_option(enabled, Value) when is_boolean(Value) ->
    Value;
validate_option(initial_timeout, Value)
  when is_integer(Value), Value > 0 ->
    Value;
validate_option(release_cursor_every, Value)
  when is_integer(Value) ->
    Value;
validate_option(seed_nodes, {M, F, A} = Value)
  when is_atom(M), is_atom(F), is_list(A) ->
    Value;
validate_option(seed_nodes, Nodes) when is_list(Nodes) ->
    lists:foreach(
      fun(Node) when is_atom(Node) -> ok;
	 (Node) ->
	      throw({error, {options, {seed_nodes, Node}}})
      end, Nodes),
    Nodes;
validate_option(Opt, Value) ->
    throw({error, {options, {Opt, Value}}}).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

callback_mode() -> [handle_event_function].

init([]) ->
    process_flag(trap_exit, true),
    Now = erlang:monotonic_time(),

    Pid = spawn_link(fun startup/0),
    {ok, startup, #{init => Now, startup => Pid}}.

handle_event({call, From}, wait_till_ready, State, _Data)
  when State =:= ready; State =:= running ->
    {keep_state_and_data, [{reply, From, ok}]};
handle_event({call, _From}, wait_till_ready, _State, _Data) ->
    {keep_state_and_data, [postpone]};

handle_event({call, From}, wait_till_running, running, _Data) ->
    {keep_state_and_data, [{reply, From, ok}]};
handle_event({call, _From}, wait_till_running, _State, _Data) ->
    {keep_state_and_data, [postpone]};

handle_event({call, From}, is_ready, State, _Data) ->
    Reply = {reply, From, State == ready orelse State == running},
    {keep_state_and_data, [Reply]};

handle_event({call, From}, is_running, State, _Data) ->
    Reply = {reply, From, State == running},
    {keep_state_and_data, [Reply]};

handle_event({call, From}, {start, Config}, ready, Data) ->
    application:set_env([{ergw_cluster, maps:to_list(Config)}]),
    start_cluster(Config),
    {next_state, running, Data#{config => Config}, [{reply, From, ok}]};
handle_event({call, From}, {start, _}, running, _) ->
    {keep_state_and_data, [{reply, From, {error, already_started}}]};
handle_event({call, _}, {start, _}, _State, _) ->
    {keep_state_and_data, [postpone]};

handle_event(info, {'EXIT', Pid, ok}, startup,
	     #{init := Now, startup := Pid} = Data) ->
    ?LOG(info, "ergw_core: ready to process requests, cluster started in ~w ms",
	 [erlang:convert_time_unit(erlang:monotonic_time() - Now, native, millisecond)]),
    {next_state, ready, maps:remove(startup, Data)};

handle_event(info, {'EXIT', Pid, Reason}, startup, #{startup := Pid}) ->
    ?LOG(critical, "cluster support failed to start with ~0p", [Reason]),
    {stop, {shutdown, Reason}};

handle_event(Event, Info, _State, _Data) ->
    ?LOG(error, "~p: ~w: handle_event(~p, ...): ~p", [self(), ?MODULE, Event, Info]),
    keep_state_and_data.

terminate(_Reason, _State, _Data) ->
    stop_cluster(),
    ok.

code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

startup() ->
    %% undocumented, see stdlib's shell.erl
    case init:notify_when_started(self()) of
	started ->
	    ok;
	_ ->
	    init:wait_until_started()
    end,
    exit(ok).

start_cluster(_Config) ->
    do([error_m ||
	   ergw_global:create(),
	   gtp_config:init()
       ]).

stop_cluster() ->
    ok.
