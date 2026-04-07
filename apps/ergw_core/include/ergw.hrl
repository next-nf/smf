%% Copyright 2015, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-define(GTP0_PORT,	3386).
-define(GTP1c_PORT,	2123).
-define(GTP1u_PORT,	2152).
-define(GTP2c_PORT,	2123).

%% ErrLevel
-define(WARNING, 1).
-define(FATAL, 2).

-record(ctx_err, {
	  level,
	  where,
	  reply,
	  context,
	  tunnel
	 }).

-define(CTX_ERR(Level,Reply), #ctx_err{level=Level,reply=Reply,where={?FILE, ?LINE}}).
-define(CTX_ERR(Level,Reply,Context), #ctx_err{level=Level,reply=Reply,
					       context=Context,where={?FILE, ?LINE}}).

-record(node, {
	  node	:: atom() | binary(),
	  ip	:: inet:ip_address()
	 }).

-record(fq_teid, {
	  ip       :: inet:ip_address() | 'v4' | 'v6' | undefined,
	  teid = 0 :: non_neg_integer() | {upf, term()}
	 }).

-record(ue_ip, {
	  v4               :: inet:ip4_address() | undefined,
	  v6               :: inet:ip6_address() | undefined,
	  nat              :: term()
	 }).

-record(seid, {
	  cp = 0           :: non_neg_integer(),
	  dp = 0           :: non_neg_integer()
	 }).

-record(socket, {
	  name             :: term(),
	  type             :: 'gtp-c' | 'gtp-u',
	  pid              :: pid() | undefined
	 }).

-record(tunnel, {
	  interface		:: 'Access' | 'Core' | undefined,
	  vrf			:: term(),
	  socket		:: #socket{} | undefined,
	  path			:: 'undefined' | pid(),
	  version               :: 'v1' | 'v2' | undefined,
	  local			:: 'undefined' | #fq_teid{},
	  remote		:: 'undefined' | #fq_teid{},
	  remote_restart_counter :: 0 .. 255 | undefined
	 }).

-record(bearer, {
	  interface             :: 'Access' | 'Core' | 'SGi-LAN' |
				   'CP-function' | 'LI Function' | undefined,
	  vrf			:: term(),
	  local			:: 'undefined' | #fq_teid{} | #ue_ip{},
	  remote		:: 'undefined' | 'default' | #fq_teid{} | #ue_ip{}
	 }).

-record(pfcp_ctx, {
	  name			:: term(),
	  node			:: pid(),
	  features,
	  seid			:: #seid{},

	  cp_bearer		:: #bearer{},

	  idcnt = #{}		:: map(),
	  idmap = #{}		:: map(),
	  urr_by_id = #{}	:: map(),
	  urr_by_grp = #{}	:: map(),
	  chid_by_pdr = #{}	:: map(),
	  sx_rules = #{}	:: map(),
	  timers = #{}		:: map(),
	  timer_by_tref = #{}	:: map(),

	  up_inactivity_timer   :: 'undefined' | non_neg_integer()
	 }).

-record(pcc_ctx, {
	  monitors = #{}	:: map(),
	  rules = #{}		:: map(),
	  credits = #{}		:: map(),

	  %% TBD:
	  offline_charging_profile = #{}	:: map()
	 }).

-record(context, {
	  apn                    :: [binary()] | undefined,
	  imsi                   :: 'undefined' | binary(),
	  imei                   :: 'undefined' | binary(),
	  msisdn                 :: 'undefined' | binary(),

	  context_id             :: term(),
	  charging_identifier    :: non_neg_integer() | undefined,
	  default_bearer_id      :: 'undefined' | non_neg_integer(),

	  idle_timeout           :: non_neg_integer() | infinity | undefined,
	  inactivity_timeout     :: non_neg_integer() | infinity | undefined,

	  version                :: 'v1' | 'v2' | undefined,
	  pdn_type               :: 'undefined' | 'IPv4' | 'IPv6' | 'IPv4v6' | 'Non-IP',

	  ms_ip                  :: #ue_ip{} | undefined,
	  dns_v6                 :: [inet:ip6_address()] | undefined,
	  restrictions = []      :: [{'v1', boolean()} |
				     {'v2', boolean()}]
	 }).

-record(gtp_socket_info, {
	  vrf              :: term(),
	  ip               :: inet:ip_address()
	 }).

-record(request, {
	  key		:: term(),
	  socket	:: #socket{},
	  info          :: #gtp_socket_info{},
	  src		:: atom(),
	  ip		:: inet:ip_address(),
	  port		:: 0 .. 65535,
	  version	:: 'v1' | 'v2',
	  type		:: atom(),
	  arrival_ts    :: integer()
	 }).

-record(vrf, {
	  name                   :: atom(),
	  features = ['SGi-Lan'] :: ['Access' | 'Core' | 'SGi-LAN' |
				     'CP-function' | 'LI Function'],
	  teid_range,
	  ipv4,
	  ipv6
	 }).

-record(counter, {
	  rx :: {Bytes :: integer(), Packets :: integer()},
	  tx :: {Bytes :: integer(), Packets :: integer()}
	 }).

%% nBsf registration record
%% Fields allow '_' for use as ETS match spec wildcards
-record(bsf, {
	  dnn                       :: [binary()] | undefined | '_',
	  snssai = {1, 16#ffffff}   :: {0..255, 0..16#ffffff | '_'} | undefined | '_',
	  ip_domain                 :: binary() | undefined | '_',
	  ip                        :: {inet:ip4_address(),1..32}|
				       {inet:ip6_address(),1..128} | undefined | '_'
	}).

-record(seid_key, {seid}).
-record(context_key, {socket, id}).
-record(socket_teid_key, {name, type, teid}).
