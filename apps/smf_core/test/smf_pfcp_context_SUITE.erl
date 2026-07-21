-module(smf_pfcp_context_SUITE).
-compile([export_all, nowarn_export_all]).
-include_lib("common_test/include/ct.hrl").
-include_lib("pfcplib/include/pfcp_packet.hrl").
-include("../include/smf.hrl").

all() -> [result_accept, result_wrong_cause, result_timeout, result_unreachable, result_dead,
	  create_result_accept, create_result_wrong_cause, create_result_timeout].

create_result_accept(_Config) ->
    meck:new(gtp_context_reg, [passthrough, no_link]),
    meck:expect(gtp_context_reg, register, fun(_Keys, _Handler, _Pid) -> ok end),
    try
	PdrId = 1,
	Key = {'Access', 1},
	PCtx = #pfcp_ctx{seid = #seid{cp = 1}, chid_by_pdr = #{PdrId => Key}},
	BearerMap = #{Key => #bearer{interface = 'Access', local = #fq_teid{ip = v4}}},
	Reply = #pfcp{version = v1, type = session_establishment_response,
		      ie = #{pfcp_cause => 'Request accepted',
			     f_seid => #f_seid{seid = 2, ipv4 = <<127,0,0,1>>},
			     created_pdr =>
				 [#{pdr_id => #pdr_id{id = PdrId},
				    f_teid => #f_teid{teid = 16#1234, ipv4 = <<127,0,0,1>>}}]}},
	{ok, {#pfcp_ctx{}, _BearerMap, _SessionInfo}} =
	    smf_pfcp_context:create_session_result(Reply, test_handler, BearerMap, PCtx),
	ok
    after
	meck:unload(gtp_context_reg)
    end.

create_result_wrong_cause(_Config) ->
    PCtx = #pfcp_ctx{},
    Reply = #pfcp{version = v1, type = session_establishment_response,
                  ie = #{pfcp_cause => 'System failure'}},
    {error, _} = smf_pfcp_context:create_session_result(Reply, test_handler, #{}, PCtx),
    ok.

create_result_timeout(_Config) ->
    {error, _} = smf_pfcp_context:create_session_result(timeout, test_handler, #{}, #pfcp_ctx{}),
    ok.

result_accept(_Config) ->
    PCtx = #pfcp_ctx{},
    Reply = #pfcp{version = v1, type = session_modification_response,
                  ie = #{pfcp_cause => 'Request accepted'}},
    {ok, {PCtx, undefined, _SessionInfo}} = smf_pfcp_context:modify_session_result(Reply, PCtx),
    ok.

result_wrong_cause(_Config) ->
    PCtx = #pfcp_ctx{},
    Reply = #pfcp{version = v1, type = session_modification_response,
                  ie = #{pfcp_cause => 'System failure'}},
    {error, _} = smf_pfcp_context:modify_session_result(Reply, PCtx),
    ok.

result_timeout(_Config)     -> {error, _} = smf_pfcp_context:modify_session_result(timeout, #pfcp_ctx{}), ok.
result_unreachable(_Config) -> {error, _} = smf_pfcp_context:modify_session_result(unreachable, #pfcp_ctx{}), ok.
result_dead(_Config)        -> {error, _} = smf_pfcp_context:modify_session_result({error, dead}, #pfcp_ctx{}), ok.
