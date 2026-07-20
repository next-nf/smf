-module(smf_pfcp_context_SUITE).
-compile([export_all, nowarn_export_all]).
-include_lib("common_test/include/ct.hrl").
-include_lib("pfcplib/include/pfcp_packet.hrl").
-include("../include/smf.hrl").

all() -> [result_accept, result_wrong_cause, result_timeout, result_unreachable, result_dead].

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
