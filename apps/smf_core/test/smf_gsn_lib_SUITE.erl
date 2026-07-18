%% Copyright 2024, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(smf_gsn_lib_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("../include/smf.hrl").

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [normalize_bearer_gbr_aggregates,
     detect_modified_bearers_qos_change,
     detect_modified_bearers_unchanged,
     detect_modified_bearers_after_arp_override,
     bearer_update_cause_class_partitions].

init_per_suite(Config) -> Config.
end_per_suite(_Config) -> ok.

%%%===================================================================
%%% Test cases
%%%===================================================================

normalize_bearer_gbr_aggregates() ->
    [{doc, "normalize_bearer sums GBR/MBR across the bound rules, sorts the rule "
      "names, and captures the SDF filter id -> TFT id mapping"}].
normalize_bearer_gbr_aggregates(_Config) ->
    Rules = #{<<"r1">> => #{'QoS-Information' =>
                                [#{'QoS-Class-Identifier' => 1,
                                   'Max-Requested-Bandwidth-UL' => 100,
                                   'Max-Requested-Bandwidth-DL' => 200,
                                   'Guaranteed-Bitrate-UL' => 100,
                                   'Guaranteed-Bitrate-DL' => 200}],
                            'Flow-Information' =>
                                [#{'Flow-Description' =>
                                       [<<"permit out ip from any to assigned">>],
                                   'Flow-Direction' => [2],
                                   'Packet-Filter-Identifier' => [<<"sdf-1">>]}]},
              <<"r2">> => #{'QoS-Information' =>
                                [#{'QoS-Class-Identifier' => 1,
                                   'Max-Requested-Bandwidth-UL' => 50,
                                   'Max-Requested-Bandwidth-DL' => 50,
                                   'Guaranteed-Bitrate-UL' => 50,
                                   'Guaranteed-Bitrate-DL' => 50}]}},
    PCC = #pcc_ctx{rules = set_qci_arp(Rules, 1, {2, 1, 0})},
    D = smf_gsn_lib:normalize_bearer(7, 1, {2, 1, 0}, PCC, 42),
    ?assertEqual(7, D#ded_bearer.ebi),
    ?assertEqual(1, D#ded_bearer.qci),
    ?assertEqual({2, 1, 0}, D#ded_bearer.arp),
    ?assertEqual({2, 1, 0}, D#ded_bearer.bind_arp),
    ?assertEqual(42, D#ded_bearer.charging_id),
    ?assertEqual([<<"r1">>, <<"r2">>], D#ded_bearer.rules),
    %% GBR QCI 1: bitrates summed across the two bound rules
    ?assertEqual(150, maps:get('Max-Requested-Bandwidth-UL', D#ded_bearer.qos)),
    ?assertEqual(250, maps:get('Max-Requested-Bandwidth-DL', D#ded_bearer.qos)),
    %% SDF id from r1's Flow-Information captured against its assigned TFT id
    ?assertMatch(#{<<"sdf-1">> := _}, D#ded_bearer.sdf_to_pf),
    ok.

detect_modified_bearers_qos_change() ->
    [{doc, "a bound rule whose aggregate QoS grew is reported as modified with "
      "the new QoS"}].
detect_modified_bearers_qos_change(_Config) ->
    ARP = {2, 1, 0},
    Old = #ded_bearer{ebi = 5, qci = 1, arp = ARP, bind_arp = ARP, charging_id = 9,
                      qos = #{'QoS-Class-Identifier' => 1,
                              'Max-Requested-Bandwidth-UL' => 100,
                              'Max-Requested-Bandwidth-DL' => 100,
                              'Guaranteed-Bitrate-UL' => 100,
                              'Guaranteed-Bitrate-DL' => 100},
                      rules = [<<"r1">>], tft = [], sdf_to_pf = #{}},
    %% new PCC: same rule name, bigger bitrate -> descriptor changes
    NewRules = set_qci_arp(
                 #{<<"r1">> => #{'QoS-Information' =>
                                     [#{'Max-Requested-Bandwidth-UL' => 300,
                                        'Max-Requested-Bandwidth-DL' => 300,
                                        'Guaranteed-Bitrate-UL' => 300,
                                        'Guaranteed-Bitrate-DL' => 300}]}}, 1, ARP),
    NewPCC = #pcc_ctx{rules = NewRules},
    [{5, QoS, _FlowInfo, #ded_bearer{ebi = 5}}] =
        smf_gsn_lib:detect_modified_bearers(NewPCC, #{5 => Old}),
    ?assertEqual(300, maps:get('Max-Requested-Bandwidth-UL', QoS)),
    ok.

detect_modified_bearers_unchanged() ->
    [{doc, "a bearer whose rule set/QoS/TFT is unchanged is not reported (no "
      "spurious Update Bearer Request)"}].
detect_modified_bearers_unchanged(_Config) ->
    ARP = {2, 1, 0},
    NewRules = set_qci_arp(
                 #{<<"r1">> => #{'QoS-Information' =>
                                     [#{'Max-Requested-Bandwidth-UL' => 100,
                                        'Max-Requested-Bandwidth-DL' => 100,
                                        'Guaranteed-Bitrate-UL' => 100,
                                        'Guaranteed-Bitrate-DL' => 100}],
                                 'Flow-Information' => []}}, 1, ARP),
    NewPCC = #pcc_ctx{rules = NewRules},
    %% Build the "stored" descriptor the same way, so it matches exactly.
    Stored = smf_gsn_lib:normalize_bearer(5, 1, ARP, NewPCC, 9),
    ?assertEqual([], smf_gsn_lib:detect_modified_bearers(NewPCC, #{5 => Stored})),
    ok.

detect_modified_bearers_after_arp_override() ->
    [{doc, "after an HSS subscribed-ARP override the bearer is still matched to "
      "its PCC rule via the immutable binding ARP, and the re-authorised "
      "descriptor reverts the wire ARP to the rule ARP"}].
detect_modified_bearers_after_arp_override(_Config) ->
    %% The bearer was created bound to rule ARP {2,1,0}; an HSS subscribed-QoS
    %% modification (M5) then overrode its wire ARP to {5,1,0} while the PCC rule
    %% keeps {2,1,0}. A later rule QoS change must still be detected by matching
    %% on the binding ARP, and the re-authorised descriptor reverts the wire ARP
    %% to the rule ARP (PCRF decision supersedes the subscribed override).
    BindARP = {2, 1, 0},
    WireARP = {5, 1, 0},
    Old = #ded_bearer{ebi = 5, qci = 1, arp = WireARP, bind_arp = BindARP,
                      charging_id = 9,
                      qos = #{'QoS-Class-Identifier' => 1,
                              'Max-Requested-Bandwidth-UL' => 100,
                              'Max-Requested-Bandwidth-DL' => 100,
                              'Guaranteed-Bitrate-UL' => 100,
                              'Guaranteed-Bitrate-DL' => 100},
                      rules = [<<"r1">>], tft = [], sdf_to_pf = #{}},
    NewRules = set_qci_arp(
                 #{<<"r1">> => #{'QoS-Information' =>
                                     [#{'Max-Requested-Bandwidth-UL' => 300,
                                        'Max-Requested-Bandwidth-DL' => 300,
                                        'Guaranteed-Bitrate-UL' => 300,
                                        'Guaranteed-Bitrate-DL' => 300}]}}, 1, BindARP),
    NewPCC = #pcc_ctx{rules = NewRules},
    [{5, QoS, _FlowInfo, New}] =
        smf_gsn_lib:detect_modified_bearers(NewPCC, #{5 => Old}),
    ?assertEqual(300, maps:get('Max-Requested-Bandwidth-UL', QoS)),
    ?assertEqual(BindARP, New#ded_bearer.arp),
    ?assertEqual(BindARP, New#ded_bearer.bind_arp),
    ok.

bearer_update_cause_class_partitions() ->
    [{doc, "Update Bearer Response causes classify into accepted / temporary / terminal "
      "so the fan-out response applies the right action (dossier §8)"}].
bearer_update_cause_class_partitions(_Config) ->
    ?assertEqual(accepted,  smf_gsn_lib:bearer_update_cause_class(request_accepted)),
    ?assertEqual(temporary,
        smf_gsn_lib:bearer_update_cause_class(ue_is_temporarily_not_reachable_due_to_power_saving)),
    ?assertEqual(temporary,
        smf_gsn_lib:bearer_update_cause_class(
            temporarily_rejected_due_to_handover_tau_rau_procedure_in_progress)),
    ?assertEqual(terminal,  smf_gsn_lib:bearer_update_cause_class(no_resources_available)),
    ?assertEqual(terminal,  smf_gsn_lib:bearer_update_cause_class(request_rejected)),
    ok.

%%%===================================================================
%%% Helpers
%%%===================================================================

%% tag every rule def with the {QCI, ARP} the binding logic keys on
set_qci_arp(Rules, QCI, {PL, PCI, PVI}) ->
    ARP = #{'Priority-Level' => PL,
            'Pre-emption-Capability' => PCI,
            'Pre-emption-Vulnerability' => PVI},
    maps:map(
      fun(_Name, #{'QoS-Information' := [Q | _]} = Def) ->
              Def#{'QoS-Information' => [Q#{'QoS-Class-Identifier' => QCI,
                                           'Allocation-Retention-Priority' => ARP}]}
      end, Rules).
