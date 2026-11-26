// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5850: a combined fixture for the unified MITRE Coverage page.
 *
 * `coverage` is a `GET /api/mitre/coverage` body (all rule modes requested,
 * with the additive `data_sources[].source_types`); `hunts` is a
 * `GET /api/hunts/technique-coverage?days=30` body and `hunts7d` the same
 * install at `days=7`. Shapes match the server exactly; values are synthetic.
 *
 * Telemetry in this install: `microsoft_sysmon__json_`, `windows_event_log`
 * and `okta` are configured and ACTIVE, `linux_auditd` is configured and
 * STALE, nothing else is configured.
 *
 * What each technique exercises (D detection / H hunt / T telemetry, per the
 * design's section 4.2, Both view):
 *
 * | id         | D        | H (30d)   | T        | expected class                    |
 * |------------|----------|-----------|----------|-----------------------------------|
 * | T1059      | partial  | none      | active   | detected (parent; 1 of 2 subs hunted rollup) |
 * | T1059.001  | full     | hunted    | active   | both                              |
 * | T1059.003  | review   | none      | active   | huntable (staging never counts)   |
 * | T1053      | none     | drafted   | active   | huntable                          |
 * | T1053.005  | partial  | scheduled | stale    | detected + rule_no_telemetry      |
 * | T1136      | none     | none      | unmapped | unmapped (no data sources at all) |
 * | T1136.001  | none     | none      | active   | huntable                          |
 * | T1027      | none     | none      | stale    | blind                             |
 * | T1003      | off      | none      | missing  | blind (paused rule is not live)   |
 * | T1003.001  | none     | none      | missing  | blind, recon regressed_to_blind   |
 * | T1021      | none     | hunted    | active   | hunted                            |
 * | T1021.002  | none     | hunted    | active   | hunted; idea ready; 2 findings from T1021 hunts |
 * | T1685      | full     | hunted    | active   | both (hunt stored as T1562.001, alias-resolved) |
 * | T1071      | partial  | none      | unmapped | detected (unmapped is not rule_no_telemetry) |
 * | T1071.001  | none     | none      | unmapped | unmapped                          |
 * | T1105      | none     | hunted    | stale    | hunted at 30d; blind at 7d (last sweep 9 days ago) |
 */
import type { HuntTechniqueCoverageResponse } from '../hunt-layer-types';
import type { MitreCoverageResponse, RequiredDataSource } from '../types';

const NOW = '2026-11-22T21:40:00Z';
const SEEN_ACTIVE = '2026-11-22T21:35:00Z';
const SEEN_STALE = '2026-11-20T04:10:00Z';

type DsState = 'active' | 'stale' | 'missing' | 'unmapped';

function ds(name: string, state: DsState, sourceTypes: string[]): RequiredDataSource {
  const id = name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
  if (state === 'unmapped') {
    return { id, name, mapping_known: false, configured: false, readiness: 'unknown', last_seen_at: null, connected: false, source_types: [] };
  }
  if (state === 'missing') {
    return { id, name, mapping_known: true, configured: false, readiness: 'unknown', last_seen_at: null, connected: false, source_types: sourceTypes };
  }
  const active = state === 'active';
  return {
    id,
    name,
    mapping_known: true,
    configured: true,
    readiness: active ? 'active' : 'stale',
    last_seen_at: active ? SEEN_ACTIVE : SEEN_STALE,
    connected: active,
    source_types: sourceTypes,
  };
}

// v19 data-component names and their nano source types (data_sources.rs).
const PROCESS_CREATION = ds('Process Creation', 'active', ['windows_sysmon', 'linux_auditd', 'microsoft_sysmon__json_']);
const COMMAND_EXECUTION = ds('Command Execution', 'stale', ['windows_sysmon', 'linux_auditd']);
const SCRIPT_EXECUTION = ds('Script Execution', 'stale', ['windows_sysmon', 'linux_auditd']);
const FILE_CREATION = ds('File Creation', 'stale', ['windows_sysmon', 'linux_auditd']);
const SCHEDULED_JOB_CREATION = ds('Scheduled Job Creation', 'unmapped', []);
const PROCESS_ACCESS = ds('Process Access', 'missing', ['windows_sysmon', 'microsoft_defender_for_endpoint']);
const MODULE_LOAD = ds('Module Load', 'missing', ['windows_sysmon']);
const REGISTRY_KEY_MODIFICATION = ds('Windows Registry Key Modification', 'missing', ['windows_sysmon']);
const NETWORK_SHARE_ACCESS = ds('Network Share Access', 'active', ['windows_sysmon', 'windows_event_log']);
const LOGON_SESSION_CREATION = ds('Logon Session Creation', 'active', ['windows_event_log', 'okta', 'azure_ad']);
const USER_ACCOUNT_CREATION = ds('User Account Creation', 'active', ['windows_event_log', 'okta', 'azure_ad', 'aws_cloudtrail', 'linux_auditd']);
const NETWORK_CONNECTION_CREATION = ds('Network Connection Creation', 'missing', ['netflow']);
const NETWORK_TRAFFIC_CONTENT = ds('Network Traffic Content', 'missing', ['netflow', 'squid_proxy', 'conduit_mitm_proxy']);
const MALWARE_CONTENT = ds('Malware Content', 'unmapped', []);

const R_PS_ENCODED = { id: '0193f1a2-0001-7000-8000-000000000001', name: 'powershell_encoded_command', severity: 'critical', mode: 'alerting', source: 'windows_sysmon' };
const R_PS_CRADLE = { id: '0193f1a2-0002-7000-8000-000000000002', name: 'powershell_download_cradle', severity: 'high', mode: 'live', source: 'microsoft_sysmon__json_' };
const R_CMD_OFFICE = { id: '0193f1a2-0003-7000-8000-000000000003', name: 'cmd_spawned_by_office', severity: 'medium', mode: 'staging', source: 'microsoft_sysmon__json_' };
const R_SCHTASKS = { id: '0193f1a2-0004-7000-8000-000000000004', name: 'schtasks_remote_create', severity: 'high', mode: 'alerting', source: 'windows_event_log' };
const R_LSASS = { id: '0193f1a2-0005-7000-8000-000000000005', name: 'lsass_dump_procdump', severity: 'high', mode: 'paused', source: 'windows_sysmon' };
const R_DEFENDER = { id: '0193f1a2-0006-7000-8000-000000000006', name: 'defender_tamper_registry', severity: 'critical', mode: 'alerting', source: 'microsoft_sysmon__json_' };
const R_AV_STOPPED = { id: '0193f1a2-0007-7000-8000-000000000007', name: 'av_service_stopped', severity: 'high', mode: 'live', source: 'windows_event_log' };
const R_BEACON = { id: '0193f1a2-0008-7000-8000-000000000008', name: 'beacon_jitter_http', severity: 'medium', mode: 'live', source: 'netflow' };

export const unifiedCoverageFixture: { coverage: MitreCoverageResponse; hunts: HuntTechniqueCoverageResponse; hunts7d: HuntTechniqueCoverageResponse } = {
  coverage: {
    tactics: [
      { tactic_id: 'TA0002', tactic_name: 'Execution', short_name: 'execution', total_techniques: 5, covered_techniques: 3 },
      { tactic_id: 'TA0003', tactic_name: 'Persistence', short_name: 'persistence', total_techniques: 4, covered_techniques: 1 },
      { tactic_id: 'TA0005', tactic_name: 'Stealth', short_name: 'stealth', total_techniques: 1, covered_techniques: 0 },
      { tactic_id: 'TA0006', tactic_name: 'Credential Access', short_name: 'credential-access', total_techniques: 2, covered_techniques: 0 },
      { tactic_id: 'TA0008', tactic_name: 'Lateral Movement', short_name: 'lateral-movement', total_techniques: 2, covered_techniques: 0 },
      { tactic_id: 'TA0011', tactic_name: 'Command and Control', short_name: 'command-and-control', total_techniques: 3, covered_techniques: 1 },
      { tactic_id: 'TA0112', tactic_name: 'Defense Impairment', short_name: 'defense-impairment', total_techniques: 1, covered_techniques: 1 },
    ],
    techniques: [
      { technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter', is_subtechnique: false, tactic_ids: ['TA0002'], rule_count: 1, coverage_level: 'low', rules: [R_PS_ENCODED], data_sources: [PROCESS_CREATION, COMMAND_EXECUTION] },
      { technique_id: 'T1059.001', technique_name: 'PowerShell', is_subtechnique: true, parent_id: 'T1059', tactic_ids: ['TA0002'], rule_count: 2, coverage_level: 'medium', rules: [R_PS_ENCODED, R_PS_CRADLE], data_sources: [PROCESS_CREATION, SCRIPT_EXECUTION, MODULE_LOAD] },
      { technique_id: 'T1059.003', technique_name: 'Windows Command Shell', is_subtechnique: true, parent_id: 'T1059', tactic_ids: ['TA0002'], rule_count: 1, coverage_level: 'low', rules: [R_CMD_OFFICE], data_sources: [PROCESS_CREATION, COMMAND_EXECUTION] },
      { technique_id: 'T1053', technique_name: 'Scheduled Task/Job', is_subtechnique: false, tactic_ids: ['TA0002', 'TA0003'], rule_count: 0, coverage_level: 'none', rules: [], data_sources: [SCHEDULED_JOB_CREATION, PROCESS_CREATION] },
      { technique_id: 'T1053.005', technique_name: 'Scheduled Task', is_subtechnique: true, parent_id: 'T1053', tactic_ids: ['TA0002', 'TA0003'], rule_count: 1, coverage_level: 'low', rules: [R_SCHTASKS], data_sources: [SCHEDULED_JOB_CREATION, COMMAND_EXECUTION] },
      { technique_id: 'T1136', technique_name: 'Create Account', is_subtechnique: false, tactic_ids: ['TA0003'], rule_count: 0, coverage_level: 'none', rules: [], data_sources: [] },
      { technique_id: 'T1136.001', technique_name: 'Local Account', is_subtechnique: true, parent_id: 'T1136', tactic_ids: ['TA0003'], rule_count: 0, coverage_level: 'none', rules: [], data_sources: [USER_ACCOUNT_CREATION, COMMAND_EXECUTION] },
      { technique_id: 'T1027', technique_name: 'Obfuscated Files or Information', is_subtechnique: false, tactic_ids: ['TA0005'], rule_count: 0, coverage_level: 'none', rules: [], data_sources: [FILE_CREATION, MODULE_LOAD] },
      { technique_id: 'T1003', technique_name: 'OS Credential Dumping', is_subtechnique: false, tactic_ids: ['TA0006'], rule_count: 1, coverage_level: 'low', rules: [R_LSASS], data_sources: [PROCESS_ACCESS] },
      { technique_id: 'T1003.001', technique_name: 'LSASS Memory', is_subtechnique: true, parent_id: 'T1003', tactic_ids: ['TA0006'], rule_count: 0, coverage_level: 'none', rules: [], data_sources: [PROCESS_ACCESS, MODULE_LOAD] },
      { technique_id: 'T1021', technique_name: 'Remote Services', is_subtechnique: false, tactic_ids: ['TA0008'], rule_count: 0, coverage_level: 'none', rules: [], data_sources: [LOGON_SESSION_CREATION, NETWORK_CONNECTION_CREATION] },
      { technique_id: 'T1021.002', technique_name: 'SMB/Windows Admin Shares', is_subtechnique: true, parent_id: 'T1021', tactic_ids: ['TA0008'], rule_count: 0, coverage_level: 'none', rules: [], data_sources: [NETWORK_SHARE_ACCESS, LOGON_SESSION_CREATION] },
      { technique_id: 'T1685', technique_name: 'Disable or Modify Tools', is_subtechnique: false, tactic_ids: ['TA0112'], rule_count: 2, coverage_level: 'medium', rules: [R_DEFENDER, R_AV_STOPPED], data_sources: [PROCESS_CREATION, REGISTRY_KEY_MODIFICATION] },
      { technique_id: 'T1071', technique_name: 'Application Layer Protocol', is_subtechnique: false, tactic_ids: ['TA0011'], rule_count: 1, coverage_level: 'low', rules: [R_BEACON], data_sources: [MALWARE_CONTENT] },
      { technique_id: 'T1071.001', technique_name: 'Web Protocols', is_subtechnique: true, parent_id: 'T1071', tactic_ids: ['TA0011'], rule_count: 0, coverage_level: 'none', rules: [], data_sources: [MALWARE_CONTENT] },
      { technique_id: 'T1105', technique_name: 'Ingress Tool Transfer', is_subtechnique: false, tactic_ids: ['TA0011'], rule_count: 0, coverage_level: 'none', rules: [], data_sources: [NETWORK_TRAFFIC_CONTENT, NETWORK_CONNECTION_CREATION, FILE_CREATION] },
    ],
    summary: {
      coverage_unit: 'technique',
      total_techniques: 16,
      covered_techniques: 5,
      coverage_percentage: 31.25,
      total_rules_with_mitre: 8,
    },
  },

  hunts: {
    window_days: 30,
    since: '2026-10-23T21:40:00Z',
    generated_at: NOW,
    recon: {
      last_run_at: '2026-11-22T18:40:00Z',
      next_run_at: '2026-11-23T18:40:00Z',
      degraded: false,
      regressed_to_blind: ['T1003.001'],
    },
    techniques: [
      {
        technique_id: 'T1021',
        hunts_total: 1,
        hunts_enabled: 1,
        hunts: [
          { id: 'pb_01jdz0000000000000000t1021', title: 'Remote service logons from new hosts', enabled: true, schedule_cron: '0 6 * * *', last_success_at: '2026-11-22T06:04:00Z', sweeps_window: 30, findings_window: 6 },
        ],
        last_hunted_at: '2026-11-22T06:04:00Z',
        sweeps_window: 30,
        findings_window: { lead: 1, benign: 3, duplicate: 0, escalated: 0 },
        findings_from_other_hunts: 0,
        rule_ideas: { keep_hunting: 0, ready: 0, sent: 0 },
      },
      {
        // 2 of these 4 findings were filed by the T1021 hunt above (the
        // agent found SMB admin-share use while hunting remote services), so
        // the T1021 hunt's own `findings_window` (6) is larger than T1021's (4).
        technique_id: 'T1021.002',
        hunts_total: 1,
        hunts_enabled: 1,
        hunts: [
          { id: 'pb_01jdz000000000000000t1021b', title: 'Admin share writes outside patch windows', enabled: true, schedule_cron: '30 2 * * *', last_success_at: '2026-11-22T02:31:00Z', sweeps_window: 30, findings_window: 2 },
        ],
        last_hunted_at: '2026-11-22T02:31:00Z',
        sweeps_window: 30,
        findings_window: { lead: 2, benign: 1, duplicate: 0, escalated: 1 },
        findings_from_other_hunts: 2,
        rule_ideas: { keep_hunting: 0, ready: 1, sent: 0 },
      },
      {
        technique_id: 'T1053',
        hunts_total: 1,
        hunts_enabled: 0,
        hunts: [
          { id: 'pb_01jdz0000000000000000t1053', title: 'Scheduled jobs created by service accounts', enabled: false, schedule_cron: null, last_success_at: null, sweeps_window: 0, findings_window: 0 },
        ],
        last_hunted_at: null,
        sweeps_window: 0,
        findings_window: { lead: 0, benign: 0, duplicate: 0, escalated: 0 },
        findings_from_other_hunts: 0,
        rule_ideas: { keep_hunting: 0, ready: 0, sent: 0 },
      },
      {
        technique_id: 'T1053.005',
        hunts_total: 1,
        hunts_enabled: 1,
        hunts: [
          { id: 'pb_01jdz0000000000000t1053005', title: 'Remote schtasks creation', enabled: true, schedule_cron: '0 */6 * * *', last_success_at: null, sweeps_window: 0, findings_window: 0 },
        ],
        last_hunted_at: null,
        sweeps_window: 0,
        findings_window: { lead: 0, benign: 0, duplicate: 0, escalated: 0 },
        findings_from_other_hunts: 0,
        rule_ideas: { keep_hunting: 0, ready: 0, sent: 0 },
      },
      {
        technique_id: 'T1059.001',
        hunts_total: 3,
        hunts_enabled: 2,
        hunts: [
          { id: 'pb_01jdz0000000000000t1059001', title: 'PowerShell download cradles', enabled: true, schedule_cron: '0 * * * *', last_success_at: '2026-11-22T21:02:00Z', sweeps_window: 712, findings_window: 9 },
          { id: 'pb_01jdz000000000000t1059001b', title: 'Encoded PowerShell from Office parents', enabled: true, schedule_cron: '15 * * * *', last_success_at: '2026-11-22T21:16:00Z', sweeps_window: 698, findings_window: 3 },
          { id: 'pb_01jdz000000000000t1059001c', title: 'AMSI bypass strings', enabled: false, schedule_cron: null, last_success_at: '2026-10-02T11:00:00Z', sweeps_window: 0, findings_window: 0 },
        ],
        last_hunted_at: '2026-11-22T21:16:00Z',
        sweeps_window: 1410,
        findings_window: { lead: 4, benign: 6, duplicate: 1, escalated: 1 },
        findings_from_other_hunts: 0,
        rule_ideas: { keep_hunting: 0, ready: 0, sent: 1 },
      },
      {
        technique_id: 'T1105',
        hunts_total: 1,
        hunts_enabled: 1,
        hunts: [
          { id: 'pb_01jdz0000000000000000t1105', title: 'Tool downloads to temp paths', enabled: true, schedule_cron: '0 3 * * 0', last_success_at: '2026-11-13T03:07:00Z', sweeps_window: 4, findings_window: 1 },
        ],
        last_hunted_at: '2026-11-13T03:07:00Z',
        sweeps_window: 4,
        findings_window: { lead: 1, benign: 0, duplicate: 0, escalated: 0 },
        findings_from_other_hunts: 0,
        rule_ideas: { keep_hunting: 1, ready: 0, sent: 0 },
      },
      {
        // The hunt's spec still says T1562.001 (ATT&CK v18); the server
        // resolved it through mitre_technique_aliases to the v19 id.
        technique_id: 'T1685',
        hunts_total: 1,
        hunts_enabled: 1,
        hunts: [
          { id: 'pb_01jdz0000000000000000t1685', title: 'Security tooling tampering', enabled: true, schedule_cron: '0 4 * * *', last_success_at: '2026-11-22T04:05:00Z', sweeps_window: 30, findings_window: 2 },
        ],
        last_hunted_at: '2026-11-22T04:05:00Z',
        sweeps_window: 30,
        findings_window: { lead: 0, benign: 2, duplicate: 0, escalated: 0 },
        findings_from_other_hunts: 0,
        rule_ideas: { keep_hunting: 0, ready: 0, sent: 0 },
      },
    ],
    unattributed: { hunts: 1, findings_window: 3, rule_ideas: 0 },
  },

  hunts7d: {
    window_days: 7,
    since: '2026-11-15T21:40:00Z',
    generated_at: NOW,
    recon: {
      last_run_at: '2026-11-22T18:40:00Z',
      next_run_at: '2026-11-23T18:40:00Z',
      degraded: false,
      regressed_to_blind: ['T1003.001'],
    },
    techniques: [
      {
        technique_id: 'T1021',
        hunts_total: 1,
        hunts_enabled: 1,
        hunts: [
          { id: 'pb_01jdz0000000000000000t1021', title: 'Remote service logons from new hosts', enabled: true, schedule_cron: '0 6 * * *', last_success_at: '2026-11-22T06:04:00Z', sweeps_window: 7, findings_window: 2 },
        ],
        last_hunted_at: '2026-11-22T06:04:00Z',
        sweeps_window: 7,
        findings_window: { lead: 0, benign: 1, duplicate: 0, escalated: 0 },
        findings_from_other_hunts: 0,
        rule_ideas: { keep_hunting: 0, ready: 0, sent: 0 },
      },
      {
        technique_id: 'T1021.002',
        hunts_total: 1,
        hunts_enabled: 1,
        hunts: [
          { id: 'pb_01jdz000000000000000t1021b', title: 'Admin share writes outside patch windows', enabled: true, schedule_cron: '30 2 * * *', last_success_at: '2026-11-22T02:31:00Z', sweeps_window: 7, findings_window: 1 },
        ],
        last_hunted_at: '2026-11-22T02:31:00Z',
        sweeps_window: 7,
        findings_window: { lead: 1, benign: 0, duplicate: 0, escalated: 1 },
        findings_from_other_hunts: 1,
        rule_ideas: { keep_hunting: 0, ready: 1, sent: 0 },
      },
      {
        technique_id: 'T1053',
        hunts_total: 1,
        hunts_enabled: 0,
        hunts: [
          { id: 'pb_01jdz0000000000000000t1053', title: 'Scheduled jobs created by service accounts', enabled: false, schedule_cron: null, last_success_at: null, sweeps_window: 0, findings_window: 0 },
        ],
        last_hunted_at: null,
        sweeps_window: 0,
        findings_window: { lead: 0, benign: 0, duplicate: 0, escalated: 0 },
        findings_from_other_hunts: 0,
        rule_ideas: { keep_hunting: 0, ready: 0, sent: 0 },
      },
      {
        technique_id: 'T1053.005',
        hunts_total: 1,
        hunts_enabled: 1,
        hunts: [
          { id: 'pb_01jdz0000000000000t1053005', title: 'Remote schtasks creation', enabled: true, schedule_cron: '0 */6 * * *', last_success_at: null, sweeps_window: 0, findings_window: 0 },
        ],
        last_hunted_at: null,
        sweeps_window: 0,
        findings_window: { lead: 0, benign: 0, duplicate: 0, escalated: 0 },
        findings_from_other_hunts: 0,
        rule_ideas: { keep_hunting: 0, ready: 0, sent: 0 },
      },
      {
        technique_id: 'T1059.001',
        hunts_total: 3,
        hunts_enabled: 2,
        hunts: [
          { id: 'pb_01jdz0000000000000t1059001', title: 'PowerShell download cradles', enabled: true, schedule_cron: '0 * * * *', last_success_at: '2026-11-22T21:02:00Z', sweeps_window: 166, findings_window: 2 },
          { id: 'pb_01jdz000000000000t1059001b', title: 'Encoded PowerShell from Office parents', enabled: true, schedule_cron: '15 * * * *', last_success_at: '2026-11-22T21:16:00Z', sweeps_window: 165, findings_window: 1 },
          { id: 'pb_01jdz000000000000t1059001c', title: 'AMSI bypass strings', enabled: false, schedule_cron: null, last_success_at: '2026-10-02T11:00:00Z', sweeps_window: 0, findings_window: 0 },
        ],
        last_hunted_at: '2026-11-22T21:16:00Z',
        sweeps_window: 331,
        findings_window: { lead: 1, benign: 2, duplicate: 0, escalated: 0 },
        findings_from_other_hunts: 0,
        rule_ideas: { keep_hunting: 0, ready: 0, sent: 1 },
      },
      {
        // Weekly hunt, last swept 9 days ago: in the 30 day window, not in 7.
        technique_id: 'T1105',
        hunts_total: 1,
        hunts_enabled: 1,
        hunts: [
          { id: 'pb_01jdz0000000000000000t1105', title: 'Tool downloads to temp paths', enabled: true, schedule_cron: '0 3 * * 0', last_success_at: '2026-11-13T03:07:00Z', sweeps_window: 0, findings_window: 0 },
        ],
        last_hunted_at: '2026-11-13T03:07:00Z',
        sweeps_window: 0,
        findings_window: { lead: 0, benign: 0, duplicate: 0, escalated: 0 },
        findings_from_other_hunts: 0,
        rule_ideas: { keep_hunting: 1, ready: 0, sent: 0 },
      },
      {
        technique_id: 'T1685',
        hunts_total: 1,
        hunts_enabled: 1,
        hunts: [
          { id: 'pb_01jdz0000000000000000t1685', title: 'Security tooling tampering', enabled: true, schedule_cron: '0 4 * * *', last_success_at: '2026-11-22T04:05:00Z', sweeps_window: 7, findings_window: 0 },
        ],
        last_hunted_at: '2026-11-22T04:05:00Z',
        sweeps_window: 7,
        findings_window: { lead: 0, benign: 0, duplicate: 0, escalated: 0 },
        findings_from_other_hunts: 0,
        rule_ideas: { keep_hunting: 0, ready: 0, sent: 0 },
      },
    ],
    unattributed: { hunts: 1, findings_window: 0, rule_ideas: 0 },
  },
};

/** The hook's `data` for a fixture body: technique id to layer. */
export function fixtureHuntLayerMap(body: HuntTechniqueCoverageResponse) {
  return new Map(body.techniques.map((t) => [t.technique_id, t] as const));
}
