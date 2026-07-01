// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * UDM (Unified Data Model) field definitions
 *
 * AUTO-GENERATED — do not edit manually.
 * Source: nanosiem-core/docs/udmfields.csv (511 fields)
 * Regenerate: npm run generate:udm
 */

export const UDM_COLUMNS = new Set([
  // === UDM Fields (from udmfields.csv) ===
  'additional_answer_count', 'ai_confidence', 'ai_reasoning', 'ai_verdict', 'answer',
  'answer_count', 'app', 'app_id', 'array', 'auth_result', 'auth_type',
  'authentication_method', 'authentication_service', 'authority_answer_count', 'availability',
  'avg_executions', 'blocksize', 'buffer_cache_hit_ratio', 'bugtraq', 'bytes', 'bytes_in',
  'bytes_out', 'cached', 'category', 'cert', 'change_type', 'channel', 'cloud_account_id',
  'cloud_account_name', 'cloud_provider', 'cloud_region', 'cloud_service', 'cluster',
  'command', 'command_line', 'commits', 'cookie', 'cpu_cores', 'cpu_count', 'cpu_load_mhz',
  'cpu_load_percent', 'cpu_mhz', 'cpu_used', 'cpu_user_percent', 'creation_time', 'cursor',
  'custom_dest_ip_risk', 'custom_dest_ip_tags', 'custom_domain_risk', 'custom_domain_tags',
  'custom_hash_risk', 'custom_hash_tags', 'custom_ioc_dest_ip_confidence',
  'custom_ioc_dest_ip_malware', 'custom_ioc_dest_ip_threat_type',
  'custom_ioc_domain_confidence', 'custom_ioc_domain_threat_type',
  'custom_ioc_hash_confidence', 'custom_ioc_hash_threat_type', 'custom_ioc_src_ip_confidence',
  'custom_ioc_src_ip_malware', 'custom_ioc_src_ip_threat_type', 'custom_src_ip_risk',
  'custom_src_ip_tags', 'custom_url_risk', 'custom_url_tags', 'cve', 'cvss', 'date', 'delay',
  'description', 'dest', 'dest_dns', 'dest_host', 'dest_interface', 'dest_ip',
  'dest_ip_range', 'dest_mac', 'dest_name', 'dest_nt_domain', 'dest_nt_host', 'dest_port',
  'dest_port_range', 'dest_translated_ip', 'dest_translated_port', 'dest_type', 'dest_url',
  'dest_user', 'dest_user_identity_account_status', 'dest_user_identity_company',
  'dest_user_identity_country', 'dest_user_identity_department',
  'dest_user_identity_display_name', 'dest_user_identity_email',
  'dest_user_identity_employee_id', 'dest_user_identity_employee_type',
  'dest_user_identity_groups', 'dest_user_identity_manager', 'dest_user_identity_manager_upn',
  'dest_user_identity_mfa_enabled', 'dest_user_identity_office_location',
  'dest_user_identity_phone', 'dest_user_identity_title', 'dest_zone', 'direction',
  'dlp_type', 'dns', 'dns_answers', 'dump_area_used', 'duration', 'dvc', 'dvc_ip', 'dvc_mac',
  'dvc_zone', 'elapsed_time', 'email', 'enabled', 'enrich_time', 'enriched_dest_as_domain',
  'enriched_dest_as_name', 'enriched_dest_asn', 'enriched_dest_continent',
  'enriched_dest_continent_code', 'enriched_dest_country', 'enriched_dest_country_code',
  'enriched_src_as_domain', 'enriched_src_as_name', 'enriched_src_asn',
  'enriched_src_continent', 'enriched_src_continent_code', 'enriched_src_country',
  'enriched_src_country_code', 'error_code', 'event_type', 'ext', 'family', 'fan_speed',
  'fd_max', 'fd_used', 'file_access_time', 'file_acl', 'file_action', 'file_create_time',
  'file_hash', 'file_modify_time', 'file_name', 'file_path', 'file_size', 'filter_action',
  'filter_score', 'flow_id', 'free_bytes', 'http_content_type', 'http_method',
  'http_referrer', 'http_referrer_domain', 'http_status_code', 'http_user_agent',
  'http_user_agent_length', 'hypervisor', 'hypervisor_id', 'icmp_code', 'icmp_type', 'id',
  'ids_type', 'image_id', 'indexes_hit', 'ingest_time', 'inline_nat', 'instance_name',
  'instance_reads', 'instance_type', 'instance_version', 'instance_writes', 'interactive',
  'interface', 'internal_message_id', 'ioc_confidence', 'ioc_dest_ip_confidence',
  'ioc_dest_ip_malware', 'ioc_dest_ip_threat_type', 'ioc_domain_confidence',
  'ioc_domain_malware', 'ioc_domain_threat_type', 'ioc_hash_confidence', 'ioc_hash_malware',
  'ioc_hash_threat_type', 'ioc_matched', 'ioc_source', 'ioc_src_ip_confidence',
  'ioc_src_ip_malware', 'ioc_src_ip_threat_type', 'ioc_tags', 'ip', 'last_call_minute',
  'latency', 'lb_method', 'lease_duration', 'lease_scope', 'lock_mode', 'lock_session_id',
  'logical_reads', 'logon_time', 'mac', 'machine', 'mem', 'mem_committed', 'mem_free',
  'mem_used', 'memory_sorts', 'message', 'message_id', 'message_info', 'metadata', 'mfa_used',
  'mitre_technique_id', 'mount', 'msft', 'mskb', 'name', 'namespace', 'node', 'node_port',
  'number_of_users', 'obj_name', 'object', 'object_attrs', 'object_category', 'object_id',
  'object_path', 'object_size', 'operation', 'orig_dest', 'orig_recipient', 'orig_src',
  'original_file_name', 'os', 'os_pid', 'owner', 'owner_email', 'owner_id', 'packets',
  'packets_in', 'packets_out', 'parent', 'parent_command_line', 'parent_object',
  'parent_object_category', 'parent_object_id', 'parent_process_exec', 'parent_process_guid',
  'parent_process_id', 'parent_process_name', 'parent_process_path', 'password',
  'physical_reads', 'power', 'prevalence_dest_domain', 'prevalence_dest_ip',
  'prevalence_file_hash', 'prevalence_min', 'prevalence_process_hash',
  'process_current_directory', 'process_exec', 'process_guid', 'process_hash', 'process_id',
  'process_integrity_level', 'process_limit', 'process_name', 'process_path', 'processes',
  'product', 'product_version', 'protocol', 'protocol_version', 'query', 'query_count',
  'query_id', 'query_plan_hit', 'query_time', 'query_type', 'read_blocks', 'read_latency',
  'read_ops', 'reason', 'recipient', 'recipient_count', 'recipient_domain',
  'recipient_status', 'record_type', 'records_affected', 'registry_hive', 'registry_key_name',
  'registry_path', 'registry_value_data', 'registry_value_name', 'registry_value_text',
  'registry_value_type', 'reply_code', 'reply_code_id', 'resource_id', 'resource_name',
  'resource_type', 'response_time', 'result', 'result_id', 'retries', 'return_addr',
  'risk_entity', 'risk_level', 'risk_score', 'rule', 'rule_action', 'rule_id', 'rule_name',
  'seconds_in_wait', 'sender', 'sender_domain', 'serial', 'serial_num', 'service',
  'service_dll', 'service_dll_hash', 'service_dll_path', 'service_dll_signature_exists',
  'service_dll_signature_verified', 'service_exec', 'service_hash', 'service_id',
  'service_name', 'service_path', 'service_signature_exists', 'service_signature_verified',
  'session_id', 'session_limit', 'session_status', 'sessions', 'severity', 'severity_id',
  'sga_buffer_cache_size', 'sga_buffer_hit_limit', 'sga_data_dict_hit_ratio',
  'sga_fixed_area_size', 'sga_free_memory', 'sga_library_cache_size',
  'sga_redo_log_buffer_size', 'sga_shared_pool_size', 'sga_sql_area_size', 'shell',
  'signature', 'signature_extra', 'signature_id', 'signature_version', 'site', 'size',
  'snapshot', 'source', 'source_type', 'span_id', 'src', 'src_dns', 'src_host',
  'src_interface', 'src_ip', 'src_ip_range', 'src_mac', 'src_nt_domain', 'src_nt_host',
  'src_port', 'src_port_range', 'src_translated_ip', 'src_translated_port', 'src_type',
  'src_user', 'src_user_domain', 'src_user_id', 'src_user_identity_account_status',
  'src_user_identity_company', 'src_user_identity_country', 'src_user_identity_department',
  'src_user_identity_display_name', 'src_user_identity_email',
  'src_user_identity_employee_id', 'src_user_identity_employee_type',
  'src_user_identity_groups', 'src_user_identity_manager', 'src_user_identity_manager_upn',
  'src_user_identity_mfa_enabled', 'src_user_identity_office_location',
  'src_user_identity_phone', 'src_user_identity_title', 'src_user_name', 'src_user_role',
  'src_user_type', 'src_zone', 'ssid', 'ssl_end_time', 'ssl_engine', 'ssl_hash',
  'ssl_is_valid', 'ssl_issuer', 'ssl_issuer_common_name', 'ssl_issuer_email',
  'ssl_issuer_email_domain', 'ssl_issuer_locality', 'ssl_issuer_organization',
  'ssl_issuer_state', 'ssl_issuer_street', 'ssl_issuer_unit', 'ssl_name', 'ssl_policies',
  'ssl_publickey', 'ssl_publickey_algorithm', 'ssl_serial', 'ssl_session_id',
  'ssl_signature_algorithm', 'ssl_start_time', 'ssl_subject', 'ssl_subject_common_name',
  'ssl_subject_email', 'ssl_subject_email_domain', 'ssl_subject_locality',
  'ssl_subject_organization', 'ssl_subject_state', 'ssl_subject_street', 'ssl_subject_unit',
  'ssl_validity_window', 'ssl_version', 'start_mode', 'start_time', 'state', 'status',
  'status_code', 'storage', 'storage_free', 'storage_free_percent', 'storage_name',
  'storage_used', 'storage_used_percent', 'stored_procedures_called', 'subject', 'swap',
  'swap_free', 'swap_used', 'table_scans', 'tables_hit', 'tablespace_name',
  'tablespace_reads', 'tablespace_status', 'tablespace_used', 'tablespace_writes', 'tag',
  'tags', 'tcp_flag', 'temperature', 'thruput', 'thruput_max', 'time', 'timestamp', 'tos',
  'trace_id', 'transaction_id', 'transport', 'transport_dest_port', 'ttl', 'type', 'uri_path',
  'uri_query', 'url', 'url_domain', 'url_length', 'user', 'user_agent', 'user_domain',
  'user_group', 'user_id', 'user_identity_account_status', 'user_identity_company',
  'user_identity_country', 'user_identity_department', 'user_identity_display_name',
  'user_identity_email', 'user_identity_employee_id', 'user_identity_employee_type',
  'user_identity_groups', 'user_identity_manager', 'user_identity_manager_upn',
  'user_identity_mfa_enabled', 'user_identity_office_location', 'user_identity_phone',
  'user_identity_title', 'user_name', 'user_role', 'user_type', 'vendor', 'vendor_account',
  'vendor_product', 'vendor_product_id', 'vendor_region', 'version', 'vip_port', 'vlan',
  'wait_state', 'wait_time', 'wifi', 'write_blocks', 'write_latency', 'write_ops', 'xdelay',
  'xref',

  // === Additional system/computed fields ===
  '_time', '_inserted_at', 'first_seen', 'last_seen', 'count', 'raw_risk_score',
  'domain_prevalence', 'domain_first_seen', 'domain_last_seen',
]);

/**
 * Check if a field name is a UDM column (stored as explicit column in ClickHouse)
 */
export function isUdmColumn(fieldName: string): boolean {
  return UDM_COLUMNS.has(fieldName);
}

/** Canonical UDM field names, sorted alphabetically. */
export const UDM_FIELD_LIST: readonly string[] = Object.freeze(
  Array.from(UDM_COLUMNS).sort((a, b) => a.localeCompare(b)),
);

/**
 * Return UDM field names whose start matches `prefix` (case-insensitive).
 * Empty `prefix` returns the full sorted list. Result is capped at `limit`.
 */
export function filterUdmFields(prefix: string, limit = 12): string[] {
  const needle = prefix.toLowerCase();
  if (!needle) return UDM_FIELD_LIST.slice(0, limit);
  const out: string[] = [];
  for (const name of UDM_FIELD_LIST) {
    if (name.toLowerCase().startsWith(needle)) {
      out.push(name);
      if (out.length >= limit) break;
    }
  }
  return out;
}

/**
 * Prefix-filter the union of UDM field names and the active schema's field names
 * (NAN-1241). Under UDM (`extraFields` empty/undefined) this is byte-identical to
 * `filterUdmFields`; under OCSF the promoted columns (`src_endpoint.ip`, …) are
 * offered too. The union is sorted, de-duplicated, and matched both on the full
 * name and on the dotted leaf so a partial leaf still suggests dotted columns.
 */
export function filterFieldsWithSchema(
  prefix: string,
  extraFields: readonly string[] | undefined,
  limit = 12,
): string[] {
  if (!extraFields || extraFields.length === 0) {
    return filterUdmFields(prefix, limit);
  }
  const seen = new Set(UDM_FIELD_LIST);
  const merged = [...UDM_FIELD_LIST];
  for (const f of extraFields) {
    if (!seen.has(f)) {
      seen.add(f);
      merged.push(f);
    }
  }
  merged.sort((a, b) => a.localeCompare(b));

  const needle = prefix.toLowerCase();
  if (!needle) return merged.slice(0, limit);
  const out: string[] = [];
  for (const name of merged) {
    const lower = name.toLowerCase();
    const dot = lower.lastIndexOf('.');
    const leaf = dot >= 0 ? lower.slice(dot + 1) : '';
    if (lower.startsWith(needle) || (leaf && leaf.startsWith(needle))) {
      out.push(name);
      if (out.length >= limit) break;
    }
  }
  return out;
}
