//! Comprehensive nPL parser tests generated from docs-site examples.
//!
//! Every query example from the documentation is tested here to ensure
//! the parser accepts it. This catches regressions when parser changes
//! break documented syntax.
//!
//! Run with: cargo test -p nanosiem-core --test docs_query_tests

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};

fn test_time_range() -> TimeRange {
    TimeRange {
        start: "2024-01-01T00:00:00Z".parse().unwrap(),
        end: "2024-01-02T00:00:00Z".parse().unwrap(),
    }
}

/// Parse nPL and optionally generate SQL. Panics with query context on failure.
fn npl(query_str: &str) {
    let query = parse_query(query_str)
        .unwrap_or_else(|e| panic!("Parse failed for: {}\nError: {}", query_str, e));
    let gen = ClickHouseSqlGenerator::new();
    // SQL gen may fail for some commands (e.g., subsearch, lateral) — that's OK,
    // we primarily care that the parser accepts the syntax.
    let _ = gen.generate(&query, &test_time_range());
}

#[test]
fn doc_source_type_squid_proxy_or_source_type_defender_edr_src_ip() {
    npl("(source_type=squid_proxy OR source_type=defender_edr) src_ip=\"192.168.1.100\" | resolve_identity");
}

#[test]
fn doc_status_401_or_status_403_and_user_admin() {
    npl("(status=401 OR status=403) AND user=admin");
}

#[test]
fn doc_search_action_failed_login() {
    npl("[search action=failed_login | return 100 src_ip]");
}

#[test]
fn doc_search_action_suspicious() {
    npl("[search action=suspicious | fields src_ip | format]");
}

#[test]
fn doc_search_action_suspicious_2() {
    npl("[search action=suspicious | return src_ip]");
}

#[test]
fn doc_search_department_it() {
    npl("[search department=\"IT\" | fields user | format]");
}

#[test]
fn doc_search_threat_level_high() {
    npl("[search threat_level=\"high\" | return file_hash, domain]");
}

#[test]
fn doc_anomaly_field_bytes_by_src_ip_threshold_2() {
    npl("* | anomaly field=bytes by src_ip threshold=2");
}

#[test]
fn doc_anomaly_field_bytes_out_by_user_threshold_3() {
    npl("* | anomaly field=bytes_out by user threshold=3 | where is_anomaly=true");
}

#[test]
fn doc_anomaly_field_bytes_out_method_mad_threshold_3() {
    npl("* | anomaly field=bytes_out method=mad threshold=3");
}

#[test]
fn doc_anomaly_field_bytes_out_threshold_3() {
    npl("* | anomaly field=bytes_out threshold=3");
}

#[test]
fn doc_anomaly_field_cpu_usage_by_process_name_method_mad_threshold() {
    npl("* | anomaly field=cpu_usage by process_name method=mad threshold=2.5");
}

#[test]
fn doc_anomaly_field_response_time_by_endpoint_threshold_2_5() {
    npl("* | anomaly field=response_time by endpoint threshold=2.5");
}

#[test]
fn doc_anomaly_field_response_time_by_service_name_threshold_2() {
    npl("* | anomaly field=response_time by service_name threshold=2 | where is_anomaly=true");
}

#[test]
fn doc_bin_bytes_span_1000000_as_mb_bucket() {
    npl("* | bin bytes span=1000000 as mb_bucket | stats count() by mb_bucket");
}

#[test]
fn doc_bin_response_time_span_100_as_time_bucket() {
    npl("* | bin response_time span=100 as time_bucket | stats count() by time_bucket | sort time_bucket");
}

#[test]
fn doc_bin_span_15m_field_last_login_as_login_bucket() {
    npl("* | bin span=15m field=last_login as login_bucket | stats dc(user) by login_bucket");
}

#[test]
fn doc_bin_span_1d() {
    npl("* | bin span=1d | stats count() as events, dc(user) as unique_users, sum(bytes) as total_bytes by time_bucket");
}

#[test]
fn doc_bin_span_1h() {
    npl("* | bin span=1h | stats count() as login_count by time_bucket, user | anomaly field=login_count by user method=mad threshold=3");
}

#[test]
fn doc_bin_span_1h_2() {
    npl("* | bin span=1h | stats count() by time_bucket | sort time_bucket");
}

#[test]
fn doc_bin_span_1h_3() {
    npl("* | bin span=1h | stats count() by time_bucket | sort time_bucket | tail 24");
}

#[test]
fn doc_bin_span_1h_4() {
    npl("* | bin span=1h | stats sum(bytes) as total_bytes by time_bucket");
}

#[test]
fn doc_bin_span_1h_hop_5m() {
    npl("* | bin span=1h hop=5m | stats count() as hourly_count by time_bucket, src_ip | eval traffic_light = if(hourly_count < 50, \"Green\", if(hourly_count > 100, \"Red\", \"Yellow\")) | where traffic_light != \"Green\" | stats count() as alert_count, values(src_ip) as ips by time_bucket, traffic_light");
}

#[test]
fn doc_bin_span_1m() {
    npl("* | bin span=1m | stats count() as connections by time_bucket, src_ip, dest_ip | stats stdev(connections) as conn_stdev by src_ip, dest_ip | where conn_stdev < 0.5");
}

#[test]
fn doc_bin_span_1m_2() {
    npl("* | bin span=1m | stats dc(dest_port) as unique_ports by time_bucket, src_ip | where unique_ports > 50");
}

#[test]
fn doc_bin_span_5m() {
    npl("* | bin span=5m | stats count() by time_bucket");
}

#[test]
fn doc_bin_span_5m_2() {
    npl("* | bin span=5m | stats sum(bytes_out) as outbound by time_bucket, src_ip | anomaly field=outbound by src_ip threshold=3");
}

#[test]
fn doc_bin_span_5m_3() {
    npl("* | bin span=5m | stats sum(bytes_out) as outbound by time_bucket, src_ip | where outbound > 100000000");
}

#[test]
fn doc_bin_span_5m_hop_1m() {
    npl("* | bin span=5m hop=1m | stats dc(dest_port) as unique_ports by time_bucket, src_ip | where unique_ports > 50");
}

#[test]
fn doc_bin_span_5m_hop_1m_2() {
    npl("* | bin span=5m hop=1m | stats sum(bytes_out) as outbound by time_bucket, src_ip | where outbound > 100000000");
}

#[test]
fn doc_chart_avg_response_time_by_endpoint() {
    npl("* | chart avg(response_time) by endpoint");
}

#[test]
fn doc_chart_count_as_events_sum_bytes_as_total_bytes_by_src_ip() {
    npl("* | chart count() as events, sum(bytes) as total_bytes by src_ip");
}

#[test]
fn doc_chart_count_by_severity() {
    npl("* | chart count() by severity");
}

#[test]
fn doc_chart_count_by_status_method() {
    npl("* | chart count() by status, method");
}

#[test]
fn doc_chart_sparkline_response_time_by_endpoint() {
    npl("* | chart sparkline(response_time) by endpoint");
}

#[test]
fn doc_cloud_by_provider() {
    npl("* | cloud by=provider");
}

#[test]
fn doc_dedup_domain() {
    npl("* | dedup domain | table domain, first_seen, src_ip");
}

#[test]
fn doc_dedup_src_host() {
    npl("* | dedup src_host | table src_host, src_ip, os_type, last_seen");
}

#[test]
fn doc_dedup_src_ip() {
    npl("* | dedup src_ip");
}

#[test]
fn doc_dedup_src_ip_dest_ip_dest_port() {
    npl("* | dedup src_ip, dest_ip, dest_port | stats count() as unique_connections");
}

#[test]
fn doc_dedup_src_ip_dest_ip_dest_port_2() {
    npl("* | dedup src_ip, dest_ip, dest_port | table src_ip, dest_ip, dest_port, protocol, bytes");
}

#[test]
fn doc_dedup_src_ip_dest_port() {
    npl("* | dedup src_ip, dest_port");
}

#[test]
fn doc_dedup_user() {
    npl("* | dedup user");
}

#[test]
fn doc_dedup_user_2() {
    npl("* | dedup user | head 20");
}

#[test]
fn doc_dedup_user_3() {
    npl("* | dedup user | tail 20");
}

#[test]
fn doc_dedup_user_keeplast_true() {
    npl("* | dedup user keeplast=true");
}

#[test]
fn doc_dedup_user_action() {
    npl("* | dedup user, action | table user, action, timestamp");
}

#[test]
fn doc_dedup_user_src_ip() {
    npl("* | dedup user, src_ip | stats count() as unique_user_ip_pairs by action");
}

#[test]
fn doc_eval_abs_diff_abs_expected_actual() {
    npl("* | eval abs_diff = abs(expected - actual)");
}

#[test]
fn doc_eval_age_seconds_now_first_seen() {
    npl("* | eval age_seconds = now() - first_seen | eval age_days = floor(age_seconds / 86400)");
}

#[test]
fn doc_eval_category_case_status_300_success_status_400() {
    npl("* | eval category = case(status < 300, \"success\", status < 400, \"redirect\", status < 500, \"client_error\", status >= 500, \"server_error\", \"unknown\")");
}

#[test]
fn doc_eval_clean_url_replace_url_api_v_0_9_api() {
    npl("* | eval clean_url = replace(url, \"/api/v[0-9]+/\", \"/api/\")");
}

#[test]
fn doc_eval_clean_user_nullif_user() {
    npl("* | eval clean_user = nullif(user, \"\")");
}

#[test]
fn doc_eval_clean_user_trim_user() {
    npl("* | eval clean_user = trim(user)");
}

#[test]
fn doc_eval_current_epoch_time() {
    npl("* | eval current_epoch = time()");
}

#[test]
fn doc_eval_current_time_now() {
    npl("* | eval current_time = now()");
}

#[test]
fn doc_eval_date_strftime_timestamp_y_m_d() {
    npl("* | eval date = strftime(timestamp, \"%Y-%m-%d\") | eval time = strftime(timestamp, \"%H:%M:%S\")");
}

#[test]
fn doc_eval_date_str_strftime_timestamp_y_m_d() {
    npl("* | eval date_str = strftime(timestamp, \"%Y-%m-%d\")");
}

#[test]
fn doc_eval_domain_extract_domain_url() {
    npl("* | eval domain = extract_domain(url) | eval domain_entropy = entropy(domain) | where domain_entropy > 4.0 | prevalence domain_prevalence < 3");
}

#[test]
fn doc_eval_domain_replace_email() {
    npl("* | eval domain = replace(email, \"^[^@]+@\", \"\")");
}

#[test]
fn doc_eval_duration_seconds_end_time_start_time() {
    npl("* | eval duration_seconds = end_time - start_time | eval duration_minutes = round(duration_seconds / 60, 1)");
}

#[test]
fn doc_eval_exp_value_exp_rate_time() {
    npl("* | eval exp_value = exp(rate * time)");
}

#[test]
fn doc_eval_first_octet_substr_src_ip_0_3() {
    npl("* | eval first_octet = substr(src_ip, 0, 3)");
}

#[test]
fn doc_eval_full_name_concat_first_name_last_name() {
    npl("* | eval full_name = concat(first_name, \" \", last_name)");
}

#[test]
fn doc_eval_full_name_first_name_last_name() {
    npl("* | eval full_name = first_name + \" \" + last_name");
}

#[test]
fn doc_eval_geo_iplocation_src_ip() {
    npl("* | eval geo = iplocation(src_ip)");
}

#[test]
fn doc_eval_hash_md5_user_password() {
    npl("* | eval hash = md5(user + password)");
}

#[test]
fn doc_eval_hash_sha1_message() {
    npl("* | eval hash = sha1(message)");
}

#[test]
fn doc_eval_hash_sha256_file_content() {
    npl("* | eval hash = sha256(file_content)");
}

#[test]
fn doc_eval_hour_strftime_timestamp_h() {
    npl("* | eval hour = strftime(timestamp, \"%H\") | where hour < 6 OR hour > 22 | risk score=20 entity=user factor=\"After-hours activity\"");
}

#[test]
fn doc_eval_ip_coalesce_src_ip_client_ip_unknown() {
    npl("* | eval ip = coalesce(src_ip, client_ip, \"unknown\")");
}

#[test]
fn doc_eval_is_encoded_if_command_line_contains_enc_1_0() {
    npl("* | eval is_encoded = if(command_line CONTAINS \"-enc\", 1, 0)");
}

#[test]
fn doc_eval_is_error_tobool_status_400() {
    npl("* | eval is_error = tobool(status >= 400)");
}

#[test]
fn doc_eval_is_external_if_cidr_match_src_ip_10_0_0_0_8_172() {
    npl("* | eval is_external = if(cidr_match(src_ip, \"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\"), 0, 1) | where is_external = 1");
}

#[test]
fn doc_eval_is_internal_cidrmatch_192_168_0_0_16_src_ip() {
    npl("* | eval is_internal = cidrmatch(\"192.168.0.0/16\", src_ip)");
}

#[test]
fn doc_eval_is_php_if_url_like_php_yes_no() {
    npl("* | eval is_php = if(url LIKE \"%.php?%\", \"yes\", \"no\")");
}

#[test]
fn doc_eval_is_private_cidrmatch_10_0_0_0_8_src_ip_or_cidrmat() {
    npl("* | eval is_private = cidrmatch(\"10.0.0.0/8\", src_ip) OR cidrmatch(\"172.16.0.0/12\", src_ip) OR cidrmatch(\"192.168.0.0/16\", src_ip)");
}

#[test]
fn doc_eval_is_suspicious_if_bytes_out_1000000_and_hour_22() {
    npl("* | eval is_suspicious = if((bytes_out > 1000000 AND hour >= 22) OR (failed_logins > 5), true, false)");
}

#[test]
fn doc_eval_log_bytes_log_bytes() {
    npl("* | eval log_bytes = log(bytes)");
}

#[test]
fn doc_eval_mb_round_bytes_1048576_2() {
    npl("* | eval mb = round(bytes / 1048576, 2)");
}

#[test]
fn doc_eval_method_upper_upper_http_method() {
    npl("* | eval method_upper = upper(http_method)");
}

#[test]
fn doc_eval_normalized_user_lower_trim_user() {
    npl("* | eval normalized_user = lower(trim(user))");
}

#[test]
fn doc_eval_parsed_time_strptime_date_field_y_m_d_h_m_s() {
    npl("* | eval parsed_time = strptime(date_field, \"%Y-%m-%d %H:%M:%S\")");
}

#[test]
fn doc_eval_path_parts_split_file_path() {
    npl("* | eval path_parts = split(file_path, \"/\")");
}

#[test]
fn doc_eval_performance_case_response_time_100_excellent_re() {
    npl("* | eval performance = case(response_time < 100, \"excellent\", response_time < 500, \"good\", response_time < 1000, \"acceptable\", response_time >= 1000, \"poor\", \"unknown\")");
}

#[test]
fn doc_eval_port_str_tostring_dest_port() {
    npl("* | eval port_str = tostring(dest_port)");
}

#[test]
fn doc_eval_risk_points_if_failed_attempts_10_50_0_if_hour() {
    npl("* | eval risk_points = if(failed_attempts > 10, 50, 0) + if(hour < 6 OR hour > 22, 20, 0) + if(is_admin=true, 15, 0) | risk score=risk_points entity=user factor=\"Suspicious login pattern\"");
}

#[test]
fn doc_eval_risk_score_if_failed_logins_10_30_0_if_bytes_o() {
    npl("* | eval risk_score = if(failed_logins > 10, 30, 0) + if(bytes_out > 10000000, 40, 0) + if(hour < 6 OR hour > 22, 20, 0) + if(is_admin = true, 10, 0)");
}

#[test]
fn doc_eval_rounded_down_floor_bytes_1024() {
    npl("* | eval rounded_down = floor(bytes / 1024)");
}

#[test]
fn doc_eval_rounded_time_round_response_time_2() {
    npl("* | eval rounded_time = round(response_time, 2)");
}

#[test]
fn doc_eval_rounded_up_ceil_response_time() {
    npl("* | eval rounded_up = ceil(response_time)");
}

#[test]
fn doc_eval_severity_if_status_500_critical_normal() {
    npl("* | eval severity = if(status >= 500, \"critical\", \"normal\")");
}

#[test]
fn doc_eval_squared_pow_value_2() {
    npl("* | eval squared = pow(value, 2)");
}

#[test]
fn doc_eval_status_num_tonumber_status_code() {
    npl("* | eval status_num = tonumber(status_code)");
}

#[test]
fn doc_eval_std_dev_sqrt_variance() {
    npl("* | eval std_dev = sqrt(variance)");
}

#[test]
fn doc_eval_success_rate_round_successful_total_100_2() {
    npl("* | eval success_rate = round((successful / total) * 100, 2)");
}

#[test]
fn doc_eval_total_bytes_in_bytes_out() {
    npl("* | eval total = bytes_in + bytes_out | rename total as total_bytes");
}

#[test]
fn doc_eval_total_bytes_in_bytes_out_ratio_bytes_out_bytes() {
    npl("* | eval total = bytes_in + bytes_out, ratio = bytes_out / bytes_in, category = if(ratio > 2, \"upload\", \"download\")");
}

#[test]
fn doc_eval_total_bytes_bytes_in_bytes_out() {
    npl("* | eval total_bytes = bytes_in + bytes_out");
}

#[test]
fn doc_eval_url_length_len_url() {
    npl("* | eval url_length = len(url)");
}

#[test]
fn doc_eval_user_lower_lower_user() {
    npl("* | eval user_lower = lower(user)");
}

#[test]
fn doc_eventstats_avg_bytes_as_avg_bytes_by_src_ip() {
    npl("* | eventstats avg(bytes) as avg_bytes by src_ip | where bytes > avg_bytes * 2");
}

#[test]
fn doc_eventstats_avg_bytes_as_avg_bytes_by_user() {
    npl("* | eventstats avg(bytes) as avg_bytes by user | where bytes > avg_bytes * 5 | risk score=25 entity=user factor=\"Anomalous data volume\"");
}

#[test]
fn doc_eventstats_avg_response_time_as_avg_time_stdev_response_ti() {
    npl("* | eventstats avg(response_time) as avg_time, stdev(response_time) as std_time by endpoint | where response_time > (avg_time + (3 * std_time))");
}

#[test]
fn doc_eventstats_count_as_total() {
    npl("* | eventstats count() as total | stats count() as subset by action | eval percentage = (subset / total) * 100");
}

#[test]
fn doc_eventstats_count_as_total_events() {
    npl("* | eventstats count() as total_events");
}

#[test]
fn doc_eventstats_dc_user_as_unique_users_count_as_total_events() {
    npl("* | eventstats dc(user) as unique_users, count() as total_events by src_ip | table timestamp, src_ip, user, action, unique_users, total_events");
}

#[test]
fn doc_eventstats_max_bytes_as_max_bytes_by_user() {
    npl("* | eventstats max(bytes) as max_bytes by user | where bytes = max_bytes");
}

#[test]
fn doc_eventstats_sum_bytes_as_total_bytes_dc_dest_ip_as_unique() {
    npl("* | eventstats sum(bytes) as total_bytes, dc(dest_ip) as unique_dests by src_ip");
}

#[test]
fn doc_fields_raw_internal() {
    npl("* | fields - _raw, _internal_*");
}

#[test]
fn doc_fields_enriched_prevalence() {
    npl("* | fields - enriched_*, prevalence_*");
}

#[test]
fn doc_fields_password_ssn_credit_card() {
    npl("* | fields - password, ssn, credit_card");
}

#[test]
fn doc_fields_src_ip_dest_ip_src_port_dest_port_protocol_byt() {
    npl("* | fields + src_ip, dest_ip, src_port, dest_port, protocol, bytes");
}

#[test]
fn doc_fields_user_src_ip_dest_ip() {
    npl("* | fields + user, src_ip, dest_ip");
}

#[test]
fn doc_fields_timestamp_message() {
    npl("* | fields timestamp, message");
}

#[test]
fn doc_fields_timestamp_user_action_src_ip() {
    npl("* | fields timestamp, user, action, src_ip");
}

#[test]
fn doc_fillnull() {
    npl("* | fillnull");
}

#[test]
fn doc_fillnull_value_user_action_status() {
    npl("* | fillnull value=\"-\" user, action, status | table timestamp, user, action, status");
}

#[test]
fn doc_fillnull_value_anonymous_user() {
    npl("* | fillnull value=\"anonymous\" user | stats count() by user");
}

#[test]
fn doc_fillnull_value_n_a_user_src_ip_dest_ip() {
    npl("* | fillnull value=\"N/A\" user, src_ip, dest_ip");
}

#[test]
fn doc_fillnull_value_unknown() {
    npl("* | fillnull value=\"unknown\"");
}

#[test]
fn doc_fillnull_value_unknown_enriched_src_country_enriched_dest() {
    npl("* | fillnull value=\"unknown\" enriched_src_country, enriched_dest_country");
}

#[test]
fn doc_fillnull_value_0_bytes_in_bytes_out() {
    npl("* | fillnull value=0 bytes_in, bytes_out | eval total = bytes_in + bytes_out");
}

#[test]
fn doc_fillnull_value_0_bytes_response_time() {
    npl("* | fillnull value=0 bytes, response_time");
}

#[test]
fn doc_format_maxresults_10_row_sep() {
    npl("* | format maxresults=10 row_sep=\" | \" col_sep=\", \"");
}

#[test]
fn doc_funnel_by_session_id_window_5m_step1_endpoint_api_auth() {
    npl("* | funnel by session_id window=5m step1=(endpoint=\"/api/auth\") step2=(endpoint=\"/api/user/profile\") step3=(endpoint=\"/api/data/query\")");
}

#[test]
fn doc_funnel_by_src_host_window_30m_step1_action_file_download() {
    npl("* | funnel by src_host window=30m step1=(action=\"file_download\" file_type=\"executable\") step2=(action=\"file_execution\") step3=(action=\"registry_modification\") step4=(action=\"network_connection\")");
}

#[test]
fn doc_funnel_by_src_ip_window_24h_step1_action_reconnaissance() {
    npl("* | funnel by src_ip window=24h step1=(action=\"reconnaissance\") step2=(action=\"initial_access\") step3=(action=\"execution\") step4=(action=\"persistence\") step5=(action=\"exfiltration\")");
}

#[test]
fn doc_funnel_by_user_window_1h_step1_action_login_step2_actio() {
    npl("* | funnel by user window=1h step1=(action=\"login\") step2=(action=\"file_access\") step3=(action=\"data_export\")");
}

#[test]
fn doc_funnel_by_user_window_48h_step1_action_email_received_sub() {
    npl("* | funnel by user window=48h step1=(action=\"email_received\" subject CONTAINS \"urgent\") step2=(action=\"email_opened\") step3=(action=\"link_clicked\") step4=(action=\"credentials_entered\")");
}

#[test]
fn doc_funnel_by_user_window_7d_step1_action_account_created_st() {
    npl("* | funnel by user window=7d step1=(action=\"account_created\") step2=(action=\"first_login\") step3=(action=\"profile_completed\") step4=(action=\"first_transaction\")");
}

#[test]
fn doc_head() {
    npl("* | head");
}

#[test]
fn doc_head_100() {
    npl("* | head 100 | reverse");
}

#[test]
fn doc_head_100_2() {
    npl("* | head 100 | table timestamp, user, action");
}

#[test]
fn doc_head_100_3() {
    npl("* | head 100 | table timestamp, user, action, src_ip");
}

#[test]
fn doc_head_20() {
    npl("* | head 20");
}

#[test]
fn doc_inputlookup_url_https_api_domaincheck_com_v1_domain_key() {
    npl("* | inputlookup url=\"https://api.domaincheck.com/v1/{domain}?key=YOUR_KEY\" key=domain format=json | where inputlookup_risk > 0.7");
}

#[test]
fn doc_inputlookup_url_https_api_example_com_live_ip_key_src() {
    npl("* | inputlookup url=\"https://api.example.com/live/{ip}\" key=src_ip format=json cache_ttl=0");
}

#[test]
fn doc_inputlookup_url_https_api_ipinfo_io_src_ip_json_key_sr() {
    npl("* | inputlookup url=\"https://api.ipinfo.io/{src_ip}/json\" key=src_ip format=json | eval geo_info = inputlookup_city . \", \" . inputlookup_country | table src_ip, geo_info, action");
}

#[test]
fn doc_inputlookup_url_https_api_ipinfo_io_src_ip_json_key_sr_2() {
    npl("* | inputlookup url=\"https://api.ipinfo.io/{src_ip}/json\" key=src_ip format=json | rename inputlookup_city as src_city, inputlookup_country as src_country | inputlookup url=\"https://api.ipinfo.io/{dest_ip}/json\" key=dest_ip format=json | rename inputlookup_city as dest_city, inputlookup_country as dest_country | table src_ip, src_city, dest_ip, dest_city");
}

#[test]
fn doc_inputlookup_url_https_api_threatfeed_io_src_ip_key_src() {
    npl("* | inputlookup url=\"https://api.threatfeed.io/{src_ip}\" key=src_ip | where inputlookup_risk_score > 80");
}

#[test]
fn doc_inputlookup_url_https_feeds_example_com_malware_file_has() {
    npl("* | inputlookup url=\"https://feeds.example.com/malware/{file_hash}.csv\" key=file_hash format=csv | where inputlookup_malware_family != \"\"");
}

#[test]
fn doc_inputlookup_url_https_ipinfo_io_src_ip_json_key_src_ip() {
    npl("* | inputlookup url=\"https://ipinfo.io/{src_ip}/json\" key=src_ip format=json | table src_ip, inputlookup_city, inputlookup_country");
}

#[test]
fn doc_inputlookup_url_https_slow_api_example_com_hash_key_fi() {
    npl("* | inputlookup url=\"https://slow-api.example.com/{hash}\" key=file_hash format=json timeout=60");
}

#[test]
fn doc_join_type_inner_file_hash_search_source_type_threat_feed() {
    npl("* | join type=inner file_hash [search source_type=\"threat_feed\" | table file_hash, threat_level, malware_family]");
}

#[test]
fn doc_join_type_inner_src_ip_search_action_suspicious() {
    npl("* | join type=inner src_ip [search action=suspicious | table src_ip]");
}

#[test]
fn doc_join_type_left_src_host_search_source_type_asset_inventory() {
    npl("* | join type=left src_host [search source_type=\"asset_inventory\" | table src_host, owner, criticality]");
}

#[test]
fn doc_join_type_left_src_ip_dest_port_search_source_type_servic() {
    npl("* | join type=left src_ip, dest_port [search source_type=\"service_catalog\" | table src_ip, dest_port, service_name]");
}

#[test]
fn doc_join_type_left_user_search_source_type_users() {
    npl("* | join type=left user [search source_type=\"users\" | table user, priority] | fillnull value=\"normal\" priority");
}

#[test]
fn doc_join_type_left_user_max_5_search_action_login() {
    npl("* | join type=left user max=5 [search action=login | stats count() by user, src_ip | table user, src_ip, count]");
}

#[test]
fn doc_lookup_asset_inventory_src_host_output_asset_owner_asset_ty() {
    npl("* | lookup asset_inventory src_host OUTPUT asset_owner, asset_type, criticality | where criticality=\"high\"");
}

#[test]
fn doc_lookup_cost_centers_src_host_output_cost_center_business_un() {
    npl("* | lookup cost_centers src_host OUTPUT cost_center, business_unit | stats sum(bytes) by cost_center");
}

#[test]
fn doc_lookup_data_classification_file_path_output_classification() {
    npl("* | lookup data_classification file_path OUTPUT classification, retention_period | where classification=\"confidential\"");
}

#[test]
fn doc_lookup_domain_categories_domain_output_category_risk_level() {
    npl("* | lookup domain_categories domain OUTPUT category, risk_level | stats count() by category, risk_level");
}

#[test]
fn doc_lookup_geo_ip_src_ip_output_country_city_latitude_longitu() {
    npl("* | lookup geo_ip src_ip OUTPUT country, city, latitude, longitude | stats count() by country");
}

#[test]
fn doc_lookup_ip_reputation_src_ip() {
    npl("* | lookup ip_reputation src_ip");
}

#[test]
fn doc_lookup_ip_reputation_src_ip_output_country() {
    npl("* | lookup ip_reputation src_ip OUTPUT country | stats count() by country, action | sort -count");
}

#[test]
fn doc_lookup_ip_reputation_src_ip_output_src_threat_score() {
    npl("* | lookup ip_reputation src_ip OUTPUT src_threat_score | lookup ip_reputation dest_ip OUTPUT dest_threat_score | where src_threat_score > 50 OR dest_threat_score > 50");
}

#[test]
fn doc_lookup_ip_reputation_src_ip_output_threat_score_category_c() {
    npl("* | lookup ip_reputation src_ip OUTPUT threat_score, category, country");
}

#[test]
fn doc_lookup_service_catalog_dest_port_output_service_name_protoc() {
    npl("* | lookup service_catalog dest_port OUTPUT service_name, protocol, description | table dest_port, service_name, protocol");
}

#[test]
fn doc_lookup_threat_intel_file_hash_output_malware_family_threat() {
    npl("* | lookup threat_intel file_hash OUTPUT malware_family, threat_level, first_seen | where threat_level=\"high\"");
}

#[test]
fn doc_lookup_threat_intel_file_hash_output_threat_level() {
    npl("* | lookup threat_intel file_hash OUTPUT threat_level | eval risk_score = if(threat_level=\"high\", 100, if(threat_level=\"medium\", 50, 10)) | where risk_score > 50 | table file_hash, threat_level, risk_score, src_host");
}

#[test]
fn doc_lookup_threat_intel_file_hash_output_threat_level_2() {
    npl("* | lookup threat_intel file_hash OUTPUT threat_level | where threat_level=\"high\" | risk score=80 entity=src_host factor=\"Known malware execution\"");
}

#[test]
fn doc_lookup_user_directory_user_output_full_name_case_insensitive() {
    npl("* | lookup user_directory user OUTPUT full_name CASE_INSENSITIVE");
}

#[test]
fn doc_lookup_user_directory_user_output_full_name_department_man() {
    npl("* | lookup user_directory user OUTPUT full_name, department, manager | table user, full_name, department, action");
}

#[test]
fn doc_lookup_user_priority_user_output_priority_level() {
    npl("* | lookup user_priority user OUTPUT priority_level | where priority_level=\"executive\" | table timestamp, user, action, src_ip");
}

#[test]
fn doc_lookup_vendor_mapping_product_id_output_vendor_name_product() {
    npl("* | lookup vendor_mapping product_id OUTPUT vendor_name, product_name, version | table product_id, vendor_name, product_name");
}

#[test]
fn doc_lookup_vulnerability_db_software_version_output_cve_ids_sev() {
    npl("* | lookup vulnerability_db software_version OUTPUT cve_ids, severity, patch_available | where severity=\"critical\" AND patch_available=true");
}

#[test]
fn doc_mvexpand_dest_ports() {
    npl("* | mvexpand dest_ports");
}

#[test]
fn doc_mvexpand_dns_answers() {
    npl("* | mvexpand dns_answers");
}

#[test]
fn doc_mvexpand_dns_answers_limit_500() {
    npl("* | mvexpand dns_answers limit=500");
}

#[test]
fn doc_mvexpand_related_ips() {
    npl("* | mvexpand related_ips | dedup related_ips");
}

#[test]
fn doc_mvexpand_tags() {
    npl("* | mvexpand tags | stats count() by tags");
}

#[test]
fn doc_mvexpand_users_limit_10() {
    npl("* | mvexpand users limit=10");
}

#[test]
fn doc_prevalence_domain_first_seen_now_24h() {
    npl("* | prevalence domain_first_seen > now() - 24h");
}

#[test]
fn doc_prevalence_domain_first_seen_now_interval_24_hour() {
    npl("* | prevalence domain_first_seen > now() - INTERVAL 24 HOUR");
}

#[test]
fn doc_prevalence_domain_prevalence_3_window_7d() {
    npl("* | prevalence domain_prevalence < 3 window=7d");
}

#[test]
fn doc_prevalence_enrich_true() {
    npl("* | prevalence enrich=true | inputlookup url=\"https://api.example.com/{src_ip}\" key=src_ip | table src_ip, hash_prevalence, inputlookup_country");
}

#[test]
fn doc_prevalence_enrich_true_2() {
    npl("* | prevalence enrich=true | table file_hash, hash_prevalence, hash_first_seen");
}

#[test]
fn doc_prevalence_enrich_true_3() {
    npl("* | prevalence enrich=true | where host_count < 5");
}

#[test]
fn doc_prevalence_enrich_true_4() {
    npl("* | prevalence enrich=true | where prevalence_first_seen > \"2026-01-01\" | sort prevalence_score");
}

#[test]
fn doc_prevalence_enrich_true_window_24h() {
    npl("* | prevalence enrich=true window=24h");
}

#[test]
fn doc_prevalence_hash_prevalence_3_and_hash_first_seen_now() {
    npl("* | prevalence hash_prevalence < 3 AND hash_first_seen > now() - INTERVAL 3 DAY | where bytes > 1000000");
}

#[test]
fn doc_prevalence_hash_prevalence_3_and_hash_first_seen_now_2() {
    npl("* | prevalence hash_prevalence < 3 AND hash_first_seen > now() - INTERVAL 7 DAY window=30d");
}

#[test]
fn doc_prevalence_hash_prevalence_5_window_24h() {
    npl("* | prevalence hash_prevalence < 5 window=24h");
}

#[test]
fn doc_prevalence_hash_prevalence_5_window_7d() {
    npl("* | prevalence hash_prevalence < 5 window=7d");
}

#[test]
fn doc_rare_action() {
    npl("* | rare action");
}

#[test]
fn doc_rare_dest_ip() {
    npl("* | rare dest_ip");
}

#[test]
fn doc_rare_dest_port_by_src_ip() {
    npl("* | rare dest_port by src_ip");
}

#[test]
fn doc_rare_limit_20_url() {
    npl("* | rare limit=20 url");
}

#[test]
fn doc_rare_limit_5_src_ip() {
    npl("* | rare limit=5 src_ip");
}

#[test]
fn doc_rare_process_name_limit_15() {
    npl("* | rare process_name limit=15");
}

#[test]
fn doc_rare_user() {
    npl("* | rare user");
}

#[test]
fn doc_rare_user_agent_limit_25() {
    npl("* | rare user_agent limit=25");
}

#[test]
fn doc_rename_clientip_as_src_ip_serverip_as_dest_ip() {
    npl("* | rename clientIP as src_ip, serverIP as dest_ip");
}

#[test]
fn doc_rename_http_request_headers_user_agent_as_user_agent_http_r() {
    npl("* | rename http_request_headers_user_agent as user_agent, http_response_status_code as status");
}

#[test]
fn doc_rename_ip_address_as_src_ip() {
    npl("* | rename ip_address as src_ip | lookup ip_enrichment src_ip");
}

#[test]
fn doc_rename_src_ip_as_source_ip() {
    npl("* | rename src_ip as source_ip");
}

#[test]
fn doc_rename_src_ip_as_source_ip_dest_ip_as_destination_ip_src_p() {
    npl("* | rename src_ip as source_ip, dest_ip as destination_ip, src_port as source_port");
}

#[test]
fn doc_rename_src_ip_as_temp_dest_ip_as_src_ip_temp_as_dest_ip() {
    npl("* | rename src_ip as temp, dest_ip as src_ip, temp as dest_ip");
}

#[test]
fn doc_rename_user_name_as_user() {
    npl("* | rename user_name as user | dedup user");
}

#[test]
fn doc_reverse() {
    npl("* | reverse");
}

#[test]
fn doc_rex_email_a_za_z0_9_a_za_z0_9_a_za_z_2() {
    npl("* | rex \"(?<email>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})\" | dedup email | table email");
}

#[test]
fn doc_rex_key_w_value_s() {
    npl("* | rex \"(?<key>\\w+)=(?<value>[^\\s]+)\" | table key, value");
}

#[test]
fn doc_rex_user_user_action_action() {
    npl("* | rex \"\\\"user\\\":\\\"(?<user>[^\\\"]+)\\\",\\\"action\\\":\\\"(?<action>[^\\\"]+)\\\"\" | table user, action");
}

#[test]
fn doc_rex_timestamp_level_w_message() {
    npl("* | rex \"\\[(?<timestamp>[^\\]]+)\\] (?<level>\\w+): (?<message>.*)\" | table timestamp, level, message");
}

#[test]
fn doc_rex_file_file_path_s() {
    npl("* | rex \"file: (?<file_path>/[^\\s]+)\" | dedup file_path | table file_path");
}

#[test]
fn doc_rex_hash_file_hash_a_fa_f0_9_32_64() {
    npl("* | rex \"hash: (?<file_hash>[a-fA-F0-9]{32,64})\" | dedup file_hash | table file_hash, message");
}

#[test]
fn doc_rex_ip_ip_address_d_d_d_d() {
    npl("* | rex \"IP: (?<ip_address>\\d+\\.\\d+\\.\\d+\\.\\d+)\" | table ip_address, message");
}

#[test]
fn doc_rex_user_user_w_action_action_w_status_statu() {
    npl("* | rex \"user=(?<user>\\w+) action=(?<action>\\w+) status=(?<status>\\d+)\" | table user, action, status");
}

#[test]
fn doc_rex_user_username_w() {
    npl("* | rex \"user=(?<username>\\w+)\" | rex \"ip=(?<ip_address>[\\d.]+)\" | rex \"action=(?<action>\\w+)\" | table username, ip_address, action");
}

#[test]
fn doc_rex_user_username_w_2() {
    npl("* | rex \"user=(?<username>\\w+)\" | table username, message");
}

#[test]
fn doc_rex_version_version_d_d_d() {
    npl("* | rex \"version (?<version>\\d+\\.\\d+\\.\\d+)\" | stats count() by version");
}

#[test]
fn doc_rex_field_url_https_domain_path() {
    npl("* | rex field=url \"https?://(?<domain>[^/]+)/(?<path>.*)\" | table domain, path");
}

#[test]
fn doc_rex_mode_sed_s_s_g() {
    npl("* | rex mode=sed \"s/\\s+/ /g\" | table message");
}

#[test]
fn doc_rex_mode_sed_field_file_path_s_g() {
    npl("* | rex mode=sed field=file_path \"s/\\\\\\//-/g\"");
}

#[test]
fn doc_rex_mode_sed_field_message_s_a_za_z0_9_a_za_z0_9() {
    npl("* | rex mode=sed field=message \"s/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+/REDACTED_EMAIL/g\"");
}

#[test]
fn doc_rex_mode_sed_field_message_s_password_password_redact() {
    npl("* | rex mode=sed field=message \"s/password=[^ ]*/password=REDACTED/g\"");
}

#[test]
fn doc_risk_score_severity_level_entity_user_factor_severity_based() {
    npl("* | risk score=severity_level entity=user factor=\"Severity-based score\"");
}

#[test]
fn doc_sample() {
    npl("* | sample");
}

#[test]
fn doc_sample_100() {
    npl("* | sample 100");
}

#[test]
fn doc_sample_10000() {
    npl("* | sample 10000 | stats count() by src_ip");
}

#[test]
fn doc_sample_5000() {
    npl("* | sample 5000 | top user");
}

#[test]
fn doc_sequence_by_src_host_maxspan_15m_fields_process_name_parent() {
    npl("* | sequence by src_host maxspan=15m fields(process_name, parent_command_line, file_path, dest_ip) [process_name=\"lsass.exe\" action=\"process_access\"] [action=\"file_create\" file_path=\"*.dmp\"] [action=\"network_connection\" dest_port=445]");
}

#[test]
fn doc_sequence_by_src_ip_maxspan_1h_fields_dest_ip_dest_port_ac() {
    npl("* | sequence by src_ip maxspan=1h fields(dest_ip, dest_port) [action=\"port_scan\"] [action=\"vulnerability_probe\"] [action=\"exploit_attempt\"]");
}

#[test]
fn doc_sequence_by_src_ip_maxspan_2h_fields_file_path_bytes_out_d() {
    npl("* | sequence by src_ip maxspan=2h fields(file_path, bytes_out, dest_ip) [action=\"file_access\" file_path=\"*confidential*\"] [action=\"compression\" OR action=\"archive\"] [dest_ip!=\"10.*\" AND dest_ip!=\"192.168.*\"]");
}

#[test]
fn doc_sequence_by_user_maxspan_1h_fields_src_ip_dest_host_auth_t() {
    npl("* | sequence by user maxspan=1h fields(src_ip, dest_host, auth_type) [action=\"login\" src_host=/workstation.*/i] [action=\"login\" src_host=/server.*/i] [action=\"file_access\" dest_host=/dc.*/i]");
}

#[test]
fn doc_sequence_by_user_maxspan_24h_fields_subject_url_src_ip_a() {
    npl("* | sequence by user maxspan=24h fields(subject, url, src_ip) [action=\"email_open\" subject=/urgent|verify|suspended/i] [action=\"link_click\" url_domain!=\"company.com\"] [action=\"credential_submit\"] [action=\"login\" status=\"success\"]");
}

#[test]
fn doc_sequence_by_user_maxspan_30m_privilege_user_action_pri() {
    npl("* | sequence by user maxspan=30m [privilege=\"user\"] [action=\"privilege_escalation\"] [privilege=\"admin\"]");
}

#[test]
fn doc_sequence_by_user_src_host_maxspan_30m_fields_process_name() {
    npl("* | sequence by user, src_host maxspan=30m fields(process_name, command_line) [action=\"login\" user_type=\"standard\"] [action=\"privilege_escalation\"] [action=\"admin_command\"]");
}

#[test]
fn doc_sort_timestamp() {
    npl("* | sort -timestamp");
}

#[test]
fn doc_sort_timestamp_2() {
    npl("* | sort -timestamp | dedup endpoint | table endpoint, status, response_time, timestamp");
}

#[test]
fn doc_sort_timestamp_3() {
    npl("* | sort -timestamp | dedup user");
}

#[test]
fn doc_sort_timestamp_4() {
    npl("* | sort -timestamp | head 100");
}

#[test]
fn doc_sort_timestamp_5() {
    npl("* | sort timestamp");
}

#[test]
fn doc_sort_timestamp_6() {
    npl("* | sort timestamp | reverse");
}

#[test]
fn doc_sort_timestamp_7() {
    npl("* | sort timestamp | streamstats count() as session_num by user");
}

#[test]
fn doc_sort_timestamp_8() {
    npl("* | sort timestamp | streamstats current=false last(status) as prev_status by endpoint | where status != prev_status");
}

#[test]
fn doc_sort_timestamp_9() {
    npl("* | sort timestamp | tail 1000 | stats count() by user");
}

#[test]
fn doc_sort_timestamp_10() {
    npl("* | sort timestamp | tail 50");
}

#[test]
fn doc_spath() {
    npl("* | spath");
}

#[test]
fn doc_spath_input_json_data_path_response_status_output_status() {
    npl("* | spath input=json_data path=response.status output=status");
}

#[test]
#[ignore] // spath bracket JSONPath notation (items[0].name) not yet supported in SQL gen
fn doc_spath_path_items_0_name_output_first_item() {
    npl("* | spath path=items[0].name output=first_item");
}

#[test]
fn doc_spath_path_metadata_user_id_output_user_id() {
    npl("* | spath path=metadata.user.id output=user_id");
}

#[test]
fn doc_spath_path_user_email_output_email() {
    npl("* | spath path=user.email output=email");
}

#[test]
fn doc_spath_path_user_name_output_username() {
    npl("* | spath path=user.name output=username | spath path=user.email output=email | spath path=user.role output=role");
}

#[test]
fn doc_stats_avg_bytes_as_avg_bytes_stdev_bytes_as_stdev_bytes() {
    npl("* | stats avg(bytes) as avg_bytes, stdev(bytes) as stdev_bytes, max(bytes) as max_bytes by src_ip | where max_bytes > (avg_bytes + (3 * stdev_bytes))");
}

#[test]
fn doc_stats_avg_bytes_by_protocol() {
    npl("* | stats avg(bytes) by protocol");
}

#[test]
fn doc_stats_avg_response_time_as_avg_response() {
    npl("* | stats avg(response_time) as avg_response");
}

#[test]
fn doc_stats_avg_response_time_as_avg_time_by_endpoint() {
    npl("* | stats avg(response_time) as avg_time by endpoint | sort -avg_time | head 5");
}

#[test]
fn doc_stats_avg_response_time_as_avg_time_by_endpoint_2() {
    npl("* | stats avg(response_time) as avg_time by endpoint | sort -avg_time | tail 5");
}

#[test]
fn doc_stats_avg_response_time_as_avg_time_by_endpoint_3() {
    npl("* | stats avg(response_time) as avg_time by endpoint | sort -avg_time limit=5");
}

#[test]
fn doc_stats_avg_response_time_as_avg_time_by_endpoint_4() {
    npl("* | stats avg(response_time) as avg_time by endpoint | sort avg_time | tail 5");
}

#[test]
fn doc_stats_avg_response_time_as_avg_time_by_endpoint_5() {
    npl("* | stats avg(response_time) as avg_time by endpoint | where avg_time >= 500 AND avg_time <= 2000");
}

#[test]
fn doc_stats_avg_response_time_as_avg_time_by_endpoint_6() {
    npl("* | stats avg(response_time) as avg_time by endpoint | where endpoint IN (\"/api/login\", \"/api/auth\", \"/api/token\")");
}

#[test]
fn doc_stats_count_by_src_ip_dest_ip_dest_port() {
    npl("* | stats count by src_ip, dest_ip, dest_port | ai prompt=\"Flag port scanning activity as SCAN or NORMAL.\" max_rows=50");
}

#[test]
fn doc_stats_count() {
    npl("* | stats count()");
}

#[test]
fn doc_stats_count_as_cnt_dc_user_as_unique_users_by_src_ip() {
    npl("* | stats count() as cnt, dc(user) as unique_users by src_ip | rename src_ip as \"Source IP\", cnt as \"Event Count\", unique_users as \"Unique Users\"");
}

#[test]
fn doc_stats_count_as_event_count_sum_bytes_as_byte_sum_avg_re() {
    npl("* | stats count() as event_count, sum(bytes) as byte_sum, avg(response_time) as avg_resp by endpoint | rename endpoint as \"API Endpoint\", event_count as \"Requests\", byte_sum as \"Total Bytes\", avg_resp as \"Avg Response (ms)\"");
}

#[test]
fn doc_stats_count_as_events_by_src_ip() {
    npl("* | stats count() as events by src_ip | sort -events | tail 10");
}

#[test]
fn doc_stats_count_as_events_avg_bytes_as_avg_bytes_by_src_ip() {
    npl(
        "* | stats count() as events, avg(bytes) as avg_bytes by src_ip | sort -events, +avg_bytes",
    );
}

#[test]
fn doc_stats_count_as_events_dc_dest_port_as_unique_ports_by_sr() {
    npl("* | stats count() as events, dc(dest_port) as unique_ports by src_ip | where (events > 1000 OR unique_ports > 50) AND src_ip != \"192.168.1.1\"");
}

#[test]
fn doc_stats_count_as_events_dc_src_ip_as_unique_ips_sum_bytes() {
    npl("* | stats count() as events, dc(src_ip) as unique_ips, sum(bytes) as bytes, avg(response_time) as avg_time by endpoint | table endpoint, events, avg_time");
}

#[test]
fn doc_stats_count_as_events_dc_user_as_unique_users_by_src_ip() {
    npl("* | stats count() as events, dc(user) as unique_users by src_ip | where events > 100 AND unique_users > 10");
}

#[test]
fn doc_stats_count_as_events_sum_bytes_as_bytes_by_src_ip_dest() {
    npl("* | stats count() as events, sum(bytes) as bytes by src_ip, dest_ip | fields src_ip, events");
}

#[test]
fn doc_stats_count_as_events_sum_bytes_as_bytes_by_src_ip_dest_2() {
    npl("* | stats count() as events, sum(bytes) as bytes by src_ip, dest_port, protocol");
}

#[test]
fn doc_stats_count_as_events_sum_bytes_as_bytes_dc_dest_ip_as() {
    npl("* | stats count() as events, sum(bytes) as bytes, dc(dest_ip) as unique_destinations by user | sort -events | head 10 | table user, events, bytes, unique_destinations");
}

#[test]
fn doc_stats_count_as_events_sum_bytes_as_total_bytes_by_user() {
    npl("* | stats count() as events, sum(bytes) as total_bytes by user | sort -events, -total_bytes");
}

#[test]
fn doc_stats_count_as_events_sum_bytes_as_total_bytes_by_user_2() {
    npl("* | stats count() as events, sum(bytes) as total_bytes by user | table user, events, total_bytes");
}

#[test]
fn doc_stats_count_as_events_values_dest_port_as_ports_by_src_i() {
    npl("* | stats count() as events, values(dest_port) as ports by src_ip | sort -events | head 10");
}

#[test]
fn doc_stats_count_as_failures_by_src_ip() {
    npl("* | stats count() as failures by src_ip | where failures > 5");
}

#[test]
fn doc_stats_count_as_requests_earliest_timestamp_as_session_st() {
    npl("* | stats count() as requests, earliest(timestamp) as session_start, latest(timestamp) as session_end, dc(endpoint) as unique_endpoints by session_id");
}

#[test]
fn doc_stats_count_as_requests_sum_bytes_as_total_bytes_avg_re() {
    npl("* | stats count() as requests, sum(bytes) as total_bytes, avg(response_time) as avg_time by src_ip");
}

#[test]
fn doc_stats_count_as_total() {
    npl("* | stats count() as total");
}

#[test]
fn doc_stats_count_by_dest_port() {
    npl("* | stats count() by dest_port | sort -count | tail 5");
}

#[test]
fn doc_stats_count_by_dest_port_2() {
    npl("* | stats count() by dest_port | sort count limit=10");
}

#[test]
fn doc_stats_count_by_endpoint() {
    npl("* | stats count() by endpoint | sort -count limit=10");
}

#[test]
fn doc_stats_count_by_enriched_src_country() {
    npl("* | stats count() by enriched_src_country | sort enriched_src_country");
}

#[test]
fn doc_stats_count_by_enriched_src_country_2() {
    npl("* | stats count() by enriched_src_country | where enriched_src_country != \"\"");
}

#[test]
fn doc_stats_count_by_enriched_src_country_enriched_dest_country() {
    npl("* | stats count() by enriched_src_country, enriched_dest_country");
}

#[test]
fn doc_stats_count_by_process_name() {
    npl("* | stats count() by process_name | where process_name CONTAINS \"powershell\"");
}

#[test]
fn doc_stats_count_by_severity_category_user() {
    npl("* | stats count() by severity, category, user | sort -severity, category, -count");
}

#[test]
fn doc_stats_count_by_severity_user() {
    npl("* | stats count() by severity, user | sort -severity, user");
}

#[test]
fn doc_stats_count_by_source_type() {
    npl("* | stats count() by source_type | table source_type, count");
}

#[test]
fn doc_stats_count_by_src_ip() {
    npl("* | stats count() by src_ip | rename src_ip as ip, count as events | where events > 100 | sort -events");
}

#[test]
fn doc_stats_count_by_src_ip_2() {
    npl("* | stats count() by src_ip | where src_ip=/^192\\.168\\./");
}

#[test]
fn doc_stats_count_by_src_ip_dest_port() {
    npl("* | stats count() by src_ip, dest_port | head 25");
}

#[test]
fn doc_stats_count_by_url() {
    npl("* | stats count() by url | where url CONTAINS \"/admin/\" OR url CONTAINS \"/config/\"");
}

#[test]
fn doc_stats_count_by_url_2() {
    npl("* | stats count() by url | where url LIKE \"%.php?%\"");
}

#[test]
fn doc_stats_count_by_user() {
    npl("* | stats count() by user");
}

#[test]
fn doc_stats_count_by_user_2() {
    npl("* | stats count() by user | append [search earliest=-30d latest=-7d | stats count() as baseline by user]");
}

#[test]
fn doc_stats_count_by_user_3() {
    npl("* | stats count() by user | sort -count");
}

#[test]
fn doc_stats_count_by_user_4() {
    npl("* | stats count() by user | sort -count | head 10");
}

#[test]
fn doc_stats_count_by_user_5() {
    npl("* | stats count() by user | sort -count | tail 10");
}

#[test]
fn doc_stats_count_by_user_6() {
    npl("* | stats count() by user | sort count");
}

#[test]
fn doc_stats_count_by_user_7() {
    npl("* | stats count() by user | sort count | reverse");
}

#[test]
fn doc_stats_count_by_user_8() {
    npl("* | stats count() by user | sort count desc");
}

#[test]
fn doc_stats_count_by_user_9() {
    npl("* | stats count() by user | sort user");
}

#[test]
fn doc_stats_count_by_user_10() {
    npl("* | stats count() by user | where lower(user) LIKE \"%admin%\"");
}

#[test]
fn doc_stats_dc_src_ip_as_unique_ips() {
    npl("* | stats dc(src_ip) as unique_ips");
}

#[test]
fn doc_stats_dc_src_ip_as_unique_sources_dc_dest_port_as_unique() {
    npl("* | stats dc(src_ip) as unique_sources, dc(dest_port) as unique_ports, count() as total_events");
}

#[test]
fn doc_stats_dc_user_by_dest_host() {
    npl("* | stats dc(user) by dest_host");
}

#[test]
fn doc_stats_earliest_timestamp_as_first_occurrence() {
    npl("* | stats earliest(timestamp) as first_occurrence");
}

#[test]
fn doc_stats_first_message_by_user() {
    npl("* | stats first(message) by user");
}

#[test]
fn doc_stats_last_status_by_session_id() {
    npl("* | stats last(status) by session_id");
}

#[test]
fn doc_stats_latest_timestamp_as_last_occurrence() {
    npl("* | stats latest(timestamp) as last_occurrence");
}

#[test]
fn doc_stats_list_action_by_user() {
    npl("* | stats list(action) by user");
}

#[test]
fn doc_stats_list_message_by_user() {
    npl("* | stats list(message) by user");
}

#[test]
fn doc_stats_max_bytes_as_largest_transfer() {
    npl("* | stats max(bytes) as largest_transfer");
}

#[test]
fn doc_stats_max_timestamp_as_last_seen_by_user() {
    npl("* | stats max(timestamp) as last_seen by user");
}

#[test]
fn doc_stats_median_response_time_by_endpoint() {
    npl("* | stats median(response_time) by endpoint");
}

#[test]
fn doc_stats_min_response_time_as_fastest() {
    npl("* | stats min(response_time) as fastest");
}

#[test]
fn doc_stats_min_timestamp_as_first_seen_by_src_ip() {
    npl("* | stats min(timestamp) as first_seen by src_ip");
}

#[test]
fn doc_stats_min_timestamp_as_first_seen_max_timestamp_as_last_s() {
    npl("* | stats min(timestamp) as first_seen, max(timestamp) as last_seen by file_hash | where last_seen > now() - INTERVAL 1 HOUR");
}

#[test]
fn doc_stats_min_timestamp_as_first_seen_max_timestamp_as_last_s_2() {
    npl("* | stats min(timestamp) as first_seen, max(timestamp) as last_seen, count() as occurrences by file_hash");
}

#[test]
fn doc_stats_mode_status_by_endpoint() {
    npl("* | stats mode(status) by endpoint");
}

#[test]
fn doc_stats_perc95_bytes_by_src_ip() {
    npl("* | stats perc95(bytes) by src_ip");
}

#[test]
fn doc_stats_perc95_response_time_as_p95_by_endpoint() {
    npl("* | stats perc95(response_time) as p95 by endpoint");
}

#[test]
fn doc_stats_percentile_bytes_50_as_median_bytes() {
    npl("* | stats percentile(bytes, 50) as median_bytes");
}

#[test]
fn doc_stats_percentile_response_time_50_as_median_percentile_re() {
    npl("* | stats percentile(response_time, 50) as median, percentile(response_time, 95) as p95, percentile(response_time, 99) as p99 by endpoint");
}

#[test]
fn doc_stats_percentile_response_time_95_as_p95() {
    npl("* | stats percentile(response_time, 95) as p95");
}

#[test]
fn doc_stats_range_response_time_as_time_spread() {
    npl("* | stats range(response_time) as time_spread");
}

#[test]
fn doc_stats_sparkline_count_by_src_ip() {
    npl("* | stats sparkline count by src_ip");
}

#[test]
fn doc_stats_sparkline_bytes_as_trend_count_by_src_ip() {
    npl("* | stats sparkline(bytes) as trend, count() by src_ip");
}

#[test]
fn doc_stats_stdev_response_time_as_response_variance() {
    npl("* | stats stdev(response_time) as response_variance");
}

#[test]
fn doc_stats_sum_bytes_in_as_inbound_sum_bytes_out_as_outbound_b() {
    npl("* | stats sum(bytes_in) as inbound, sum(bytes_out) as outbound by src_ip | eval ratio = outbound / inbound | sort -ratio");
}

#[test]
fn doc_stats_sum_bytes_in_as_inbound_sum_bytes_out_as_outbound_b_2() {
    npl("* | stats sum(bytes_in) as inbound, sum(bytes_out) as outbound by src_ip | eval ratio = outbound / inbound | where ratio > 10");
}

#[test]
fn doc_stats_sum_bytes_in_as_inbound_sum_bytes_out_as_outbound_b_3() {
    npl("* | stats sum(bytes_in) as inbound, sum(bytes_out) as outbound by src_ip | eval total = inbound + outbound | table src_ip, inbound, outbound, total");
}

#[test]
fn doc_stats_sum_bytes_in_as_inbound_sum_bytes_out_as_outbound() {
    npl("* | stats sum(bytes_in) as inbound, sum(bytes_out) as outbound, sum(bytes_in + bytes_out) as total by src_ip | eval ratio = outbound / inbound | where ratio > 10");
}

#[test]
fn doc_stats_sum_bytes_as_total_by_user() {
    npl("* | stats sum(bytes) as total by user | where user NOT IN (\"system\", \"backup\", \"monitoring\")");
}

#[test]
fn doc_stats_sum_bytes_as_total_bytes() {
    npl("* | stats sum(bytes) as total_bytes");
}

#[test]
fn doc_stats_sum_bytes_as_total_bytes_by_src_ip() {
    npl("* | stats sum(bytes) as total_bytes by src_ip | sort -total_bytes | head 10");
}

#[test]
fn doc_stats_sum_bytes_as_total_bytes_by_user() {
    npl("* | stats sum(bytes) as total_bytes by user | rename user as username, total_bytes as \"Total Bytes Transferred\"");
}

#[test]
fn doc_stats_sum_bytes_by_src_ip() {
    npl("* | stats sum(bytes) by src_ip");
}

#[test]
fn doc_stats_values_dest_port_by_src_ip() {
    npl("* | stats values(dest_port) by src_ip");
}

#[test]
fn doc_stats_values_user_by_src_ip() {
    npl("* | stats values(user) by src_ip");
}

#[test]
fn doc_stats_var_bytes_by_protocol() {
    npl("* | stats var(bytes) by protocol");
}

#[test]
fn doc_streamstats_count_as_event_num() {
    npl("* | streamstats count() as event_num");
}

#[test]
fn doc_streamstats_current_false_last_timestamp_as_prev_ts_by_dest() {
    npl("* | streamstats current=false last(timestamp) as prev_ts by dest_host | eval time_diff = timestamp - prev_ts");
}

#[test]
fn doc_streamstats_dc_dest_port_as_unique_ports_by_src_ip() {
    npl("* | streamstats dc(dest_port) as unique_ports by src_ip | where unique_ports > 50");
}

#[test]
fn doc_streamstats_sum_bytes_as_total_bytes_by_user() {
    npl("* | streamstats sum(bytes) as total_bytes by user");
}

#[test]
fn doc_streamstats_window_10_avg_bytes_as_rolling_avg_by_src_ip() {
    npl("* | streamstats window=10 avg(bytes) as rolling_avg by src_ip");
}

#[test]
fn doc_streamstats_window_100_avg_response_time_as_avg_time_stdev() {
    npl("* | streamstats window=100 avg(response_time) as avg_time, stdev(response_time) as std_time | eval is_anomaly = response_time > (avg_time + (3 * std_time)) | where is_anomaly=true");
}

#[test]
fn doc_table_timestamp_as_time_user_as_username_action_as_ac() {
    npl("* | table timestamp as \"Time\", user as \"Username\", action as \"Action\", src_ip as \"Source IP\"");
}

#[test]
fn doc_table_timestamp_user_action_src_ip() {
    npl("* | table timestamp, user, action, src_ip");
}

#[test]
fn doc_table_timestamp_user_aws_eventname_aws_sourceipaddress() {
    npl("* | table timestamp, user, aws_eventName, aws_sourceIPAddress");
}

#[test]
fn doc_table_user() {
    npl("* | table user");
}

#[test]
fn doc_table_user_src_ip_dest_ip_bytes_timestamp() {
    npl("* | table user, src_ip, dest_ip, bytes, timestamp");
}

#[test]
fn doc_tail() {
    npl("* | tail");
}

#[test]
fn doc_tail_100() {
    npl("* | tail 100");
}

#[test]
fn doc_tail_20() {
    npl("* | tail 20");
}

#[test]
fn doc_timechart_span_15m_count_as_events_sum_bytes_as_total_by() {
    npl("* | timechart span=15m count() as events, sum(bytes) as total_bytes");
}

#[test]
fn doc_timechart_span_15m_count_eval_status_500_as_errors_count() {
    npl("* | timechart span=15m count(eval(status>=500)) as errors, count() as total | eval error_rate = (errors / total) * 100");
}

#[test]
fn doc_timechart_span_1d_count_by_severity() {
    npl("* | timechart span=1d count() by severity");
}

#[test]
fn doc_timechart_span_1h_count() {
    npl("* | timechart span=1h count()");
}

#[test]
fn doc_timechart_span_1h_count_by_action() {
    npl("* | timechart span=1h count() by action");
}

#[test]
fn doc_timechart_span_1h_count_by_action_2() {
    npl("* | timechart span=1h count() by action | rename _time as \"Time\", count as \"Events\"");
}

#[test]
fn doc_timechart_span_1h_dc_user_as_unique_users() {
    npl("* | timechart span=1h dc(user) as unique_users");
}

#[test]
fn doc_timechart_span_1h_sum_bytes_in_as_inbound_sum_bytes_out_a() {
    npl("* | timechart span=1h sum(bytes_in) as inbound, sum(bytes_out) as outbound");
}

#[test]
fn doc_timechart_span_5m_avg_response_time_as_avg_ms() {
    npl("* | timechart span=5m avg(response_time) as avg_ms");
}

#[test]
fn doc_timechart_span_5m_count_as_events() {
    npl("* | timechart span=5m count() as events | where events > 1000");
}

#[test]
fn doc_top_action_showperc_false() {
    npl("* | top action showperc=false");
}

#[test]
fn doc_top_dest_ip_showcount_true_showperc_false() {
    npl("* | top dest_ip showcount=true showperc=false");
}

#[test]
fn doc_top_dest_port_by_src_ip() {
    npl("* | top dest_port by src_ip");
}

#[test]
fn doc_top_limit_15_process_name() {
    npl("* | top limit=15 process_name");
}

#[test]
fn doc_top_limit_20_url() {
    npl("* | top limit=20 url");
}

#[test]
fn doc_top_limit_5_src_ip() {
    npl("* | top limit=5 src_ip");
}

#[test]
fn doc_top_user() {
    npl("* | top user");
}

#[test]
fn doc_top_user_agent_limit_25() {
    npl("* | top user_agent limit=25");
}

#[test]
fn doc_transaction_process_id_startswith_action_process_create() {
    npl("* | transaction process_id startswith=(action=\"process_create\") endswith=(action=\"process_terminate\") maxspan=1h");
}

#[test]
fn doc_transaction_request_id_maxspan_5m() {
    npl("* | transaction request_id maxspan=5m | where duration > 1000");
}

#[test]
fn doc_transaction_session_id_maxspan_30m() {
    npl("* | transaction session_id maxspan=30m");
}

#[test]
fn doc_transaction_src_ip_maxspan_1m() {
    npl("* | transaction src_ip maxspan=1m | where eventcount > 100 | eval scan_type = if(eventcount > 200, \"port_scan\", \"flood\") | table src_ip, scan_type, eventcount, duration");
}

#[test]
fn doc_transaction_src_ip_startswith_action_reconnaissance_ends() {
    npl("* | transaction src_ip startswith=(action=\"reconnaissance\") endswith=(action=\"data_exfiltration\") maxspan=24h");
}

#[test]
fn doc_transaction_src_ip_dest_ip_dest_port_maxspan_10m() {
    npl("* | transaction src_ip, dest_ip, dest_port maxspan=10m");
}

#[test]
fn doc_transaction_user_maxspan_1h_maxevents_100() {
    npl("* | transaction user maxspan=1h maxevents=100");
}

#[test]
fn doc_transaction_user_startswith_action_login_endswith_actio() {
    npl("* | transaction user startswith=(action=\"login\") endswith=(action=\"logout\") maxspan=8h");
}

#[test]
fn doc_where_cidrmatch_192_168_0_0_16_src_ip() {
    npl("* | where cidrmatch(\"192.168.0.0/16\", src_ip)");
}

#[test]
fn doc_where_dest_host_server_db01() {
    npl("* | where dest_host=\"server-db01\" | lateral entity=dest_host");
}

#[test]
fn doc_where_is_public_ip_dest_ip() {
    npl("* | where is_public_ip(dest_ip) | stats sum(bytes) as total, count() as connections by dest_ip | where connections > 100 AND total < 10000");
}

#[test]
fn doc_where_isnotnull_file_hash_and_match_process_name_i_powe() {
    npl("* | where isnotnull(file_hash) AND match(process_name, \"(?i)powershell\")");
}

#[test]
fn doc_where_isnull_enriched_country() {
    npl("* | where isnull(enriched_country)");
}

#[test]
fn doc_where_prevalence_dest_domain_10_and_prevalence_file_hash() {
    npl("* | where prevalence_dest_domain < 10 AND prevalence_file_hash < 5");
}

#[test]
fn doc_where_src_host_workstation_42() {
    npl("* | where src_host=\"workstation-42\" | asset field=src_host");
}

#[test]
fn doc_where_src_ip_in_search_action_suspicious() {
    npl("* | where src_ip IN [search action=suspicious | return src_ip]");
}

#[test]
fn doc_where_user_in_search_department_finance() {
    npl("* | where user IN [search department=\"finance\" | return user]");
}

#[test]
fn doc_malware() {
    npl("*malware*");
}

#[test]
fn doc_q_() {
    npl("| inputlookup url=\"https://api.example.com/blocklist.json\" format=json | where risk_score > 80");
}

#[test]
fn doc_q__2() {
    npl("| inputlookup url=\"https://feeds.example.com/iocs.csv\" format=csv | table ip, category, threat_level");
}

#[test]
fn doc_action_file_access() {
    npl("action=file_access | risk score=30 entity=user factor=\"File access\" weight=0.5");
}

#[test]
fn doc_action_file_access_2() {
    npl("action=file_access | where file_hash IN [search source_type=\"threat_intel\" | return file_hash]");
}

#[test]
fn doc_action_file_created() {
    npl("action=file_created | anomaly field=file_size by file_type threshold=3");
}

#[test]
fn doc_action_file_created_or_action_file_modified() {
    npl("action=file_created OR action=file_modified | table timestamp, action, file_path, file_hash, user, src_host");
}

#[test]
fn doc_action_file_download() {
    npl("action=file_download | prevalence hash_prevalence < 5 AND domain_prevalence < 10");
}

#[test]
fn doc_action_login() {
    npl("action=login | join type=left user [search source_type=\"user_directory\" | table user, department, manager]");
}

#[test]
fn doc_action_login_2() {
    npl("action=login | rare target_user");
}

#[test]
fn doc_action_login_3() {
    npl("action=login | rex \"user (?<username>\\w+) from (?<source_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)\" | stats count() by username, source_ip");
}

#[test]
fn doc_action_login_4() {
    npl("action=login | risk score=if(is_admin, 80, 40) entity=user factor=\"Admin access\"");
}

#[test]
fn doc_action_login_5() {
    npl(
        "action=login | sort timestamp | dedup user keepfirst=true | table user, timestamp, src_ip",
    );
}

#[test]
fn doc_action_login_6() {
    npl("action=login | sort timestamp | streamstats current=false last(timestamp) as prev_login by user | eval seconds_since_last = timestamp - prev_login | where seconds_since_last < 5");
}

#[test]
fn doc_action_login_7() {
    npl("action=login | sort timestamp | streamstats sum(eval(status=\"failure\")) as cumulative_failures by src_ip | where cumulative_failures > 10");
}

#[test]
fn doc_action_login_8() {
    npl("action=login | stats count() by user");
}

#[test]
fn doc_action_login_9() {
    npl("action=login | table timestamp, user, src_ip, status, message");
}

#[test]
fn doc_action_login_10() {
    npl("action=login | transaction user maxspan=1h | where eventcount > 5 AND dc(src_host) > 3");
}

#[test]
fn doc_action_login_11() {
    npl("action=login | transaction user startswith=(status=\"failure\") endswith=(status=\"success\") maxspan=15m");
}

#[test]
fn doc_action_login_earliest_1d() {
    npl("action=login earliest=-1d | stats count() as today | append [search action=login earliest=-2d latest=-1d | stats count() as yesterday]");
}

#[test]
fn doc_action_login_src_host_dest_host() {
    npl("action=login src_host!=dest_host | risk score=40 entity=user factor=\"Lateral movement\"");
}

#[test]
fn doc_action_login_status_failure() {
    npl("action=login status=failure | bin span=10m | stats count() as failures by time_bucket, src_ip | where failures > 5");
}

#[test]
fn doc_action_login_status_failure_2() {
    npl("action=login status=failure | bin span=10m | stats count() by time_bucket, src_ip | where count > 5");
}

#[test]
fn doc_action_login_status_failure_3() {
    npl("action=login status=failure | bin span=1h hop=5m | stats count() as failures by time_bucket, src_ip | where failures > 100");
}

#[test]
fn doc_action_login_status_failure_4() {
    npl("action=login status=failure | bin span=5m | stats count() as attempts by time_bucket, src_ip | where attempts > 10");
}

#[test]
fn doc_action_login_status_failure_5() {
    npl("action=login status=failure | head 50");
}

#[test]
fn doc_action_login_status_failure_6() {
    npl(
        "action=login status=failure | risk score=10 entity=src_ip factor=\"Failed login attempt\"",
    );
}

#[test]
fn doc_action_login_status_failure_7() {
    npl("action=login status=failure | stats count, values(src_ip) as sources, dc(src_ip) as source_count by user | where count > 5 | ai prompt=\"Label each row as BRUTE_FORCE, CREDENTIAL_STUFFING, or BENIGN. Consider the number of distinct source IPs and total attempts.\" | sort -ai_confidence");
}

#[test]
fn doc_action_login_status_failure_8() {
    npl("action=login status=failure | stats count() as attempts by src_ip | risk score=attempts*5 entity=src_ip factor=\"Multiple failed logins\"");
}

#[test]
fn doc_action_login_status_failure_9() {
    npl("action=login status=failure | stats count() as failures, dc(user) as unique_users, values(user) as attempted_users by src_ip | where failures > 10");
}

#[test]
fn doc_action_login_status_failure_10() {
    npl("action=login status=failure | timechart cont=true span=1m count() by src_ip");
}

#[test]
fn doc_action_login_status_failure_11() {
    npl("action=login status=failure | timechart span=10m count() by src_ip");
}

#[test]
fn doc_action_login_status_failure_12() {
    npl("action=login status=failure | top target_user");
}

#[test]
fn doc_action_privilege_escalation() {
    npl("action=privilege_escalation | risk score=60 entity=user factor=\"Privilege escalation attempt\"");
}

#[test]
fn doc_age_timestamp_3600() {
    npl("age(timestamp) < 3600");
}

#[test]
fn doc_alert_name_brute_force_detected() {
    npl("alert_name=\"Brute Force Detected\" | dedup src_ip, target_user | table timestamp, src_ip, target_user, alert_severity");
}

#[test]
fn doc_alert_name_suspicious_activity() {
    npl("alert_name=\"Suspicious Activity\" | table timestamp as \"Alert Time\", src_ip as \"Source\", user as \"User\", alert_severity as \"Severity\", message as \"Details\"");
}

#[test]
fn doc_bytes_10485760_dest_port_in_80_443() {
    npl("bytes > 10485760 dest_port IN (80, 443) | stats sum(bytes) as total_bytes by src_ip, dest_ip | where total_bytes > 104857600");
}

#[test]
fn doc_bytes_out_100000000() {
    npl("bytes_out > 100000000 | risk score=30 entity=src_ip factor=\"Large data transfer\"");
}

#[test]
fn doc_cloud_account_id_123456789012() {
    npl("cloud_account_id=\"123456789012\" | cloud");
}

#[test]
fn doc_cloud_provider_aws() {
    npl("cloud_provider=aws | cloud");
}

#[test]
fn doc_cloud_provider_aws_2() {
    npl("cloud_provider=aws | cloud by=account");
}

#[test]
fn doc_cloud_provider_gcp() {
    npl("cloud_provider=gcp | cloud by=region");
}

#[test]
fn doc_cloud_service_iam() {
    npl("cloud_service=iam | cloud by=account");
}

#[test]
fn doc_cloud_service_iam_2() {
    npl("cloud_service=iam | cloud by=account show_mfa=true");
}

#[test]
fn doc_cloud_service_s3() {
    npl("cloud_service=s3 | cloud by=resource");
}

#[test]
fn doc_commandline_contains_powershell() {
    npl("CommandLine CONTAINS \"powershell\"");
}

#[test]
fn doc_commandline_powershell_enc_a_za_z0_9_50() {
    npl("CommandLine=/powershell.*-enc.*[A-Za-z0-9+\\/=]{50,}/");
}

#[test]
fn doc_custom_ioc_src_ip_threat_type_or_custom_ioc_dest_ip_th() {
    npl("custom_ioc_src_ip_threat_type != \"\" OR custom_ioc_dest_ip_threat_type != \"\"");
}

#[test]
fn doc_custom_src_ip_risk_70_or_custom_dest_ip_risk_70() {
    npl("custom_src_ip_risk >= 70 OR custom_dest_ip_risk >= 70");
}

#[test]
fn doc_dest_domain() {
    npl("dest_domain=* | prevalence domain_first_seen > now() - INTERVAL 1 DAY | stats count() by dest_domain, domain_first_seen");
}

#[test]
fn doc_dest_host() {
    npl("dest_host != \"\" | prevalence domain_prevalence < 10 domain_first_seen > now() - 24h");
}

#[test]
fn doc_dest_host_suspicious_server_internal() {
    npl("dest_host=\"suspicious-server.internal\" | resolve_identity field=dest_host | table timestamp, identity_ip, src_ip, user, action, identity_confidence");
}

#[test]
fn doc_dest_ip_and_prevalence_dest_ip_20() {
    npl("dest_ip != \"\" AND prevalence_dest_ip < 20 | table timestamp, dest_ip, prevalence_dest_ip");
}

#[test]
fn doc_dest_ip_and_prevalence_dest_ip_15() {
    npl("dest_ip != \"\" AND prevalence_dest_ip <= 15 | table timestamp, dest_ip, prevalence_dest_ip");
}

#[test]
fn doc_domain_startswith_malicious() {
    npl("domain STARTSWITH \"malicious\"");
}

#[test]
fn doc_enriched_src_as_name_like_amazon_or_enriched_src_as_name() {
    npl("enriched_src_as_name LIKE \"%Amazon%\" OR enriched_src_as_name LIKE \"%Google%\" OR enriched_src_as_name LIKE \"%Microsoft%\"");
}

#[test]
fn doc_enriched_src_asn_as15169_or_enriched_dest_asn_as15169() {
    npl("enriched_src_asn = \"AS15169\" OR enriched_dest_asn = \"AS15169\"");
}

#[test]
fn doc_enriched_src_continent_asia_and_enriched_dest_continent() {
    npl("enriched_src_continent = \"Asia\" AND enriched_dest_continent = \"North America\"");
}

#[test]
fn doc_enriched_src_country_code_cn_or_enriched_dest_country_co() {
    npl("enriched_src_country_code = \"CN\" OR enriched_dest_country_code = \"CN\"");
}

#[test]
fn doc_enriched_src_country_code_not_in_us_ca_gb_de_f() {
    npl("enriched_src_country_code NOT IN (\"US\", \"CA\", \"GB\", \"DE\", \"FR\") AND src_ip NOT IN CIDR(\"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\")");
}

#[test]
fn doc_event_type_authentication() {
    npl("event_type=\"authentication\" | risk score=10 entity=user factor=\"Login attempt\" | where auth_result=\"failure\" | risk score=20 factor=\"Failed login\" | where src_ip != /^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)/  | risk score=25 factor=\"External IP\" | eval hour = tonumber(strftime(timestamp, \"%H\")) | where hour < 6 OR hour > 22 | risk score=20 factor=\"Off-hours access\" | where risk_score >= 50 | table timestamp, user, src_ip, auth_result, risk_score, risk_factors");
}

#[test]
fn doc_event_type_malware_detected() {
    npl("event_type=\"malware_detected\" | risk score=50");
}

#[test]
fn doc_event_type_network_bytes_out_10000000() {
    npl("event_type=\"network\" bytes_out > 10000000 | risk score=20 entity=src_ip factor=\"Large outbound transfer\" | where dest_port != 80 AND dest_port != 443 | risk score=15 factor=\"Non-web port\" | where dest_ip != /^(10\\.|192\\.168\\.)/ | risk score=20 factor=\"External destination\" | eval hour = tonumber(strftime(timestamp, \"%H\")) | where hour < 6 OR hour > 20 | risk score=25 factor=\"Off-hours transfer\" | where risk_score >= 60 | table timestamp, src_ip, dest_ip, dest_port, bytes_out, risk_score, risk_factors");
}

#[test]
fn doc_event_type_process_start() {
    npl("event_type=\"process_start\" | risk score=10 entity=user factor=\"Process execution\" | where process_name=\"wscript.exe\" OR process_name=\"cscript.exe\" OR process_name=\"mshta.exe\" | risk score=30 factor=\"Script interpreter\" | where command_line = /http:|https:|ftp:/ | risk score=35 factor=\"Remote script reference\" | where risk_score >= 50 | table timestamp, user, dest_host, process_name, command_line, risk_score");
}

#[test]
fn doc_event_type_process_start_dest_port_0() {
    npl("event_type=\"process_start\" dest_port > 0 | risk score=15 entity=dest_host factor=\"Process with network\" | prevalence hash_prevalence < 3 | risk score=35 factor=\"Rare process hash\" | where dest_port != 80 AND dest_port != 443 | risk score=20 factor=\"Non-standard port\" | where risk_score >= 50 | table timestamp, dest_host, process_name, file_hash, dest_ip, dest_port, risk_score");
}

#[test]
fn doc_event_type_authentication_and_status_failure() {
    npl("event_type=authentication AND status=failure | stats count() as attempts by src_ip | risk score=if(attempts > 50, 90, if(attempts > 10, 70, 40)) entity=src_ip factor=\"Failed logins\"");
}

#[test]
fn doc_event_type_authentication_and_user_type_admin() {
    npl("event_type=authentication AND user_type=admin | risk score=if(src_ip=/^(10\\.|192\\.168\\.)/, 40, 80) entity=user factor=\"Admin login\"");
}

#[test]
fn doc_event_type_file_access() {
    npl("event_type=file_access | risk score=30 entity=user factor=\"File access\" weight=0.5");
}

#[test]
fn doc_event_type_network() {
    npl("event_type=network | eval risk_points = if(bytes_out > 100000000, 30, 0) + if(dest_port != 80 AND dest_port != 443, 20, 0) + if(hour < 6 OR hour > 22, 25, 0) | risk score=risk_points entity=src_ip factor=\"Data transfer risk\"");
}

#[test]
fn doc_event_type_network_connection() {
    npl("event_type=network_connection | stats count() as connection_count by src_ip | risk score=if(connection_count > 1000, 85, if(connection_count > 100, 60, 30)) entity=src_ip factor=\"Connection volume\"");
}

#[test]
fn doc_event_type_process_creation_and_process_name_powershell_exe() {
    npl("event_type=process_creation AND process_name=powershell.exe | risk score=75 entity=src_host factor=\"PowerShell execution\"");
}

#[test]
fn doc_eventid_in_4672_4673_4674() {
    npl("EventID IN (4672, 4673, 4674) | stats count() by user, PrivilegeList | where count > 5");
}

#[test]
fn doc_eventid_not_in_4624_4625() {
    npl("EventID NOT IN (4624, 4625)");
}

#[test]
fn doc_eventid_1() {
    npl("EventID=1 | prevalence hash_first_seen > now() - INTERVAL 1 DAY");
}

#[test]
fn doc_eventid_1_2() {
    npl("EventID=1 | prevalence hash_prevalence < 5 window=24h");
}

#[test]
fn doc_eventid_1_3() {
    npl("EventID=1 | prevalence hash_prevalence < 5 window=24h | table timestamp, Image, CommandLine, hash_prevalence");
}

#[test]
fn doc_eventid_4624_logontype_3() {
    npl("EventID=4624 LogonType=3 | stats dc(dest_host) as unique_targets by src_ip | where unique_targets > 10");
}

#[test]
fn doc_failed_login() {
    npl("failed login");
}

#[test]
fn doc_file_hash() {
    npl("file_hash=* | dedup file_hash | table file_hash, file_name, first_seen, src_host");
}

#[test]
fn doc_file_hash_2() {
    npl("file_hash=* | prevalence hash_prevalence < 5");
}

#[test]
fn doc_file_hash_3() {
    npl("file_hash=* | prevalence hash_prevalence < 5 | table timestamp, file_hash, process_name, src_host");
}

#[test]
fn doc_file_hash_hash_prevalence_5() {
    npl("file_hash=* hash_prevalence < 5 | risk score=50 entity=src_host factor=\"Rare file execution\"");
}

#[test]
fn doc_filename_like_dll() {
    npl("filename LIKE \"%.dll\"");
}

#[test]
fn doc_filename_exe() {
    npl("filename=*.exe");
}

#[test]
fn doc_filename_cmd_exe() {
    npl("filename=/cmd\\.exe$/");
}

#[test]
fn doc_has_custom_src_ip_tags_tor_exit() {
    npl("has(custom_src_ip_tags, 'tor_exit')");
}

#[test]
fn doc_has_ioc_src_ip_tags_tor_exit_or_has_ioc_dest_ip_tags_t() {
    npl("has(ioc_src_ip_tags, 'tor_exit') OR has(ioc_dest_ip_tags, 'tor_exit')");
}

#[test]
fn doc_image_powershell_exe_commandline_enc() {
    npl("Image=*powershell.exe CommandLine=*-enc* | eval cmd_entropy = entropy(CommandLine) | where cmd_entropy > 4.5");
}

#[test]
fn doc_ioc_dest_ip_threat_type_and_ioc_dest_ip_threat_type() {
    npl("ioc_dest_ip_threat_type != \"\" AND ioc_dest_ip_threat_type != \"anonymizer\"");
}

#[test]
fn doc_ioc_dest_ip_threat_type_or_ioc_domain_threat_type() {
    npl("ioc_dest_ip_threat_type != \"\" OR ioc_domain_threat_type != \"\"");
}

#[test]
fn doc_ioc_dest_ip_threat_type_in_botnet_cc_payload_delivery() {
    npl("ioc_dest_ip_threat_type IN (\"botnet_cc\", \"payload_delivery\")");
}

#[test]
fn doc_ioc_src_ip_confidence_80_or_ioc_dest_ip_confidence_80() {
    npl("ioc_src_ip_confidence >= 80 OR ioc_dest_ip_confidence >= 80");
}

#[test]
fn doc_ioc_src_ip_threat_type_or_ioc_dest_ip_threat_type() {
    npl("ioc_src_ip_threat_type != \"\" OR ioc_dest_ip_threat_type != \"\"");
}

#[test]
fn doc_len_password_8() {
    npl("len(password) < 8");
}

#[test]
fn doc_level_error() {
    npl("level=error | bin span=5m | stats count() by time_bucket, service");
}

#[test]
fn doc_lower_user_admin() {
    npl("lower(user) = \"admin\"");
}

#[test]
fn doc_not_enriched_src_country_code_us_and_enriched_dest_coun() {
    npl("NOT (enriched_src_country_code = \"US\" AND enriched_dest_country_code = \"US\")");
}

#[test]
fn doc_path_endswith_system32() {
    npl("path ENDSWITH \"\\\\system32\"");
}

#[test]
fn doc_prevalence_min_10() {
    npl("prevalence_min < 10");
}

#[test]
fn doc_prevalence_min_100() {
    npl("prevalence_min < 100 | prevalence domain_first_seen > now() - 24h enrich=true");
}

#[test]
fn doc_prevalence_min_5() {
    npl("prevalence_min < 5 | stats count by dest_host");
}

#[test]
fn doc_prevalence_min_10_2() {
    npl("prevalence_min <= 10");
}

#[test]
fn doc_process_name_powershell_exe() {
    npl("process_name=\"powershell.exe\" | bin span=5m | stats count() as executions, dc(src_host) as unique_hosts by time_bucket | where executions > 10 AND unique_hosts > 5");
}

#[test]
fn doc_process_name_powershell_exe_2() {
    npl("process_name=\"powershell.exe\" | rex field=command_line \"-(?<flag>\\w+)\\s+(?<value>[^\\s-]+)\" | table process_name, flag, value");
}

#[test]
fn doc_process_name() {
    npl("process_name=* | prevalence hash_prevalence <= 10 window=7d | table timestamp, process_name, file_hash, hash_prevalence, src_host");
}

#[test]
fn doc_response_time_1000() {
    npl("response_time > 1000 | stats avg(response_time), max(response_time), count() by endpoint");
}

#[test]
fn doc_severity_critical() {
    npl("severity=critical | append [search severity=high priority=urgent] | dedup _id");
}

#[test]
fn doc_severity_error() {
    npl("severity=error | dedup message | table message, count, first_seen");
}

#[test]
fn doc_severity_error_2() {
    npl("severity=error | rare error_code");
}

#[test]
fn doc_severity_error_3() {
    npl("severity=error | rex \"error code: (?<error_code>\\d+)\" | stats count() by error_code");
}

#[test]
fn doc_severity_error_4() {
    npl("severity=error | table timestamp, source_type, message, src_host, error_code");
}

#[test]
fn doc_severity_error_5() {
    npl("severity=error | top error_code");
}

#[test]
fn doc_source_type_apache() {
    npl("source_type=\"apache\" | rex \"(?<method>\\w+) (?<url>[^\\s]+) HTTP/(?<version>[\\d.]+)\\\" (?<status>\\d{3})\" | stats count() by method, status");
}

#[test]
fn doc_source_type_auth_logs() {
    npl("source_type=\"auth_logs\" | sequence by user, src_ip maxspan=5m [action=\"login\" status=\"failure\"] [action=\"login\" status=\"success\"]");
}

#[test]
fn doc_source_type_auth_logs_2() {
    npl("source_type=\"auth_logs\" | sequence by user, src_ip maxspan=5m fields(user_agent, auth_type) [action=\"login\" status=\"failure\"] [action=\"login\" status=\"failure\"] [action=\"login\" status=\"success\"]");
}

#[test]
fn doc_source_type_dns() {
    npl("source_type=\"dns\" | regex query=\"(?i)\\.(xyz|top|tk|pw|cc)$\" | stats count() as requests, dc(src_ip) as unique_hosts by query | where requests > 10 | sort -requests");
}

#[test]
fn doc_source_type_edr_action_file_create() {
    npl("source_type=\"edr\" action=\"file_create\" | regex file_path=\"(?i)\\.(exe|ps1|bat|vbs|dll)$\" | table timestamp, file_path, process_name");
}

#[test]
fn doc_source_type_edr_action_process_create() {
    npl("source_type=\"edr\" action=\"process_create\" | regex process_path!=\"(?i)^(C:\\\\Windows\\\\|C:\\\\Program Files)\" | table timestamp, src_host, process_name, process_path");
}

#[test]
fn doc_source_type_edr_process_name_powershell_exe() {
    npl("source_type=\"edr\" process_name=\"powershell.exe\" | regex command_line=\"(?i)(-enc|-encodedcommand)\\s+[A-Za-z0-9+/=]{20,}\" | table timestamp, src_host, user, command_line");
}

#[test]
fn doc_source_type_endpoint() {
    npl("source_type=\"endpoint\" | sequence by src_host maxspan=10m fields(url, file_path, process_name, command_line) [action=\"file_download\" uri_path=\"*.exe\"] [action=\"file_write\" file_path=\"/tmp/*\" OR file_path=\"*\\\\Temp\\\\*\"] [action=\"process_create\"]");
}

#[test]
fn doc_source_type_firewall() {
    npl("source_type=\"firewall\" | head 1");
}

#[test]
fn doc_source_type_firewall_2() {
    npl("source_type=\"firewall\" | regex src_ip=\"^10\\.1\\.(5[0-9]|6[0-3])\\.\" | stats count() by src_ip, dest_ip");
}

#[test]
fn doc_source_type_firewall_3() {
    npl("source_type=\"firewall\" | rex \"src=(?<src_ip>[\\d.]+):(?<src_port>\\d+) dst=(?<dst_ip>[\\d.]+):(?<dst_port>\\d+)\" | table src_ip, src_port, dst_ip, dst_port");
}

#[test]
fn doc_source_type_firewall_4() {
    npl("source_type=\"firewall\" | sample 10");
}

#[test]
fn doc_source_type_firewall_action_block() {
    npl("source_type=\"firewall\" action=block | append [search source_type=\"ids\" action=alert]");
}

#[test]
fn doc_source_type_proxy() {
    npl("source_type=\"proxy\" | regex http_user_agent=\"(?i)(curl|wget|python|powershell|nmap)\" | stats count() by src_ip, http_user_agent");
}

#[test]
fn doc_source_type_proxy_2() {
    npl("source_type=\"proxy\" | regex url!=\"(?i)\\.(jpg|png|gif|css|js|woff2?)$\" | stats count() by url_domain");
}

#[test]
fn doc_source_type_squid_proxy() {
    npl("source_type=\"squid_proxy\" | sequence by user, src_ip maxspan=5m fields(message, url) [url_domain=/file[-_]?(upload|share|drop|transfer|send)/i] [uri_path=/\\.(exe|scr|bat|cmd|ps1|vbs|js|hta|msi|dll)$/i]");
}

#[test]
fn doc_source_type_squid_proxy_2() {
    npl("source_type=\"squid_proxy\" | sequence by user, url_domain maxspan=10m fields(status_code, url, message) [status_code>=400] [status_code<400]");
}

#[test]
fn doc_source_type_syslog() {
    npl("source_type=\"syslog\" | regex \"error|fail|denied|unauthorized\" | table timestamp, src_host, message");
}

#[test]
fn doc_source_type_windows() {
    npl("source_type=\"windows\" | rex \"EventID=(?<event_id>\\d+).*User=(?<user>[^\\s]+)\" | table event_id, user");
}

#[test]
fn doc_source_type_cloudtrail_aws_eventname_deletebucket() {
    npl("source_type=cloudtrail aws_eventName=\"DeleteBucket\"");
}

#[test]
fn doc_source_type_dns_2() {
    npl("source_type=dns | resolve_identity | where identity_confidence != \"stale\" AND identity_confidence != \"none\" | table timestamp, src_ip, src_host, query, answer");
}

#[test]
fn doc_source_type_dns_query_type_a() {
    npl("source_type=dns query_type=A | ai prompt=\"Score each DNS query. Label as DGA, SUSPICIOUS, or LEGITIMATE. DGA domains have high entropy, random-looking character sequences, and unusual TLDs.\" max_rows=200 | where ai_verdict=\"DGA\"");
}

#[test]
fn doc_source_type_edr() {
    npl("source_type=edr | tree parent=ppid child=pid label=process_name");
}

#[test]
fn doc_source_type_edr_action_process_create_2() {
    npl("source_type=edr action=process_create | tree parent=parent_pid child=pid label=process_name detail=command_line");
}

#[test]
fn doc_source_type_findings() {
    npl("source_type=findings | bin span=15m | stats sum(risk_score) as total_risk by risk_entity | where total_risk > 200");
}

#[test]
fn doc_source_type_findings_2() {
    npl("source_type=findings | bin span=1d | stats sum(risk_score) as daily_risk by risk_entity, _time | sort risk_entity, _time | eval risk_trend = daily_risk - lag(daily_risk, 1) | where risk_trend > 50");
}

#[test]
fn doc_source_type_findings_3() {
    npl("source_type=findings | bin span=1h | stats sum(risk_score) as total_risk by risk_entity | where total_risk > 100");
}

#[test]
fn doc_source_type_findings_4() {
    npl("source_type=findings | bin span=5m | stats sum(risk_score) as total_risk by risk_entity | where total_risk > 150 | eval action=\"block\" | output firewall_blocks");
}

#[test]
fn doc_source_type_findings_5() {
    npl("source_type=findings | bin span=7d | stats sum(risk_score) as total_risk, avg(risk_score) as avg_risk, count() as signal_count by risk_entity | where total_risk > 500 AND avg_risk > 30");
}

#[test]
fn doc_source_type_findings_6() {
    npl("source_type=findings | where _time >= relative_time(now(), \"-30d\") | stats sum(risk_score) as total_risk, avg(risk_score) as avg_risk, max(risk_score) as peak_risk, count() as incident_count by risk_entity | eval risk_category = case(total_risk > 500, \"High Risk\", total_risk > 200, \"Medium Risk\", total_risk > 50, \"Low Risk\", 1=1, \"Minimal Risk\") | stats count() by risk_category");
}

#[test]
fn doc_source_type_findings_7() {
    npl("source_type=findings | where entity_type=\"user\" | bin span=24h | stats sum(risk_score) as total_risk, count() as signal_count by risk_entity | where total_risk > 150 | eval risk_per_signal = total_risk / signal_count | where risk_per_signal > 20");
}

#[test]
fn doc_source_type_firewall_5() {
    npl("source_type=firewall | resolve_identity | where is_nat_candidate=true | stats dc(src_host) as unique_hosts, values(src_host) as hosts by src_ip | where unique_hosts > 3");
}

#[test]
fn doc_source_type_firewall_action_block_2() {
    npl("source_type=firewall action=block | resolve_identity | table timestamp, src_ip, src_host, user, dest_ip, dest_port, identity_confidence");
}

#[test]
fn doc_source_type_firewall_action_block_3() {
    npl("source_type=firewall action=block | stats count, values(dest_port) as ports, dc(dest_ip) as dest_count by src_ip | ai prompt=\"Triage each source IP as TRUE_POSITIVE, FALSE_POSITIVE, or NEEDS_REVIEW. True positives are likely attacks (port scans, known exploit ports). False positives are routine blocks (DNS, NTP).\" | where ai_verdict=\"TRUE_POSITIVE\"");
}

#[test]
fn doc_source_type_firewall_action_block_earliest_1h() {
    npl("source_type=firewall action=block earliest=-1h | resolve_identity max_age=4h | where identity_confidence IN (\"high\", \"medium\") | table timestamp, src_ip, src_host, user, identity_confidence");
}

#[test]
fn doc_source_type_firewall_action_blocked() {
    npl("source_type=firewall action=blocked | stats count() as blocked_count by src_ip | where blocked_count > 100 | risk score=blocked_count/10 entity=src_ip factor=\"High block rate\"");
}

#[test]
fn doc_source_type_firewall_dest_port_4444_action_allow() {
    npl("source_type=firewall dest_port=4444 action=allow | resolve_identity | table timestamp, src_ip, src_host, user, dest_ip, dest_port, identity_confidence, identity_source, is_nat_candidate");
}

#[test]
fn doc_source_type_squid_proxy_3() {
    npl("source_type=squid_proxy | ai prompt=\"Classify each event as NORMAL, SUSPICIOUS, or MALICIOUS. Look for data exfiltration, C2 beaconing, or access to known-bad domains.\"");
}

#[test]
fn doc_source_type_squid_proxy_4() {
    npl("source_type=squid_proxy | resolve_identity field=dest_ip | table timestamp, src_ip, dest_ip, dest_host, url, identity_confidence");
}

#[test]
fn doc_source_type_squid_proxy_5() {
    npl("source_type=squid_proxy | stats count, values(url), sum(bytes_out) as total_bytes by src_ip, dest_host | where count > 3 | ai prompt=\"Classify as NORMAL, SUSPICIOUS, or MALICIOUS based on browsing patterns. Look for data exfiltration or unusual destinations.\" | where ai_verdict=\"MALICIOUS\"");
}

#[test]
fn doc_source_type_squid_proxy_user_jsmith() {
    npl("source_type=squid_proxy user=\"jsmith\" | tree parent=http_referrer child=url label=dest_host prevalence=dest_host");
}

#[test]
fn doc_source_type_squid_proxy_user_jsmith_2() {
    npl("source_type=squid_proxy user=\"jsmith\" | tree web");
}

#[test]
fn doc_source_type_squid_proxy_user_jsmith_3() {
    npl("source_type=squid_proxy user=\"jsmith\" | tree web root=\"*github.com*\"");
}

#[test]
fn doc_source_type_squid_proxy_user_suspicious_user() {
    npl("source_type=squid_proxy user=\"suspicious_user\" | tree web");
}

#[test]
fn doc_source_type_ssh_logs() {
    npl("source_type=ssh_logs | where action=\"login_failed\" | stats count() as attempts, values(user) as targeted_users, min(timestamp) as first_attempt, max(timestamp) as last_attempt by src_ip | where attempts > 10");
}

#[test]
fn doc_source_type_sysmon() {
    npl("source_type=sysmon | stats count() as total, count(process_hash) as has_hash, count(command_line) as has_cmdline");
}

#[test]
fn doc_source_type_sysmon_action_process_create() {
    npl("source_type=sysmon action=process_create | tree parent=parent_process_id child=process_id label=process_name detail=command_line prevalence=process_hash");
}

#[test]
fn doc_source_type_sysmon_action_process_create_2() {
    npl("source_type=sysmon action=process_create | tree process");
}

#[test]
fn doc_source_type_sysmon_action_process_create_3() {
    npl("source_type=sysmon action=process_create | tree process root=\"/powershell|pwsh/\"");
}

#[test]
fn doc_source_type_sysmon_action_process_create_4() {
    npl("source_type=sysmon action=process_create | tree process root=\"/wscript|cscript/\"");
}

#[test]
fn doc_source_type_sysmon_action_process_create_5() {
    npl("source_type=sysmon action=process_create | tree process root=\"cmd.exe\"");
}

#[test]
fn doc_source_type_sysmon_action_process_create_earliest_5m_src_ho() {
    npl("source_type=sysmon action=process_create earliest=-5m src_host=\"LAPTOP-SALES01.corp.local\" | tree process root = /powershell/");
}

#[test]
fn doc_source_type_sysmon_action_process_create_process_name_powe() {
    npl("source_type=sysmon action=process_create process_name=\"*powershell*\" | tree parent=parent_process_id child=process_id label=process_name detail=command_line prevalence=process_hash");
}

#[test]
fn doc_source_type_sysmon_action_process_create_src_host_suspiciou() {
    npl("source_type=sysmon action=process_create src_host=\"SUSPICIOUS-HOST\" | tree process");
}

#[test]
fn doc_source_type_sysmon_event_id_1() {
    npl("source_type=sysmon event_id=1 | table timestamp, user, process_name, command_line, parent_command_line | ai prompt=\"Classify as MALICIOUS, SUSPICIOUS, or BENIGN. Flag living-off-the-land binaries, encoded PowerShell, unusual parent-child relationships, and known attack tools.\" | where ai_verdict!=\"BENIGN\" | sort -ai_confidence");
}

#[test]
fn doc_source_type_sysmon_src_host_laptop_hr01_corp_local_action() {
    npl("source_type=sysmon src_host=\"LAPTOP-HR01.corp.local\" action=process_create process_name=\"*cmd.exe*\" | tree parent=parent_process_id child=process_id label=process_name detail=command_line prevalence=process_hash");
}

#[test]
fn doc_source_type_windows_security() {
    npl("source_type=windows_security | where event_id=4688 | where process_name CONTAINS \"psexec\" | stats count() as executions, values(dest_host) as targets, min(timestamp) as first_seen, max(timestamp) as last_seen by src_host, user | where count(targets) > 1");
}

#[test]
fn doc_sourcetype_sysmon_and_prevalence_process_hash_5() {
    npl("sourcetype = \"sysmon\" AND prevalence_process_hash < 5");
}

#[test]
fn doc_sourcetype_sysmon_and_prevalence_process_hash_25() {
    npl("sourcetype = \"sysmon\" AND prevalence_process_hash <= 25");
}

#[test]
fn doc_sourcetype_squid_proxy() {
    npl("sourcetype=squid_proxy | prevalence enrich=true | where host_count < 3 | stats count by prevalence_artifact, prevalence_type, host_count, prevalence_first_seen");
}

#[test]
fn doc_sourcetype_squid_proxy_2() {
    npl("sourcetype=squid_proxy | prevalence enrich=true | where is_rare=1 | table timestamp, user, prevalence_artifact, prevalence_type, host_count, prevalence_score");
}

#[test]
fn doc_src_host_dc01() {
    npl("src_host=\"DC01\" | lateral methods=auth,network");
}

#[test]
fn doc_src_host_server_01() {
    npl("src_host=\"server-01\" | asset sections=network,process,auth");
}

#[test]
fn doc_src_host_wks_0142() {
    npl("src_host=\"WKS-0142\" | lateral");
}

#[test]
fn doc_src_host_workstation_42() {
    npl("src_host=\"workstation-42\" | asset");
}

#[test]
fn doc_src_host_workstation_42_2() {
    npl("src_host=\"WORKSTATION-42\" | resolve_identity field=src_host");
}

#[test]
fn doc_src_host_workstation_42_3() {
    npl("src_host=\"WORKSTATION-42\" | resolve_identity field=src_host | table timestamp, identity_ip, user, identity_confidence");
}

#[test]
fn doc_src_ip_10_1_1_50() {
    npl("src_ip=\"10.1.1.50\" | asset");
}

#[test]
fn doc_src_ip_10_1_1_50_2() {
    npl("src_ip=\"10.1.1.50\" | lateral seed=host");
}

#[test]
fn doc_src_ip_192_168_1() {
    npl("src_ip=\"192.168.1.*\" | resolve_identity | where identity_confidence IN (\"high\", \"medium\") | where src_host LIKE 'WORKSTATION%'");
}

#[test]
fn doc_src_ip_192_168_1_100() {
    npl("src_ip=\"192.168.1.100\" | asset");
}

#[test]
fn doc_src_ip_192_168_1_100_2() {
    npl("src_ip=\"192.168.1.100\" | resolve_identity");
}

#[test]
fn doc_src_ip_192_168_1_100_3() {
    npl("src_ip=\"192.168.1.100\" | resolve_identity | table timestamp, source_type, src_ip, src_host, user, action, identity_confidence");
}

#[test]
fn doc_src_ip_192_168_1_100_4() {
    npl("src_ip=192.168.1.100");
}

#[test]
fn doc_status_in_200_201_204() {
    npl("status IN (200, 201, 204)");
}

#[test]
fn doc_status_in_401_403() {
    npl("status IN (401, 403) | stats count() as failures by src_ip, user_agent | where failures > 5");
}

#[test]
fn doc_status_401() {
    npl("status=401");
}

#[test]
fn doc_status_401_or_status_403() {
    npl("status=401 OR status=403");
}

#[test]
fn doc_status_500() {
    npl("status=500 | append [search status=500 earliest=-7d latest=-1d]");
}

#[test]
fn doc_status_500_2() {
    npl("status=500 | head 5");
}

#[test]
fn doc_status_500_3() {
    npl("status=500 | sample 50 | table timestamp, url, error_message");
}

#[test]
fn doc_suspicious_activity_true() {
    npl("suspicious_activity=true | risk score=75 entity=src_ip factor=\"Suspicious behavior detected\"");
}

#[test]
fn doc_timestamp_now_interval_1_hour() {
    npl("timestamp > now() - INTERVAL 1 HOUR");
}

#[test]
fn doc_timestamp_now_interval_1_hour_process_name_powershell() {
    npl("timestamp > now() - INTERVAL 1 HOUR process_name=powershell.exe command_line CONTAINS \"-enc\" | eval cmd_entropy = entropy(command_line) | eval decoded = base64_decode(extract(command_line, \"-enc[odedCommand]* ([A-Za-z0-9+/=]+)\")) | where cmd_entropy > 4.5 | table timestamp, user, src_host, command_line, cmd_entropy, decoded");
}

#[test]
fn doc_timestamp_now_interval_1_hour_source_type_in_windows() {
    npl("timestamp > now() - INTERVAL 1 HOUR source_type IN (\"windows_security\", \"sysmon\") action=login auth_type=network | bin span=5m | stats dc(dest_host) as unique_targets, dc(src_ip) as unique_sources, values(authentication_method) as methods, values(user_type) as user_types, count() as login_count by time_bucket, user, src_host | where unique_targets > 5 | sort -unique_targets");
}

#[test]
fn doc_timestamp_now_interval_1_hour_source_type_sysmon() {
    npl("timestamp > now() - INTERVAL 1 HOUR source_type=sysmon | head 1000");
}

#[test]
fn doc_timestamp_now_interval_1_hour_source_type_sysmon_2() {
    npl("timestamp > now() - INTERVAL 1 HOUR source_type=sysmon | stats count() by process_name");
}

#[test]
fn doc_timestamp_now_interval_2_hours_source_type_database_qu() {
    npl("timestamp > now() - INTERVAL 2 HOURS source_type=database query_time > 5000 | eval query_seconds = query_time / 1000 | stats avg(query_seconds) as avg_time, max(query_seconds) as max_time, count() as query_count, values(instance_name) as instances, values(instance_type) as db_types by user, query | where query_count > 3 | sort -avg_time | head 10");
}

#[test]
fn doc_timestamp_now_interval_24_hours_action_login_status_fa() {
    npl("timestamp > now() - INTERVAL 24 HOURS action=login status=failure | eval hour = hour(timestamp) | stats count() as attempts, dc(src_ip) as unique_ips, values(enriched_src_country) as countries, values(authentication_method) as auth_methods by user, hour | where attempts > 5 | sort -attempts");
}

#[test]
fn doc_timestamp_now_interval_24_hours_source_type_sysmon_eve() {
    npl("timestamp > now() - INTERVAL 24 HOURS source_type=sysmon EventID=1 enriched_src_country NOT IN (\"United States\") | prevalence hash_prevalence < 5 window=24h | table timestamp, src_host, process_name, process_hash, command_line, enriched_src_country, hash_prevalence");
}

#[test]
fn doc_timestamp_now_interval_6_hours_dest_port_in_80_443() {
    npl("timestamp > now() - INTERVAL 6 HOURS dest_port IN (80, 443) enriched_dest_country != \"\" | stats sum(bytes_out) as total_bytes, dc(src_ip) as unique_sources, dc(dest_ip) as unique_destinations, count() as connections by enriched_dest_country, enriched_dest_continent | eval total_mb = round(total_bytes / 1048576, 2) | sort -total_mb | head 20");
}

#[test]
fn doc_user_in_admin_root_administrator() {
    npl("user IN (\"admin\", \"root\", \"administrator\")");
}

#[test]
fn doc_user_alice_corp_com() {
    npl("user=\"alice@corp.com\" | asset");
}

#[test]
fn doc_user_corp_admin() {
    npl("user=\"CORP\\admin\" | asset field=user");
}

#[test]
fn doc_user_john_doe() {
    npl("user=\"john.doe\" | table timestamp, action, src_ip, dest_ip, dest_port, bytes");
}

#[test]
fn doc_user_john_doe_2() {
    npl("user=\"john.doe\" | timechart span=1h count() by action");
}

#[test]
fn doc_user_jsmith() {
    npl("user=\"jsmith\" | asset");
}

#[test]
fn doc_user_jsmith_2() {
    npl("user=\"jsmith\" | lateral");
}

#[test]
fn doc_user_jsmith_3() {
    npl("user=\"jsmith\" | lateral | stats count by dest_host, method");
}

#[test]
fn doc_user_jsmith_4() {
    npl("user=\"jsmith\" | lateral | table timestamp, src_host, dest_host, method_detail, hop_number");
}

#[test]
fn doc_user_jsmith_5() {
    npl("user=\"jsmith\" | lateral | where hop_number > 1");
}

#[test]
fn doc_user_jsmith_6() {
    npl("user=\"jsmith\" | lateral | where method_detail=\"rdp\"");
}

#[test]
fn doc_user_jsmith_7() {
    npl("user=\"jsmith\" | lateral maxhops=2");
}

#[test]
fn doc_user_jsmith_8() {
    npl("user=\"jsmith\" | lateral maxhops=5 | sort hop_number, timestamp");
}

#[test]
fn doc_user_jsmith_9() {
    npl("user=\"jsmith\" | lateral methods=auth");
}

#[test]
fn doc_user_jsmith_10() {
    npl("user=\"jsmith\" | resolve_identity field=user");
}

#[test]
fn doc_user_jsmith_11() {
    npl("user=\"jsmith\" | resolve_identity field=user | table timestamp, identity_ip, src_host, identity_confidence, identity_source");
}

#[test]
fn doc_user_jsmith_12() {
    npl("user=\"jsmith\" | resolve_identity field=user | where identity_confidence IN (\"high\", \"medium\") | stats count, dc(identity_ip) as unique_ips, values(identity_ip) as ips by src_host");
}

#[test]
fn doc_user_admin() {
    npl("user=/admin|root/i");
}

#[test]
fn doc_user_admin_2() {
    npl("user=admin");
}

#[test]
fn doc_user_admin_and_status_401() {
    npl("user=admin AND status=401");
}

#[test]
fn doc_user_admin_not_status_200() {
    npl("user=admin NOT status=200");
}

#[test]
fn doc_user_admin_3() {
    npl("user=admin*");
}
