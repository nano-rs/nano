// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generate ClickHouse ALTER TABLE statements for all UDM fields
//!
//! This tool generates a complete ClickHouse migration file that adds
//! all 500+ UDM fields as columns to the logs table.
//!
//! Usage:
//!   cargo run --bin generate_clickhouse_udm_schema > clickhouse/052_add_all_udm_fields.sql

use nanosiem_core::udm::fields::UdmField;
use std::collections::HashSet;

fn main() {
    println!("-- Add all UDM fields to ClickHouse logs table");
    println!("-- Generated from UDM field definitions");
    println!("-- Total fields: {}", UdmField::all().len());
    println!();

    // Fields that already exist in the base schema (init.sql)
    let existing_fields: HashSet<&str> = [
        "id",
        "timestamp",
        "message",
        "metadata",
        "source_type",
        "src_ip",
        "dest_ip",
        "src_host",
        "dest_host",
        "src_port",
        "dest_port",
        "protocol",
        "bytes_in",
        "bytes_out",
        "user",
        "action",
        "event_type", // NAN-659: ALIAS column in init.sql, must be skipped here
        "status",
        "auth_type",
        "auth_result",
        "session_id",
        "process_name",
        "process_id",
        "parent_command_line",
        "command_line",
        "file_path",
        "file_name",
        "file_hash",
        "file_action",
        "user_agent",
        "enriched_src_country",
        "enriched_src_country_code",
        "enriched_src_continent",
        "enriched_src_continent_code",
        "enriched_src_asn",
        "enriched_src_as_name",
        "enriched_src_as_domain",
        "enriched_dest_country",
        "enriched_dest_country_code",
        "enriched_dest_continent",
        "enriched_dest_continent_code",
        "enriched_dest_asn",
        "enriched_dest_as_name",
        "enriched_dest_as_domain",
        "ingest_time",
        "enrich_time",
    ]
    .into_iter()
    .collect();

    // Fields added in 051_add_udm_fields.sql
    let fields_051: HashSet<&str> = [
        "src_user",
        "dest_user",
        "status_code",
        "process_path",
        "process_guid",
        "process_hash",
        "parent_process_id",
        "parent_process_path",
        "url",
        "url_domain",
        "uri_path",
        "http_method",
        "http_user_agent",
        "http_referrer",
        "http_content_type",
        "registry_path",
        "registry_value_data",
        "query",
        "query_type",
        "duration",
    ]
    .into_iter()
    .collect();

    let mut new_fields = Vec::new();

    for field in UdmField::all() {
        let field_name = field.to_string();

        // Skip if already exists
        if existing_fields.contains(field_name.as_str()) || fields_051.contains(field_name.as_str())
        {
            continue;
        }

        new_fields.push((field_name, field));
    }

    println!("-- Adding {} new UDM fields", new_fields.len());
    println!();

    // Group fields by type for better organization
    let mut string_fields = Vec::new();
    let mut int_fields = Vec::new();
    let mut float_fields = Vec::new();
    let mut bool_fields = Vec::new();

    for (field_name, _field) in new_fields {
        let clickhouse_type = infer_clickhouse_type(&field_name);

        match clickhouse_type {
            ClickHouseType::String | ClickHouseType::LowCardinalityString => {
                string_fields.push((field_name, clickhouse_type));
            }
            ClickHouseType::Int32
            | ClickHouseType::Int64
            | ClickHouseType::UInt16
            | ClickHouseType::UInt32
            | ClickHouseType::UInt64 => {
                int_fields.push((field_name, clickhouse_type));
            }
            ClickHouseType::Float64 => {
                float_fields.push((field_name, clickhouse_type));
            }
            ClickHouseType::Bool => {
                bool_fields.push((field_name, clickhouse_type));
            }
        }
    }

    // Output string fields
    if !string_fields.is_empty() {
        println!("-- String fields ({} fields)", string_fields.len());
        for (field_name, field_type) in string_fields {
            let (ch_type, default) = match field_type {
                ClickHouseType::LowCardinalityString => ("LowCardinality(String)", "''"),
                _ => ("String", "''"),
            };
            println!(
                "ALTER TABLE logs ADD COLUMN IF NOT EXISTS {} {} DEFAULT {};",
                field_name, ch_type, default
            );
        }
        println!();
    }

    // Output integer fields
    if !int_fields.is_empty() {
        println!("-- Integer fields ({} fields)", int_fields.len());
        for (field_name, field_type) in int_fields {
            let (ch_type, default) = match field_type {
                ClickHouseType::Int32 => ("Int32", "0"),
                ClickHouseType::Int64 => ("Int64", "0"),
                ClickHouseType::UInt16 => ("UInt16", "0"),
                ClickHouseType::UInt32 => ("UInt32", "0"),
                ClickHouseType::UInt64 => ("UInt64", "0"),
                _ => ("Int32", "0"),
            };
            println!(
                "ALTER TABLE logs ADD COLUMN IF NOT EXISTS {} {} DEFAULT {};",
                field_name, ch_type, default
            );
        }
        println!();
    }

    // Output float fields
    if !float_fields.is_empty() {
        println!("-- Float fields ({} fields)", float_fields.len());
        for (field_name, _) in float_fields {
            println!(
                "ALTER TABLE logs ADD COLUMN IF NOT EXISTS {} Float64 DEFAULT 0.0;",
                field_name
            );
        }
        println!();
    }

    // Output boolean fields
    if !bool_fields.is_empty() {
        println!("-- Boolean fields ({} fields)", bool_fields.len());
        for (field_name, _) in bool_fields {
            println!(
                "ALTER TABLE logs ADD COLUMN IF NOT EXISTS {} UInt8 DEFAULT 0;",
                field_name
            );
        }
        println!();
    }

    // Add indexes for commonly queried fields
    println!("-- Add indexes for commonly queried fields");
    println!("ALTER TABLE logs ADD INDEX IF NOT EXISTS idx_dest_user dest_user TYPE bloom_filter GRANULARITY 4;");
    println!("ALTER TABLE logs ADD INDEX IF NOT EXISTS idx_src_mac src_mac TYPE bloom_filter GRANULARITY 4;");
    println!("ALTER TABLE logs ADD INDEX IF NOT EXISTS idx_dest_mac dest_mac TYPE bloom_filter GRANULARITY 4;");
    println!("ALTER TABLE logs ADD INDEX IF NOT EXISTS idx_signature signature TYPE bloom_filter GRANULARITY 4;");
    println!("ALTER TABLE logs ADD INDEX IF NOT EXISTS idx_vendor_product vendor_product TYPE set(100) GRANULARITY 4;");
    println!();
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum ClickHouseType {
    String,
    LowCardinalityString,
    Int32,
    Int64,
    UInt16,
    UInt32,
    UInt64,
    Float64,
    Bool,
}

/// Infer ClickHouse type from field name
fn infer_clickhouse_type(field_name: &str) -> ClickHouseType {
    // Port numbers
    if field_name.ends_with("_port") {
        return ClickHouseType::UInt16;
    }

    // IDs (process_id, parent_process_id, etc.)
    if field_name.ends_with("_id") || field_name.ends_with("_pid") {
        return ClickHouseType::UInt32;
    }

    // Counts
    if field_name.ends_with("_count") || field_name.starts_with("count_") {
        return ClickHouseType::UInt64;
    }

    // Sizes and bytes
    if field_name.ends_with("_size")
        || field_name.ends_with("_bytes")
        || field_name.contains("_memory")
    {
        return ClickHouseType::UInt64;
    }

    // Percentages and ratios
    if field_name.ends_with("_percent")
        || field_name.ends_with("_ratio")
        || field_name.contains("_rate")
    {
        return ClickHouseType::Float64;
    }

    // Time fields (milliseconds, microseconds)
    if field_name.ends_with("_time")
        || field_name.ends_with("_duration")
        || field_name.ends_with("_latency")
    {
        return ClickHouseType::Int64;
    }

    // Boolean fields
    if field_name.starts_with("is_")
        || field_name.starts_with("has_")
        || field_name.ends_with("_enabled")
        || field_name.ends_with("_supported")
    {
        return ClickHouseType::Bool;
    }

    // Scores (CVSS, risk, etc.)
    if field_name.ends_with("_score") || field_name == "cvss" || field_name == "priority" {
        return ClickHouseType::Float64;
    }

    // Low cardinality string fields (categories, types, statuses, etc.)
    if field_name.ends_with("_type")
        || field_name.ends_with("_status")
        || field_name.ends_with("_category")
        || field_name.ends_with("_severity")
        || field_name.ends_with("_priority")
        || field_name.ends_with("_level")
        || field_name.ends_with("_mode")
        || field_name.ends_with("_method")
        || field_name == "protocol"
        || field_name == "transport"
        || field_name == "direction"
    {
        return ClickHouseType::LowCardinalityString;
    }

    // Default to String for everything else
    ClickHouseType::String
}
