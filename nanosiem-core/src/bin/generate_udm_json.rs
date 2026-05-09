// SPDX-License-Identifier: AGPL-3.0-or-later

/// CLI tool to generate JSON representation of UDM fields
///
/// Usage: cargo run --bin generate_udm_json > udm_fields.json
use nanosiem_core::udm::csv_parser::parse_udm_csv;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize)]
struct UdmFieldJson {
    field_name: String,
    snake_case_name: String,
    pascal_case_name: String,
    data_models: Vec<String>,
    inferred_type: String,
    category: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UdmFieldsOutput {
    total_fields: usize,
    fields: Vec<UdmFieldJson>,
    fields_by_category: BTreeMap<String, Vec<String>>,
    fields_by_type: BTreeMap<String, Vec<String>>,
}

fn main() {
    let csv_path = "docs/udmfields.csv";

    let fields = match parse_udm_csv(csv_path) {
        Ok(fields) => fields,
        Err(e) => {
            eprintln!("Error parsing CSV: {}", e);
            std::process::exit(1);
        }
    };

    // Convert to JSON-friendly format
    let mut json_fields = Vec::new();
    let mut fields_by_category: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut fields_by_type: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for field in &fields {
        let category = format!("{:?}", field.category);
        let data_type = format!("{:?}", field.inferred_type);

        json_fields.push(UdmFieldJson {
            field_name: field.field_name.clone(),
            snake_case_name: field.snake_case_name.clone(),
            pascal_case_name: field.pascal_case_name.clone(),
            data_models: field.data_models.clone(),
            inferred_type: data_type.clone(),
            category: category.clone(),
        });

        fields_by_category
            .entry(category)
            .or_insert_with(Vec::new)
            .push(field.field_name.clone());

        fields_by_type
            .entry(data_type)
            .or_insert_with(Vec::new)
            .push(field.field_name.clone());
    }

    let output = UdmFieldsOutput {
        total_fields: fields.len(),
        fields: json_fields,
        fields_by_category,
        fields_by_type,
    };

    // Output as pretty JSON
    match serde_json::to_string_pretty(&output) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("Error serializing to JSON: {}", e);
            std::process::exit(1);
        }
    }
}
