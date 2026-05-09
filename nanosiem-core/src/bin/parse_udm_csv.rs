// SPDX-License-Identifier: AGPL-3.0-or-later

/// CLI tool to parse UDM fields CSV and generate structured output
///
/// Usage: cargo run --bin parse_udm_csv
use nanosiem_core::udm::csv_parser::{generate_statistics, parse_udm_csv, UdmFieldDefinition};
use std::collections::HashMap;

fn main() {
    println!("=== UDM Fields CSV Parser ===\n");

    // Parse the CSV
    let csv_path = "docs/udmfields.csv";
    println!("Parsing {}...\n", csv_path);

    let fields = match parse_udm_csv(csv_path) {
        Ok(fields) => fields,
        Err(e) => {
            eprintln!("Error parsing CSV: {}", e);
            std::process::exit(1);
        }
    };

    // Generate and print statistics
    let stats = generate_statistics(&fields);
    println!("{}", stats);

    // Print sample fields from each category
    println!("\n=== Sample Fields by Category ===\n");

    let mut fields_by_category: HashMap<String, Vec<&UdmFieldDefinition>> = HashMap::new();
    for field in &fields {
        let category = format!("{:?}", field.category);
        fields_by_category
            .entry(category)
            .or_insert_with(Vec::new)
            .push(field);
    }

    let mut categories: Vec<_> = fields_by_category.keys().collect();
    categories.sort();

    for category in categories {
        let category_fields = &fields_by_category[category];
        println!("{}:", category);

        // Show first 5 fields in each category
        for field in category_fields.iter().take(5) {
            println!(
                "  - {} ({})",
                field.field_name,
                format!("{:?}", field.inferred_type)
            );
            println!("    Snake case: {}", field.snake_case_name);
            println!("    Pascal case: {}", field.pascal_case_name);
            if !field.data_models.is_empty() {
                println!("    Data models: {}", field.data_models.join(", "));
            }
        }

        if category_fields.len() > 5 {
            println!("  ... and {} more", category_fields.len() - 5);
        }
        println!();
    }

    // Generate Rust enum code snippet
    println!("\n=== Generated Rust Enum Snippet (first 20 fields) ===\n");
    println!("pub enum UdmField {{");
    for field in fields.iter().take(20) {
        println!("    {},", field.pascal_case_name);
    }
    println!("    // ... {} more fields", fields.len() - 20);
    println!("}}");

    // Generate field metadata snippet
    println!("\n=== Generated Metadata Snippet (first 5 fields) ===\n");
    for field in fields.iter().take(5) {
        println!(
            "UdmField::{} => UdmFieldMetadata {{",
            field.pascal_case_name
        );
        println!("    name: \"{}\",", field.field_name);
        println!("    column_name: \"{}\",", field.snake_case_name);
        println!("    data_type: UdmDataType::{:?},", field.inferred_type);
        println!("    category: UdmFieldCategory::{:?},", field.category);
        println!("    description: \"TODO: Add description\",");
        println!(
            "    data_models: &[{}],",
            field
                .data_models
                .iter()
                .map(|m| format!("\"{}\"", m))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("}},\n");
    }

    println!("\n=== Summary ===");
    println!("Successfully parsed {} unique UDM fields", fields.len());
    println!("Ready for code generation!");
}
