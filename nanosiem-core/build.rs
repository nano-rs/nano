/// Build script to generate UDM field definitions from CSV
///
/// This script parses docs/udmfields.csv and generates Rust code for:
/// - UdmField enum with all variants
/// - column_name() implementation
/// - category() implementation
/// - data_type() implementation
/// - FromStr implementation
/// - description() and data_models() implementations
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone)]
struct FieldDef {
    snake_case: String,
    pascal_case: String,
    data_models: Vec<String>,
    category: String,
    data_type: String,
}

fn main() {
    println!("cargo:rerun-if-changed=docs/udmfields.csv");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("generated_fields.rs");

    // Parse CSV
    let fields = parse_csv("docs/udmfields.csv").expect("Failed to parse CSV");

    // Generate code
    let code = generate_code(&fields);

    // Write to output file
    let mut f = File::create(&dest_path).expect("Failed to create output file");
    f.write_all(code.as_bytes())
        .expect("Failed to write generated code");

    println!("Generated {} fields to {:?}", fields.len(), dest_path);
}

fn parse_csv(path: &str) -> Result<Vec<FieldDef>, String> {
    let file = File::open(path).map_err(|e| format!("Failed to open CSV: {}", e))?;
    let reader = BufReader::new(file);
    let mut fields = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("Line {}: {}", line_num, e))?;

        // Skip header and empty lines
        if line_num == 0 || line.trim().is_empty() {
            continue;
        }

        // Parse CSV line (simple split - doesn't handle quoted commas)
        let parts: Vec<&str> = line.split(',').collect();
        if parts.is_empty() {
            continue;
        }

        let field_name = parts[0].trim();
        if field_name.is_empty() {
            continue;
        }

        // Parse data models (remaining parts)
        let data_models: Vec<String> = parts[1..]
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let snake_case = field_name.to_string();
        let pascal_case = to_pascal_case(field_name);
        let category = infer_category(&data_models);
        let data_type = infer_data_type(field_name);

        fields.push(FieldDef {
            snake_case,
            pascal_case,
            data_models,
            category,
            data_type,
        });
    }

    Ok(fields)
}

fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect()
}

fn infer_category(data_models: &[String]) -> String {
    for model in data_models {
        let model_lower = model.to_lowercase();

        if model_lower.contains("authentication") {
            return "Authentication".to_string();
        } else if model_lower.contains("network traffic")
            || model_lower.contains("network sessions")
        {
            return "Network".to_string();
        } else if model_lower.contains("endpoint") {
            return "Endpoint".to_string();
        } else if model_lower.contains("email") {
            return "Email".to_string();
        } else if model_lower.contains("web") {
            return "Web".to_string();
        } else if model_lower.contains("database") {
            return "Database".to_string();
        } else if model_lower.contains("malware") {
            return "Malware".to_string();
        } else if model_lower.contains("intrusion") {
            return "Intrusion".to_string();
        } else if model_lower.contains("vulnerabilities") {
            return "Vulnerability".to_string();
        } else if model_lower.contains("certificates") {
            return "Certificate".to_string();
        } else if model_lower.contains("dns") || model_lower.contains("network resolution") {
            return "Dns".to_string();
        } else if model_lower.contains("performance") {
            return "Performance".to_string();
        } else if model_lower.contains("inventory") {
            return "Inventory".to_string();
        } else if model_lower.contains("cloud") {
            return "Cloud".to_string();
        } else if model_lower.contains("change") {
            return "Change".to_string();
        } else if model_lower.contains("data access") {
            return "DataAccess".to_string();
        } else if model_lower.contains("data loss prevention") {
            return "DataLossPrevention".to_string();
        } else if model_lower.contains("alerts") {
            return "Alerts".to_string();
        } else if model_lower.contains("file") {
            return "Endpoint".to_string(); // File operations are endpoint events
        } else if model_lower.contains("system") {
            return "System".to_string();
        } else if model_lower.contains("enrichment") && !model_lower.contains("custom") {
            return "Enrichment".to_string();
        } else if model_lower.contains("threat intelligence") {
            return "ThreatIntelligence".to_string();
        } else if model_lower.contains("custom enrichment") {
            return "CustomEnrichment".to_string();
        } else if model_lower.contains("prevalence") {
            return "Prevalence".to_string();
        } else if model_lower.contains("risk") {
            return "Risk".to_string();
        } else if model_lower.contains("detection") {
            return "Detection".to_string();
        } else if model_lower.contains("interprocess messaging") {
            return "InterprocessMessaging".to_string();
        }
    }

    "Custom".to_string()
}

fn infer_data_type(field_name: &str) -> String {
    let name_lower = field_name.to_lowercase();

    // Array fields (tags, answers)
    if name_lower.ends_with("_tags") {
        return "Array".to_string();
    }

    // IP address fields
    if name_lower.contains("_ip") || name_lower == "ip" {
        return "IpAddress".to_string();
    }

    // Timestamp fields
    if name_lower.contains("_time") || name_lower.contains("timestamp") || name_lower == "time" {
        return "Timestamp".to_string();
    }

    // Boolean fields
    if name_lower.starts_with("is_")
        || name_lower.starts_with("has_")
        || name_lower == "ioc_matched"
    {
        return "Boolean".to_string();
    }

    // Integer fields
    if name_lower.ends_with("_count")
        || name_lower.ends_with("_id")
        || name_lower.ends_with("_port")
        || name_lower.ends_with("_code")
        || name_lower.ends_with("_confidence")
        || name_lower.starts_with("prevalence_")
    {
        return "Integer".to_string();
    }

    // Long fields
    if name_lower.contains("bytes") || name_lower.ends_with("_size") {
        return "Long".to_string();
    }

    // Float fields
    if name_lower.ends_with("_percent")
        || name_lower.ends_with("_ratio")
        || name_lower.ends_with("_score")
    {
        return "Float".to_string();
    }

    "String".to_string()
}

fn generate_code(fields: &[FieldDef]) -> String {
    let mut code = String::new();

    // File header
    code.push_str("// AUTO-GENERATED CODE - DO NOT EDIT\n");
    code.push_str("// Generated from docs/udmfields.csv by build.rs\n\n");

    // Generate enum
    code.push_str("/// Standard UDM fields for normalized log data\n");
    code.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]\n");
    code.push_str("#[serde(rename_all = \"snake_case\")]\n");
    code.push_str("pub enum UdmField {\n");

    for field in fields {
        code.push_str(&format!("    /// {}\n", field.snake_case));
        code.push_str(&format!("    {},\n", field.pascal_case));
    }

    code.push_str("}\n\n");

    // Generate impl block
    code.push_str("impl UdmField {\n");

    // column_name() method
    code.push_str("    /// Get the database column name for this UDM field\n");
    code.push_str("    pub fn column_name(&self) -> &'static str {\n");
    code.push_str("        match self {\n");
    for field in fields {
        code.push_str(&format!(
            "            UdmField::{} => \"{}\",\n",
            field.pascal_case, field.snake_case
        ));
    }
    code.push_str("        }\n");
    code.push_str("    }\n\n");

    // category() method
    code.push_str("    /// Get the category for this field\n");
    code.push_str("    pub fn category(&self) -> UdmFieldCategory {\n");
    code.push_str("        match self {\n");
    for field in fields {
        code.push_str(&format!(
            "            UdmField::{} => UdmFieldCategory::{},\n",
            field.pascal_case, field.category
        ));
    }
    code.push_str("        }\n");
    code.push_str("    }\n\n");

    // data_type() method
    code.push_str("    /// Get the data type for this field\n");
    code.push_str("    pub fn data_type(&self) -> UdmDataType {\n");
    code.push_str("        match self {\n");
    for field in fields {
        code.push_str(&format!(
            "            UdmField::{} => UdmDataType::{},\n",
            field.pascal_case, field.data_type
        ));
    }
    code.push_str("        }\n");
    code.push_str("    }\n\n");

    // description() method - using field name for now
    code.push_str("    /// Get a human-readable description of this field\n");
    code.push_str("    pub fn description(&self) -> &'static str {\n");
    code.push_str("        // For now, return the column name\n");
    code.push_str("        // TODO: Add proper descriptions in CSV\n");
    code.push_str("        self.column_name()\n");
    code.push_str("    }\n\n");

    // data_models() method
    code.push_str("    /// Get applicable data models for this field\n");
    code.push_str("    pub fn data_models(&self) -> &'static [&'static str] {\n");
    code.push_str("        match self {\n");
    for field in fields {
        if field.data_models.is_empty() {
            code.push_str(&format!(
                "            UdmField::{} => &[],\n",
                field.pascal_case
            ));
        } else {
            let models: Vec<String> = field
                .data_models
                .iter()
                .map(|m| format!("\"{}\"", m))
                .collect();
            code.push_str(&format!(
                "            UdmField::{} => &[{}],\n",
                field.pascal_case,
                models.join(", ")
            ));
        }
    }
    code.push_str("        }\n");
    code.push_str("    }\n\n");

    // metadata() method
    code.push_str("    /// Get field metadata\n");
    code.push_str("    pub fn metadata(&self) -> UdmFieldMetadata {\n");
    code.push_str("        UdmFieldMetadata {\n");
    code.push_str("            name: self.column_name(),\n");
    code.push_str("            column_name: self.column_name(),\n");
    code.push_str("            data_type: self.data_type(),\n");
    code.push_str("            category: self.category(),\n");
    code.push_str("            description: self.description(),\n");
    code.push_str("            data_models: self.data_models(),\n");
    code.push_str("        }\n");
    code.push_str("    }\n\n");

    // all() method
    code.push_str("    /// Get all UDM fields\n");
    code.push_str("    pub fn all() -> &'static [UdmField] {\n");
    code.push_str("        &[\n");
    for field in fields {
        code.push_str(&format!("            UdmField::{},\n", field.pascal_case));
    }
    code.push_str("        ]\n");
    code.push_str("    }\n\n");

    // by_category() method
    code.push_str("    /// Get all fields in a specific category\n");
    code.push_str("    pub fn by_category(category: UdmFieldCategory) -> Vec<UdmField> {\n");
    code.push_str("        Self::all()\n");
    code.push_str("            .iter()\n");
    code.push_str("            .filter(|f| f.category() == category)\n");
    code.push_str("            .copied()\n");
    code.push_str("            .collect()\n");
    code.push_str("    }\n");

    code.push_str("}\n\n");

    // Generate FromStr implementation
    code.push_str("impl FromStr for UdmField {\n");
    code.push_str("    type Err = UdmFieldParseError;\n\n");
    code.push_str("    fn from_str(s: &str) -> Result<Self, Self::Err> {\n");
    code.push_str("        match s {\n");
    for field in fields {
        code.push_str(&format!(
            "            \"{}\" => Ok(UdmField::{}),\n",
            field.snake_case, field.pascal_case
        ));
    }
    code.push_str("            _ => Err(UdmFieldParseError(s.to_string())),\n");
    code.push_str("        }\n");
    code.push_str("    }\n");
    code.push_str("}\n");

    code
}
