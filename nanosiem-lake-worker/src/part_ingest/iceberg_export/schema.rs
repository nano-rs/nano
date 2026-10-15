// SPDX-License-Identifier: AGPL-3.0-or-later

//! Public schema contracts are independent of serving generations.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, ensure, Result};
use iceberg::spec::{MappedField, NameMapping, NestedFieldRef, Schema, StructType, Type};
use iceberg::table::Table;
use iceberg::{TableIdent, TableRequirement, TableUpdate};

pub const CONTRACT_VERSION: &str = "nano.schema_contract_version";
pub const OCSF_VERSION: &str = "nano.ocsf_version";
pub const TENANT: &str = "nano.export.tenant_id";
pub const FROZEN: &str = "nano.export.frozen";

/// Version is an operator-selected public contract, never inferred from OCSF semver.
#[derive(Clone)]
pub struct SchemaContract {
    pub version: u32,
    pub ocsf_version: String,
    /// Logical desired fields; existing IDs remain authoritative during evolution.
    pub schema: Schema,
}

impl SchemaContract {
    pub fn table_ident(&self, namespace: &str, dataset: &str) -> Result<TableIdent> {
        ensure!(self.version > 0, "schema contract version must be positive");
        for value in [namespace, dataset] {
            ensure!(
                !value.is_empty()
                    && value.len() <= 128
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "invalid export identifier"
            );
        }
        ensure!(
            !self.ocsf_version.is_empty()
                && self.ocsf_version.len() <= 64
                && self
                    .ocsf_version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "invalid OCSF version"
        );
        Ok(TableIdent::from_strs([
            namespace,
            &format!("{dataset}_v{}", self.version),
        ])?)
    }

    pub fn properties(&self, tenant: &str) -> HashMap<String, String> {
        HashMap::from([
            (CONTRACT_VERSION.to_string(), self.version.to_string()),
            (OCSF_VERSION.to_string(), self.ocsf_version.clone()),
            (TENANT.to_string(), tenant.to_string()),
            ("commit.retry.num-retries".to_string(), "0".to_string()),
        ])
    }

    pub fn validate_table(&self, table: &Table, tenant: &str, location: &str) -> Result<()> {
        self.validate_identity(table, tenant, location)?;
        ensure!(table.metadata().properties().get(FROZEN).map(String::as_str) != Some("true"), "export contract table is frozen");
        Ok(())
    }

    pub(super) fn validate_identity(&self, table: &Table, tenant: &str, location: &str) -> Result<()> {
        let properties = table.metadata().properties();
        ensure!(
            properties.get(TENANT).map(String::as_str) == Some(tenant),
            "export table belongs to another tenant"
        );
        ensure!(
            properties.get(CONTRACT_VERSION) == Some(&self.version.to_string()),
            "export table contract version mismatch"
        );
        ensure!(
            table.metadata().location().trim_end_matches('/') == location.trim_end_matches('/'),
            "export table location mismatch"
        );
        ensure!(
            table.metadata().format_version() == iceberg::spec::FormatVersion::V2,
            "export requires Iceberg v2"
        );
        ensure!(
            table
                .metadata()
                .default_partition_spec()
                .fields()
                .is_empty(),
            "export requires unpartitioned hour/day files"
        );
        Ok(())
    }

    /// Metadata updates accompany the data snapshot in one fenced REST commit.
    /// Sparse incoming schemas retain old fields; deletions/renames are never applied.
    pub fn evolution(
        &self,
        table: &Table,
    ) -> Result<(Schema, Vec<TableRequirement>, Vec<TableUpdate>)> {
        let current = table.metadata().current_schema();
        let mut last_id = table.metadata().last_column_id();
        let fields = merge_fields(
            current.as_struct().fields(),
            self.schema.as_struct().fields(),
            &mut last_id,
        )?;
        let changed = fields != current.as_struct().fields();
        let schema = Schema::builder()
            .with_schema_id(if changed {
                table
                    .metadata()
                    .schemas_iter()
                    .map(|s| s.schema_id())
                    .max()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("schema ID exhausted"))?
            } else {
                current.schema_id()
            })
            .with_fields(fields)
            .with_identifier_field_ids(current.identifier_field_ids())
            .build()?;
        let mut requirements = vec![TableRequirement::CurrentSchemaIdMatch {
            current_schema_id: current.schema_id(),
        }];
        let mut updates = Vec::new();
        if changed {
            requirements.push(TableRequirement::LastAssignedFieldIdMatch {
                last_assigned_field_id: table.metadata().last_column_id(),
            });
            updates.push(TableUpdate::AddSchema {
                schema: schema.clone(),
            });
            updates.push(TableUpdate::SetCurrentSchema {
                schema_id: schema.schema_id(),
            });
        }
        updates.push(TableUpdate::SetProperties {
            updates: HashMap::from([
                (OCSF_VERSION.to_string(), self.ocsf_version.clone()),
                (
                    iceberg::spec::DEFAULT_SCHEMA_NAME_MAPPING.to_string(),
                    serde_json::to_string(&name_mapping(&schema))?,
                ),
            ]),
        });
        Ok((schema, requirements, updates))
    }
}

fn merge_fields(
    current: &[NestedFieldRef],
    desired: &[NestedFieldRef],
    last_id: &mut i32,
) -> Result<Vec<NestedFieldRef>> {
    let mut fields = current.to_vec();
    for field in desired {
        if let Some(index) = fields.iter().position(|old| old.name == field.name) {
            fields[index] = merge_field(&fields[index], field, last_id)?;
        } else {
            ensure!(
                !field.required && field.initial_default.is_none() && field.write_default.is_none(),
                "new export columns must be optional without defaults"
            );
            fields.push(fresh_field(field, last_id)?);
        }
    }
    Ok(fields)
}

fn merge_field(
    old: &NestedFieldRef,
    desired: &NestedFieldRef,
    last_id: &mut i32,
) -> Result<NestedFieldRef> {
    ensure!(
        old.initial_default == desired.initial_default
            && old.write_default == desired.write_default,
        "changing export field defaults requires a new contract"
    );
    ensure!(
        old.required == desired.required,
        "changing export field nullability requires a new contract"
    );
    let mut field = old.as_ref().clone();
    field.field_type = Box::new(
        match (old.field_type.as_ref(), desired.field_type.as_ref()) {
            (Type::Primitive(a), Type::Primitive(b)) if a == b => Type::Primitive(a.clone()),
            (Type::Struct(a), Type::Struct(b)) => Type::Struct(StructType::new(merge_fields(
                a.fields(),
                b.fields(),
                last_id,
            )?)),
            (Type::List(a), Type::List(b)) => Type::List(iceberg::spec::ListType::new(
                merge_field(&a.element_field, &b.element_field, last_id)?,
            )),
            (Type::Map(a), Type::Map(b)) => {
                // Map keys define identity; even additive changes would alter key equality.
                ensure!(
                    same_logical_type(&a.key_field.field_type, &b.key_field.field_type),
                    "changing export map keys requires a new contract"
                );
                Type::Map(iceberg::spec::MapType::new(
                    a.key_field.clone(),
                    merge_field(&a.value_field, &b.value_field, last_id)?,
                ))
            }
            _ => bail!("changing export field types requires a new contract"),
        },
    );
    Ok(Arc::new(field))
}

fn same_logical_type(a: &Type, b: &Type) -> bool {
    // IDs supplied by inference are irrelevant, but map-key shape is immutable.
    match (a, b) {
        (Type::Primitive(a), Type::Primitive(b)) => a == b,
        (Type::Struct(a), Type::Struct(b)) => {
            a.fields().len() == b.fields().len()
                && a.fields().iter().zip(b.fields()).all(|(a, b)| {
                    a.name == b.name
                        && a.required == b.required
                        && same_logical_type(&a.field_type, &b.field_type)
                })
        }
        (Type::List(a), Type::List(b)) => {
            a.element_field.required == b.element_field.required
                && same_logical_type(&a.element_field.field_type, &b.element_field.field_type)
        }
        (Type::Map(a), Type::Map(b)) => {
            same_logical_type(&a.key_field.field_type, &b.key_field.field_type)
                && a.value_field.required == b.value_field.required
                && same_logical_type(&a.value_field.field_type, &b.value_field.field_type)
        }
        _ => false,
    }
}

fn fresh_field(source: &NestedFieldRef, last_id: &mut i32) -> Result<NestedFieldRef> {
    *last_id = last_id
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("field ID exhausted"))?;
    let mut field = source.as_ref().clone();
    field.id = *last_id;
    field.field_type = Box::new(match source.field_type.as_ref() {
        Type::Primitive(p) => Type::Primitive(p.clone()),
        Type::Struct(s) => Type::Struct(StructType::new(
            s.fields()
                .iter()
                .map(|f| fresh_field(f, last_id))
                .collect::<Result<_>>()?,
        )),
        Type::List(l) => Type::List(iceberg::spec::ListType::new(fresh_field(
            &l.element_field,
            last_id,
        )?)),
        Type::Map(m) => Type::Map(iceberg::spec::MapType::new(
            fresh_field(&m.key_field, last_id)?,
            fresh_field(&m.value_field, last_id)?,
        )),
    });
    Ok(Arc::new(field))
}

pub fn name_mapping(schema: &Schema) -> NameMapping {
    fn mapped(field: &NestedFieldRef) -> MappedField {
        let children = match field.field_type.as_ref() {
            Type::Primitive(_) => vec![],
            Type::Struct(s) => s.fields().iter().map(mapped).collect(),
            Type::List(l) => vec![mapped(&l.element_field)],
            Type::Map(m) => vec![mapped(&m.key_field), mapped(&m.value_field)],
        };
        MappedField::new(Some(field.id), vec![field.name.clone()], children)
    }
    NameMapping::new(schema.as_struct().fields().iter().map(mapped).collect())
}
