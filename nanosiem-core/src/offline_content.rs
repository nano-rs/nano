// SPDX-License-Identifier: AGPL-3.0-or-later
//! C12 offline catalog verification. This yields immutable verified content;
//! it cannot import, build, approve, deploy or activate anything.
#[cfg(feature = "enterprise")]
use crate::airgap::{BundleType, verify_bundle};
use serde::{Deserialize, Serialize};
#[cfg(feature = "enterprise")]
use sha2::{Digest, Sha256};
pub mod staging;
pub mod build;
pub mod parser_apply;
pub mod runtime;
#[cfg(feature = "enterprise")]
use std::io::Read;

pub const PROVENANCE_PATH: &str = "_nano/content-provenance.json";
pub const CONTENT_CONTRACT: &str = "nano.content.ocsf-1.9.v1";
pub const MAX_ARCHIVE_BYTES: usize = 32 * 1024 * 1024;
#[cfg(feature = "enterprise")]
const MAX_EXPANDED_BYTES: usize = 64 * 1024 * 1024;
#[cfg(feature = "enterprise")]
const MAX_FILE_BYTES: usize = 512 * 1024;
#[cfg(feature = "enterprise")]
const MAX_FILES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Parsers,
    Rules,
}
impl ContentKind {
    pub fn repository(self) -> &'static str {
        match self {
            Self::Parsers => "https://github.com/nano-rs/parsers",
            Self::Rules => "https://github.com/nano-rs/rules",
        }
    }
    #[cfg(feature = "enterprise")]
    fn is_definition(self, path: &str) -> bool {
        match self {
            Self::Parsers => {
                path == "parser.yaml"
                    || path == "parser.yml"
                    || path.ends_with("/parser.yaml")
                    || path.ends_with("/parser.yml")
            }
            // The upstream nano-rs/rules catalog stores native nPL bodies in
            // YAML-named files; every selected definition must be validated.
            Self::Rules => {
                path.ends_with(".npl") || path.ends_with(".yml") || path.ends_with(".yaml")
            }
        }
    }
}

/// This file is a normal signed/checksummed payload in the established v1
/// archive. No signature format or old bundle producer default changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentProvenance {
    pub contract: String,
    pub kind: ContentKind,
    pub repository: String,
    pub commit: String,
    pub ocsf_version: String,
}
impl ContentProvenance {
    #[cfg(feature = "enterprise")]
    fn validate(&self, kind: ContentKind, version: &str) -> Result<(), ContentRefusal> {
        if self.contract != CONTENT_CONTRACT
            || self.kind != kind
            || self.repository != kind.repository()
            || self.ocsf_version != "1.9"
            || self.commit != version
            || self.commit.len() != 40
            || self.commit.bytes().all(|b| b == b'0')
            || !self
                .commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ContentRefusal::Provenance);
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct ContentFile {
    pub path: String,
    pub sha256: String,
    pub source: String,
}

/// Constructible only after vendor signature, full payload closure/provenance
/// and definition validation. A caller cannot turn this into an activation.
#[derive(Debug)]
pub struct VerifiedContentCatalog {
    archive_sha256: String,
    provenance: ContentProvenance,
    files: Vec<ContentFile>,
}
impl VerifiedContentCatalog {
    pub fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }
    pub fn provenance(&self) -> &ContentProvenance {
        &self.provenance
    }
    pub fn files(&self) -> &[ContentFile] {
        &self.files
    }
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ContentRefusal {
    #[error("offline content verification requires the enterprise edition")]
    Unsupported,
    #[error("content archive is invalid or exceeds its bounds")]
    Archive,
    #[error("content provenance is incompatible or incomplete")]
    Provenance,
    #[error("content definition is invalid")]
    Definition,
}

/// The production verifier always uses the existing compiled vendor anchor.
/// Customer approval keys cannot be supplied here. All bytes remain private
/// locals until every declared payload has reached verified EOF.
pub async fn verify_content_bundle(
    bytes: Vec<u8>,
) -> Result<VerifiedContentCatalog, ContentRefusal> {
    #[cfg(not(feature = "enterprise"))]
    {
        let _ = bytes;
        Err(ContentRefusal::Unsupported)
    }
    #[cfg(feature = "enterprise")]
    {
        if bytes.is_empty() || bytes.len() > MAX_ARCHIVE_BYTES {
            return Err(ContentRefusal::Archive);
        }
        let archive_sha256 = hex::encode(Sha256::digest(&bytes));
        let mut bundle =
            verify_bundle(std::io::Cursor::new(bytes)).map_err(|_| ContentRefusal::Archive)?;
        let kind = match bundle.bundle_type() {
            BundleType::Parsers => ContentKind::Parsers,
            BundleType::Rules => ContentKind::Rules,
            _ => return Err(ContentRefusal::Provenance),
        };
        let version = bundle.manifest().content_version.clone();
        if bundle.manifest().files.is_empty() || bundle.manifest().files.len() > MAX_FILES {
            return Err(ContentRefusal::Archive);
        }
        let mut provenance = None;
        let mut definitions = Vec::new();
        let mut expanded = 0_usize;
        while let Some(mut payload) = bundle.next_payload().map_err(|_| ContentRefusal::Archive)? {
            let path = payload.path().to_string();
            // Portable paths: the base verifier rejects native traversal; these
            // additional checks refuse Windows aliases and ambiguous separators.
            if path.chars().any(char::is_control)
                || path.len() > 512
                || path.contains(['\\', ':'])
                || path
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == "..")
            {
                return Err(ContentRefusal::Archive);
            }
            let mut file = Vec::new();
            (&mut payload)
                .take((MAX_FILE_BYTES + 1) as u64)
                .read_to_end(&mut file)
                .map_err(|_| ContentRefusal::Archive)?;
            expanded = expanded
                .checked_add(file.len())
                .ok_or(ContentRefusal::Archive)?;
            if file.len() > MAX_FILE_BYTES || expanded > MAX_EXPANDED_BYTES {
                return Err(ContentRefusal::Archive);
            }
            // read_to_end has reached payload EOF: its size/hash are now verified.
            if path == PROVENANCE_PATH {
                if provenance.is_some() || file.len() > 64 * 1024 {
                    return Err(ContentRefusal::Provenance);
                }
                provenance = Some(
                    serde_json::from_slice::<ContentProvenance>(&file)
                        .map_err(|_| ContentRefusal::Provenance)?,
                );
            } else if kind.is_definition(&path) {
                let sha256 = hex::encode(Sha256::digest(&file));
                let source = String::from_utf8(file).map_err(|_| ContentRefusal::Definition)?;
                definitions.push(ContentFile {
                    path,
                    sha256,
                    source,
                });
            }
        }
        let provenance = provenance.ok_or(ContentRefusal::Provenance)?;
        provenance.validate(kind, &version)?;
        if definitions.is_empty() {
            return Err(ContentRefusal::Definition);
        }
        for definition in &definitions {
            match kind {
                ContentKind::Parsers => {
                    let parsed = crate::parser_repository::parse_parser_yaml(&definition.source)
                        .map_err(|_| ContentRefusal::Definition)?;
                    let vrl = if parsed.kind.as_deref() == Some("enrichment") {
                        parsed.normalize_vrl
                    } else {
                        parsed.parser_vrl
                    }
                    .filter(|s| !s.trim().is_empty())
                    .ok_or(ContentRefusal::Definition)?;
                    let valid = crate::parsers::VrlValidator::new()
                        .validate_vrl(&vrl)
                        .await
                        .map_err(|_| ContentRefusal::Definition)?;
                    if !valid.valid {
                        return Err(ContentRefusal::Definition);
                    }
                }
                ContentKind::Rules => {
                    let parsed = crate::rule_repository::parse_npl(&definition.source)
                        .map_err(|_| ContentRefusal::Definition)?;
                    if parsed.title.trim().is_empty()
                        || parsed.query.trim().is_empty()
                        || parsed
                            .mode
                            .as_deref()
                            .is_some_and(|m| !matches!(m, "staging" | "live" | "alerting"))
                    {
                        return Err(ContentRefusal::Definition);
                    }
                    crate::query::parse_query(&parsed.query)
                        .map_err(|_| ContentRefusal::Definition)?;
                }
            }
        }
        Ok(VerifiedContentCatalog {
            archive_sha256,
            provenance,
            files: definitions,
        })
    }
}

#[cfg(all(test, feature = "enterprise"))]
mod tests;

#[cfg(all(test, not(feature = "enterprise")))]
mod edition_tests {
    #[tokio::test]
    async fn offline_verification_refuses_without_the_enterprise_edition() {
        assert!(matches!(
            super::verify_content_bundle(vec![1]).await,
            Err(super::ContentRefusal::Unsupported)
        ));
    }
}
