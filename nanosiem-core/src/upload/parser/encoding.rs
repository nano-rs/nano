// SPDX-License-Identifier: AGPL-3.0-or-later

//! Content encoding and decoding utilities.
//!
//! Handles UTF-8, UTF-16 (LE/BE), and ISO-8859-1 encoding detection and conversion.

use super::types::ParseError;
use super::FileParser;

impl FileParser {
    /// Decode content based on encoding
    pub(super) fn decode_content(
        &self,
        content: &[u8],
        encoding: &str,
    ) -> Result<String, ParseError> {
        match encoding.to_lowercase().as_str() {
            "utf-8" | "utf8" => {
                // Check for BOM and skip if present
                let content = if content.starts_with(&[0xEF, 0xBB, 0xBF]) {
                    &content[3..]
                } else {
                    content
                };
                String::from_utf8(content.to_vec())
                    .map_err(|e| ParseError::EncodingError(format!("Invalid UTF-8: {}", e)))
            }
            "utf-16" | "utf16" | "utf-16le" | "utf16le" => self.decode_utf16_le(content),
            "utf-16be" | "utf16be" => self.decode_utf16_be(content),
            "iso-8859-1" | "latin1" | "latin-1" => {
                // ISO-8859-1 is a direct byte-to-char mapping
                Ok(content.iter().map(|&b| b as char).collect())
            }
            _ => Err(ParseError::EncodingError(format!(
                "Unsupported encoding: {}",
                encoding
            ))),
        }
    }

    /// Decode UTF-16 Little Endian content
    fn decode_utf16_le(&self, content: &[u8]) -> Result<String, ParseError> {
        // Skip BOM if present
        let content = if content.starts_with(&[0xFF, 0xFE]) {
            &content[2..]
        } else {
            content
        };

        if content.len() % 2 != 0 {
            return Err(ParseError::EncodingError(
                "Invalid UTF-16: odd number of bytes".to_string(),
            ));
        }

        let u16_iter = content
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));

        String::from_utf16(&u16_iter.collect::<Vec<_>>())
            .map_err(|e| ParseError::EncodingError(format!("Invalid UTF-16LE: {}", e)))
    }

    /// Decode UTF-16 Big Endian content
    fn decode_utf16_be(&self, content: &[u8]) -> Result<String, ParseError> {
        // Skip BOM if present
        let content = if content.starts_with(&[0xFE, 0xFF]) {
            &content[2..]
        } else {
            content
        };

        if content.len() % 2 != 0 {
            return Err(ParseError::EncodingError(
                "Invalid UTF-16: odd number of bytes".to_string(),
            ));
        }

        let u16_iter = content
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]));

        String::from_utf16(&u16_iter.collect::<Vec<_>>())
            .map_err(|e| ParseError::EncodingError(format!("Invalid UTF-16BE: {}", e)))
    }
}
