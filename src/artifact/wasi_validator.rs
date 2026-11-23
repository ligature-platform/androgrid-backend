//! WebAssembly and WASI Preview 1 Binary Validator
//!
//! Provides zero-dependency, safe validation of WebAssembly bytecode headers,
//! section structures, exported entrypoint symbols, and WASI Preview 1 imports.
//!
//! Traces to: AG-SPEC-2026-V2, [INV-006], [REQ-OP-004], [NFR-PERF-001]

use sha2::{Digest, Sha256};
use thiserror::Error;

/// WASM binary magic numbers: "\0asm" followed by version 1.
pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];
pub const WASM_VERSION_1: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// Errors encountered during WASI bytecode inspection and validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WasiValidationError {
    #[error("Bytecode payload is empty")]
    EmptyBytecode,

    #[error("Payload too short for WebAssembly header: expected at least 8 bytes, got {0}")]
    TooShort(usize),

    #[error("Invalid WebAssembly magic number: expected '\\0asm', found {0:?}")]
    InvalidMagic([u8; 4]),

    #[error("Unsupported WebAssembly version: expected 1, found {0}")]
    UnsupportedVersion(u32),

    #[error("Malformed WebAssembly section structure: {0}")]
    MalformedSection(String),

    #[error("Specified entrypoint '{0}' not found in WebAssembly export section")]
    EntrypointNotFound(String),

    #[error("Disallowed network egress imports: {0}")]
    DisallowedNetworkImports(String),
}

/// Extracted metadata from validated WebAssembly module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasiMetadata {
    /// Validated entrypoint symbol.
    pub entrypoint: String,

    /// SHA-256 hexadecimal digest of raw bytecode.
    pub artifact_sha256: String,

    /// Payload size in bytes.
    pub size_bytes: usize,

    /// Whether the module exports or imports WASI preview 1 interfaces.
    pub is_wasi_compatible: bool,

    /// List of imported functions and modules.
    pub wasi_imports: Vec<String>,

    /// Whether the module imports androgrid_net host functions.
    pub has_network_egress_imports: bool,

    /// List of imported androgrid_net functions.
    pub network_imports: Vec<String>,

    /// List of exported symbol names.
    pub exports: Vec<String>,
}

/// Binary validator for WebAssembly / WASI preview 1 modules.
///
/// Traces to: [INV-006], [REQ-OP-004]
pub struct WasiValidator;

impl WasiValidator {
    /// Validates WebAssembly binary header and exported entrypoint.
    ///
    /// Traces to: [INV-006], [REQ-OP-004]
    ///
    /// # Arguments
    /// * `bytecode` - Binary WebAssembly module.
    /// * `entrypoint` - Expected entrypoint function name (e.g. "_start").
    ///
    /// # Returns
    /// * `Ok(WasiMetadata)` - Verified module metadata.
    /// * `Err(WasiValidationError)` - If header, section, or entrypoint check fails.
    pub fn validate(
        bytecode: &[u8],
        entrypoint: &str,
    ) -> Result<WasiMetadata, WasiValidationError> {
        if bytecode.is_empty() {
            return Err(WasiValidationError::EmptyBytecode);
        }

        if bytecode.len() < 8 {
            return Err(WasiValidationError::TooShort(bytecode.len()));
        }

        let magic = &bytecode[0..4];
        if magic != WASM_MAGIC {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(magic);
            return Err(WasiValidationError::InvalidMagic(arr));
        }

        let version = u32::from_le_bytes([bytecode[4], bytecode[5], bytecode[6], bytecode[7]]);
        if version != 1 {
            return Err(WasiValidationError::UnsupportedVersion(version));
        }

        let mut offset = 8;
        let mut exports = Vec::new();
        let mut wasi_imports = Vec::new();
        let mut network_imports = Vec::new();
        let mut has_wasi_import = false;
        let mut has_network_egress_imports = false;

        while offset < bytecode.len() {
            if offset >= bytecode.len() {
                break;
            }
            let section_id = bytecode[offset];
            offset += 1;

            let (section_len, bytes_read) = Self::read_leb128_u32(&bytecode[offset..])
                .map_err(|e| WasiValidationError::MalformedSection(e.to_string()))?;
            offset += bytes_read;

            let section_len = section_len as usize;
            if offset + section_len > bytecode.len() {
                return Err(WasiValidationError::MalformedSection(
                    "Section length extends past end of file".to_string(),
                ));
            }

            let section_data = &bytecode[offset..offset + section_len];
            offset += section_len;

            match section_id {
                // Import Section (ID 2)
                2 => {
                    let mut s_off = 0;
                    let (import_count, read) = Self::read_leb128_u32(&section_data[s_off..])
                        .map_err(|e| {
                            WasiValidationError::MalformedSection(format!(
                                "Invalid import count: {e}"
                            ))
                        })?;
                    s_off += read;
                    for _ in 0..import_count {
                        if s_off >= section_data.len() {
                            return Err(WasiValidationError::MalformedSection(
                                "Unexpected EOF in import section".to_string(),
                            ));
                        }
                        let (mod_name, read) = Self::read_wasm_string(&section_data[s_off..])
                            .map_err(|e| {
                                WasiValidationError::MalformedSection(format!(
                                    "Invalid import module name: {e}"
                                ))
                            })?;
                        s_off += read;
                        let (field_name, read) = Self::read_wasm_string(&section_data[s_off..])
                            .map_err(|e| {
                                WasiValidationError::MalformedSection(format!(
                                    "Invalid import field name: {e}"
                                ))
                            })?;
                        s_off += read;
                        if mod_name == "wasi_snapshot_preview1" || mod_name == "wasi_unstable" {
                            has_wasi_import = true;
                            wasi_imports.push(format!("{mod_name}::{field_name}"));
                        } else if mod_name == "androgrid_net" {
                            has_network_egress_imports = true;
                            network_imports.push(format!("{mod_name}::{field_name}"));
                        }
                        if s_off >= section_data.len() {
                            return Err(WasiValidationError::MalformedSection(
                                "Unexpected EOF in import kind".to_string(),
                            ));
                        }
                        let kind = section_data[s_off];
                        s_off += 1;
                        match kind {
                            0 => {
                                // Function import: type index (LEB128 u32)
                                let (_, r) = Self::read_leb128_u32(&section_data[s_off..])
                                    .map_err(|e| {
                                        WasiValidationError::MalformedSection(format!(
                                            "Invalid import type index: {e}"
                                        ))
                                    })?;
                                s_off += r;
                            }
                            1 => {
                                // Table import: reftype (byte) + limits
                                if s_off >= section_data.len() {
                                    return Err(WasiValidationError::MalformedSection(
                                        "Unexpected EOF in table import reftype".to_string(),
                                    ));
                                }
                                s_off += 1; // reftype
                                let r = Self::skip_limits(&section_data[s_off..])?;
                                s_off += r;
                            }
                            2 => {
                                // Memory import: limits
                                let r = Self::skip_limits(&section_data[s_off..])?;
                                s_off += r;
                            }
                            3 => {
                                // Global import: valtype (byte) + mutability (byte)
                                if s_off + 2 > section_data.len() {
                                    return Err(WasiValidationError::MalformedSection(
                                        "Unexpected EOF in global import description".to_string(),
                                    ));
                                }
                                s_off += 2;
                            }
                            other => {
                                return Err(WasiValidationError::MalformedSection(format!(
                                    "Unknown import kind: {other}"
                                )));
                            }
                        }
                    }
                }
                // Export Section (ID 7)
                7 => {
                    let mut s_off = 0;
                    let (export_count, read) = Self::read_leb128_u32(&section_data[s_off..])
                        .map_err(|e| {
                            WasiValidationError::MalformedSection(format!(
                                "Invalid export count: {e}"
                            ))
                        })?;
                    s_off += read;
                    for _ in 0..export_count {
                        if s_off >= section_data.len() {
                            return Err(WasiValidationError::MalformedSection(
                                "Unexpected EOF in export section".to_string(),
                            ));
                        }
                        let (name, read) =
                            Self::read_wasm_string(&section_data[s_off..]).map_err(|e| {
                                WasiValidationError::MalformedSection(format!(
                                    "Invalid export name: {e}"
                                ))
                            })?;
                        s_off += read;
                        exports.push(name);
                        if s_off >= section_data.len() {
                            return Err(WasiValidationError::MalformedSection(
                                "Unexpected EOF in export description".to_string(),
                            ));
                        }
                        s_off += 1; // kind
                        let (_, r) =
                            Self::read_leb128_u32(&section_data[s_off..]).map_err(|e| {
                                WasiValidationError::MalformedSection(format!(
                                    "Invalid export index: {e}"
                                ))
                            })?;
                        s_off += r;
                    }
                }
                _ => {}
            }
        }

        // Verify that expected entrypoint is exported
        if !entrypoint.is_empty() && !exports.iter().any(|e| e == entrypoint) {
            return Err(WasiValidationError::EntrypointNotFound(
                entrypoint.to_string(),
            ));
        }

        let mut hasher = Sha256::new();
        hasher.update(bytecode);
        let artifact_sha256 = format!("{:x}", hasher.finalize());

        // A module is WASI compatible if it explicitly imports WASI functions or exports entrypoint
        let is_wasi_compatible =
            has_wasi_import || exports.iter().any(|e| e == "_start" || e == entrypoint);

        Ok(WasiMetadata {
            entrypoint: entrypoint.to_string(),
            artifact_sha256,
            size_bytes: bytecode.len(),
            is_wasi_compatible,
            wasi_imports,
            has_network_egress_imports,
            network_imports,
            exports,
        })
    }

    /// Asserts that network egress imports in the WebAssembly module match the declared policy.
    ///
    /// Traces to: [INV-006], ADR-011
    pub fn validate_egress_policy(
        meta: &WasiMetadata,
        egress_policy: i32,
    ) -> Result<(), WasiValidationError> {
        if meta.has_network_egress_imports && (egress_policy == 0 || egress_policy == 1) {
            return Err(WasiValidationError::DisallowedNetworkImports(format!(
                "Module imports 'androgrid_net' interfaces ({:?}) but egress_policy is BLOCKED or unspecified",
                meta.network_imports
            )));
        }
        Ok(())
    }

    /// Skips a WebAssembly limits structure (flags: u8, min: u32, [max: u32]).
    fn skip_limits(data: &[u8]) -> Result<usize, WasiValidationError> {
        if data.is_empty() {
            return Err(WasiValidationError::MalformedSection(
                "Unexpected EOF reading limits flags".to_string(),
            ));
        }
        let flags = data[0];
        let mut off = 1;
        let (_min, r1) = Self::read_leb128_u32(&data[off..]).map_err(|e| {
            WasiValidationError::MalformedSection(format!("Invalid limits min: {e}"))
        })?;
        off += r1;
        match flags {
            0 => Ok(off),
            1 => {
                let (_max, r2) = Self::read_leb128_u32(&data[off..]).map_err(|e| {
                    WasiValidationError::MalformedSection(format!("Invalid limits max: {e}"))
                })?;
                off += r2;
                Ok(off)
            }
            other => Err(WasiValidationError::MalformedSection(format!(
                "Invalid limits flags: expected 0 or 1, found {other}"
            ))),
        }
    }

    /// Reads variable-length unsigned LEB128 integer.
    fn read_leb128_u32(data: &[u8]) -> Result<(u32, usize), &'static str> {
        let mut result = 0u32;
        let mut shift = 0;
        let mut bytes_read = 0;

        for &byte in data {
            bytes_read += 1;
            let val = (byte & 0x7F) as u32;
            result |= val << shift;
            if (byte & 0x80) == 0 {
                return Ok((result, bytes_read));
            }
            shift += 7;
            if shift >= 35 {
                return Err("LEB128 integer overflow");
            }
        }

        Err("Unexpected end of data while decoding LEB128")
    }

    /// Reads length-prefixed UTF-8 string from WebAssembly section data.
    fn read_wasm_string(data: &[u8]) -> Result<(String, usize), &'static str> {
        let (len, bytes_read) = Self::read_leb128_u32(data)?;
        let len = len as usize;
        let start = bytes_read;
        let end = start + len;

        if end > data.len() {
            return Err("String length exceeds section data");
        }

        let s = std::str::from_utf8(&data[start..end])
            .map_err(|_| "Invalid UTF-8 in export or import string")?
            .to_string();

        Ok((s, end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_wasm_header_acceptance() {
        let mut minimal = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        // Export section with "_start"
        minimal.extend_from_slice(&[
            0x07, // export section id
            0x0a, // section len (10 bytes)
            0x01, // 1 export
            0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, // name: "_start"
            0x00, 0x00, // function index 0
        ]);

        let meta = WasiValidator::validate(&minimal, "_start").expect("Valid minimal WASI");
        assert_eq!(meta.entrypoint, "_start");
        assert!(meta.exports.contains(&"_start".to_string()));
    }

    #[test]
    fn test_invalid_header_rejection() {
        let bad_magic = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x00, 0x00, 0x00];
        assert!(matches!(
            WasiValidator::validate(&bad_magic, "_start"),
            Err(WasiValidationError::InvalidMagic(_))
        ));

        let bad_version = vec![0x00, 0x61, 0x73, 0x6d, 0x02, 0x00, 0x00, 0x00];
        assert!(matches!(
            WasiValidator::validate(&bad_version, "_start"),
            Err(WasiValidationError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn test_import_section_table_and_memory_limits_parsing() {
        let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

        let mut import_data = Vec::new();
        import_data.push(0x03); // 3 imports

        // Import 1: Table
        import_data.extend_from_slice(&[0x03, 0x65, 0x6e, 0x76]); // "env"
        import_data.extend_from_slice(&[0x03, 0x74, 0x62, 0x6c]); // "tbl"
        import_data.push(0x01); // kind = 1 (table)
        import_data.push(0x70); // funcref
        import_data.push(0x01); // flags = 1 (min and max)
        import_data.push(0x01); // min = 1
        import_data.push(0x0a); // max = 10

        // Import 2: Memory
        import_data.extend_from_slice(&[0x03, 0x65, 0x6e, 0x76]); // "env"
        import_data.extend_from_slice(&[0x03, 0x6d, 0x65, 0x6d]); // "mem"
        import_data.push(0x02); // kind = 2 (memory)
        import_data.push(0x00); // flags = 0 (min only)
        import_data.push(0x02); // min = 2

        // Import 3: Function androgrid_net::http_fetch
        import_data.extend_from_slice(&[
            0x0d, b'a', b'n', b'd', b'r', b'o', b'g', b'r', b'i', b'd', b'_', b'n', b'e', b't',
        ]);
        import_data.extend_from_slice(&[
            0x0a, b'h', b't', b't', b'p', b'_', b'f', b'e', b't', b'c', b'h',
        ]);
        import_data.push(0x00); // kind = 0 (function)
        import_data.push(0x00); // type_idx = 0

        wasm.push(0x02); // import section id
        wasm.push(import_data.len() as u8);
        wasm.extend_from_slice(&import_data);

        // Export section with "_start"
        wasm.extend_from_slice(&[
            0x07, 0x0a, 0x01, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
        ]);

        let meta = WasiValidator::validate(&wasm, "_start").expect("Validation must succeed");
        assert!(meta.has_network_egress_imports);
        assert_eq!(
            meta.network_imports,
            vec!["androgrid_net::http_fetch".to_string()]
        );
    }
}
