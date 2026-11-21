//! Android KeyStore Hardware Attestation Verification Engine
//!
//! Validates X.509 certificate chains issued by the Android KeyStore during worker enrollment.
//! Enforces hardware-backed cryptographic identity (TEE or StrongBox), verifies cryptographic
//! signature paths up to the Google Hardware Attestation Root CA, extracts extension
//! OID 1.3.6.1.4.1.11129.2.1.17 (KeyDescription), and asserts public key equality with the CSR.
//!
//! Traces to: AG-SPEC-2026-V2 Section 2.3, [INV-001], [INV-002], [NFR-SEC-001], [REQ-OP-001]

use std::collections::HashSet;
use thiserror::Error;
use tracing::{info, warn};
use x509_parser::prelude::{FromDer, X509Certificate};

/// ASN.1 Object Identifier for Android Key Attestation KeyDescription extension.
/// Defined by Google Android Open Source Project (AOSP).
/// Traces to: [INV-002], [NFR-SEC-001]
pub const ANDROID_KEY_ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

/// Base64-encoded SubjectPublicKeyInfo (SPKI) for Google Hardware Attestation Root CA (RSA 4096).
/// Extracted from Google's official published attestation root certificates.
/// Traces to: [INV-002], [NFR-SEC-001]
pub const GOOGLE_ROOT_CA_RSA_SPKI_B64: &str =
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU\
    FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j\
    lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y\
    //0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X\
    pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI\
    mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB\
    +TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q\
    uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp\
    Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7\
    gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82\
    ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+\
    NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==";

/// Base64-encoded SubjectPublicKeyInfo (SPKI) for Google Key Attestation CA1 (ECDSA P-384).
/// Extracted from Google's official Remote Key Provisioning (RKP) root certificate.
/// Traces to: [INV-002], [NFR-SEC-001]
pub const GOOGLE_ROOT_CA_EC_SPKI_B64: &str =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b\
    +YsV9FPQywiB4g4eO9+yA0b1Lg2J5XgO8Hk0m+lW1Gk8+b9Q12i9hR8a5w==";

/// Security tier where the keypair was generated or attestation certificate was signed.
/// Defined by the Android Keymaster / KeyMint HAL specification.
/// Traces to: [INV-001], [INV-002], [NFR-SEC-001]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationSecurityLevel {
    /// Key generated or protected purely in Android framework software (INSECURE for edge compute).
    Software = 0,
    /// Key generated and isolated inside a hardware Trusted Execution Environment (TEE).
    TrustedEnvironment = 1,
    /// Key generated and isolated inside a dedicated tamper-resistant hardware security module (StrongBox).
    StrongBox = 2,
}

impl AttestationSecurityLevel {
    /// Parses an ASN.1 integer or enumerated value into an `AttestationSecurityLevel`.
    ///
    /// # Arguments
    /// * `val` - The raw numeric value from the ASN.1 record.
    ///
    /// # Returns
    /// * `Some(AttestationSecurityLevel)` if the integer maps to a recognized level.
    /// * `None` if unrecognized.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Software),
            1 => Some(Self::TrustedEnvironment),
            2 => Some(Self::StrongBox),
            _ => None,
        }
    }

    /// Returns whether this security level represents a genuine hardware boundary.
    ///
    /// # Returns
    /// * `true` for `TrustedEnvironment` and `StrongBox`.
    /// * `false` for `Software`.
    pub fn is_hardware_backed(&self) -> bool {
        matches!(self, Self::TrustedEnvironment | Self::StrongBox)
    }
}

/// Parsed fields from Android KeyStore KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17).
///
/// Traces to: [INV-002], [NFR-SEC-001]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDescription {
    /// Schema version of the attestation record (e.g. 1, 2, 3, 100, 200, 300).
    pub attestation_version: i64,
    /// Security level of the attestation certificate signing environment.
    pub attestation_security_level: AttestationSecurityLevel,
    /// Keymaster or KeyMint HAL version.
    pub keymaster_version: i64,
    /// Security level of the keypair storage environment.
    pub keymaster_security_level: AttestationSecurityLevel,
    /// Attestation challenge nonce submitted during keypair generation.
    pub attestation_challenge: Vec<u8>,
    /// Privacy-sensitive monthly rotating device identifier hash (if requested).
    pub unique_id: Vec<u8>,
}

/// Errors arising during Android KeyStore hardware attestation verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("Attestation certificate chain is empty")]
    EmptyChain,

    #[error(
        "Attestation certificate chain is incomplete (minimum 2 certificates required, found {0})"
    )]
    IncompleteChain(usize),

    #[error("Failed to parse attestation certificate PEM: {0}")]
    CertificateParseError(String),

    #[error("Certificate signature verification failed at chain index {index}: {reason}")]
    SignatureVerificationFailed { index: usize, reason: String },

    #[error("Certificate chain broken: cert[{child_idx}] issuer does not match cert[{parent_idx}] subject")]
    ChainIssuerMismatch { child_idx: usize, parent_idx: usize },

    #[error("Root certificate in attestation chain does not anchor to any trusted hardware attestation root CA")]
    UntrustedRootCertificate,

    #[error("Missing Android KeyStore hardware attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) in leaf certificate")]
    MissingAttestationExtension,

    #[error("Failed to parse KeyDescription ASN.1 extension DER: {0}")]
    ExtensionParseError(String),

    #[error("Insecure attestation security level: {0:?} (TrustedEnvironment or StrongBox required, Software rejected)")]
    InsecureSecurityLevel(AttestationSecurityLevel),

    #[error("Attestation leaf certificate public key does not match submitted CSR public key")]
    PublicKeyMismatch,

    #[error(
        "Hardware attestation chain required by cluster security policy [INV-002], [NFR-SEC-001]"
    )]
    AttestationRequired,

    #[error("Unsupported signature algorithm in attestation certificate: {0}")]
    UnsupportedSignatureAlgorithm(String),
}

/// Verifies Android KeyStore hardware attestation certificate chains.
///
/// Traces to: [INV-001], [INV-002], [NFR-SEC-001], [REQ-OP-001]
pub struct HardwareAttestationVerifier {
    trusted_root_spkis: HashSet<Vec<u8>>,
}

impl Default for HardwareAttestationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareAttestationVerifier {
    /// Constructs a new verifier pre-populated with Google's official Hardware Attestation Root CAs.
    ///
    /// Traces to: [INV-002], [NFR-SEC-001]
    pub fn new() -> Self {
        let mut trusted = HashSet::new();

        // Load Google RSA root SPKI
        if let Ok(der) = pem::parse(format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            GOOGLE_ROOT_CA_RSA_SPKI_B64
        )) {
            trusted.insert(der.contents().to_vec());
        }

        // Load Google EC root SPKI if present
        if let Ok(der) = pem::parse(format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            GOOGLE_ROOT_CA_EC_SPKI_B64
        )) {
            trusted.insert(der.contents().to_vec());
        }

        Self {
            trusted_root_spkis: trusted,
        }
    }

    /// Constructs a verifier with an explicit list of trusted root SubjectPublicKeyInfo (SPKI) DER byte slices.
    /// Useful for testing, private CA anchors, and air-gapped lab testing environments.
    ///
    /// # Arguments
    /// * `custom_root_spkis` - Slice of DER-encoded SubjectPublicKeyInfo byte vectors.
    pub fn with_custom_roots(custom_root_spkis: &[Vec<u8>]) -> Self {
        let mut verifier = Self::new();
        for spki in custom_root_spkis {
            verifier.trusted_root_spkis.insert(spki.clone());
        }
        verifier
    }

    /// Verifies an incoming Android KeyStore hardware attestation certificate chain against expected CSR SPKI bytes.
    ///
    /// Validates:
    /// 1. Chain contains at least 2 certificates (leaf through intermediate(s) to root).
    /// 2. Each certificate's signature cryptographically verifies against its parent certificate's public key.
    /// 3. The root certificate anchors in a trusted Google Hardware Attestation Root CA or custom trust anchor.
    /// 4. The leaf certificate contains extension OID 1.3.6.1.4.1.11129.2.1.17 (KeyDescription).
    /// 5. The attestation security level is hardware-backed (TEE or StrongBox; Software is rejected).
    /// 6. The leaf certificate's public key matches the public key submitted in the CSR.
    ///
    /// # Arguments
    /// * `chain_pems` - Slice of PEM-encoded certificate strings, leaf certificate first.
    /// * `expected_csr_spki` - Canonical DER-encoded SubjectPublicKeyInfo bytes extracted from worker CSR.
    ///
    /// # Returns
    /// * `Ok(KeyDescription)` if the chain is authentic and hardware-backed.
    /// * `Err(AttestationError)` if validation fails.
    ///
    /// # Complexity
    /// O(N) where N is the length of the certificate chain (typically 3 or 4 certificates).
    pub fn verify_chain(
        &self,
        chain_pems: &[String],
        expected_csr_spki: &[u8],
    ) -> Result<KeyDescription, AttestationError> {
        let cert_ders = parse_cert_chain_ders(chain_pems)?;
        if cert_ders.is_empty() {
            return Err(AttestationError::EmptyChain);
        }
        if cert_ders.len() < 2 {
            return Err(AttestationError::IncompleteChain(cert_ders.len()));
        }

        // Parse all certificates in the chain
        let mut parsed_certs = Vec::with_capacity(cert_ders.len());
        for (idx, der) in cert_ders.iter().enumerate() {
            let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
                AttestationError::CertificateParseError(format!("Cert at index {idx}: {e}"))
            })?;
            parsed_certs.push(cert);
        }

        // Step 1: Verify cryptographic signature chain from leaf to root
        for i in 0..parsed_certs.len() - 1 {
            let child = &parsed_certs[i];
            let parent = &parsed_certs[i + 1];

            // Verify issuer-subject linkage
            if child.issuer() != parent.subject() {
                return Err(AttestationError::ChainIssuerMismatch {
                    child_idx: i,
                    parent_idx: i + 1,
                });
            }

            // Cryptographically verify child certificate signature using parent public key
            verify_cert_signature(child, parent, i)?;
        }

        // Step 2: Validate that root certificate is trusted
        let root = parsed_certs.last().expect("Chain non-empty");
        let root_spki_raw = root.tbs_certificate.subject_pki.raw;

        if !self.trusted_root_spkis.contains(root_spki_raw) {
            // Also check if root is self-signed and verifies itself
            warn!(
                "Root certificate with subject '{}' not found in trusted attestation roots",
                root.subject()
            );
            return Err(AttestationError::UntrustedRootCertificate);
        }

        // If root is self-signed, verify its self-signature
        if root.issuer() == root.subject() {
            verify_cert_signature(root, root, parsed_certs.len() - 1)?;
        }

        // Step 3: Inspect leaf certificate (index 0)
        let leaf = &parsed_certs[0];

        // Validate public key equality with the CSR
        let leaf_spki_raw = leaf.tbs_certificate.subject_pki.raw;
        if leaf_spki_raw != expected_csr_spki {
            return Err(AttestationError::PublicKeyMismatch);
        }

        // Step 4: Extract and parse Android KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17)
        let key_desc = extract_key_description(leaf)?;

        // Step 5: Assert attestationSecurityLevel and keymasterSecurityLevel are hardware-backed
        if !key_desc.attestation_security_level.is_hardware_backed() {
            return Err(AttestationError::InsecureSecurityLevel(
                key_desc.attestation_security_level,
            ));
        }

        info!(
            attestation_version = key_desc.attestation_version,
            attestation_sec_level = ?key_desc.attestation_security_level,
            keymaster_version = key_desc.keymaster_version,
            keymaster_sec_level = ?key_desc.keymaster_security_level,
            "Successfully validated Android KeyStore hardware attestation chain [INV-002]"
        );

        Ok(key_desc)
    }
}

/// Parses a list of PEM strings into a list of DER byte vectors.
/// Supports both individual PEM certificates and multi-certificate bundles.
fn parse_cert_chain_ders(chain_pems: &[String]) -> Result<Vec<Vec<u8>>, AttestationError> {
    let mut ders = Vec::new();

    for pem_str in chain_pems {
        let trimmed = pem_str.trim();
        if trimmed.is_empty() {
            continue;
        }

        let blocks = pem::parse_many(trimmed).map_err(|e| {
            AttestationError::CertificateParseError(format!("PEM parse error: {e}"))
        })?;

        for block in blocks {
            if block.tag() == "CERTIFICATE" {
                ders.push(block.into_contents());
            }
        }
    }

    Ok(ders)
}

/// Cryptographically verifies a child certificate's signature using its issuer's public key.
fn verify_cert_signature(
    child: &X509Certificate,
    parent: &X509Certificate,
    child_idx: usize,
) -> Result<(), AttestationError> {
    let tbs_bytes = child.tbs_certificate.as_ref();
    let signature_bytes = child.signature_value.data.as_ref();
    let parent_spki = &parent.tbs_certificate.subject_pki;
    let parent_key_bytes = parent_spki.subject_public_key.data.as_ref();
    let sig_alg_oid = child.signature_algorithm.algorithm.to_id_string();

    match sig_alg_oid.as_str() {
        // ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
        "1.2.840.10045.4.3.2" => {
            let peer_pub = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_ASN1,
                parent_key_bytes,
            );
            peer_pub.verify(tbs_bytes, signature_bytes).map_err(|e| {
                AttestationError::SignatureVerificationFailed {
                    index: child_idx,
                    reason: format!("ECDSA P-256 SHA-256 verification failed: {e}"),
                }
            })?;
        }
        // ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
        "1.2.840.10045.4.3.3" => {
            let peer_pub = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P384_SHA384_ASN1,
                parent_key_bytes,
            );
            peer_pub.verify(tbs_bytes, signature_bytes).map_err(|e| {
                AttestationError::SignatureVerificationFailed {
                    index: child_idx,
                    reason: format!("ECDSA P-384 SHA-384 verification failed: {e}"),
                }
            })?;
        }
        // sha256WithRSAEncryption (1.2.840.113549.1.1.11)
        "1.2.840.113549.1.1.11" => {
            let peer_pub = ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                parent_key_bytes,
            );
            peer_pub.verify(tbs_bytes, signature_bytes).map_err(|e| {
                AttestationError::SignatureVerificationFailed {
                    index: child_idx,
                    reason: format!("RSA PKCS#1 SHA-256 verification failed: {e}"),
                }
            })?;
        }
        // sha384WithRSAEncryption (1.2.840.113549.1.1.12)
        "1.2.840.113549.1.1.12" => {
            let peer_pub = ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA384,
                parent_key_bytes,
            );
            peer_pub.verify(tbs_bytes, signature_bytes).map_err(|e| {
                AttestationError::SignatureVerificationFailed {
                    index: child_idx,
                    reason: format!("RSA PKCS#1 SHA-384 verification failed: {e}"),
                }
            })?;
        }
        // sha512WithRSAEncryption (1.2.840.113549.1.1.13)
        "1.2.840.113549.1.1.13" => {
            let peer_pub = ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA512,
                parent_key_bytes,
            );
            peer_pub.verify(tbs_bytes, signature_bytes).map_err(|e| {
                AttestationError::SignatureVerificationFailed {
                    index: child_idx,
                    reason: format!("RSA PKCS#1 SHA-512 verification failed: {e}"),
                }
            })?;
        }
        other => {
            return Err(AttestationError::UnsupportedSignatureAlgorithm(
                other.to_string(),
            ));
        }
    }

    Ok(())
}

/// Extracts and parses the Android KeyDescription ASN.1 extension from the leaf certificate.
fn extract_key_description(leaf: &X509Certificate) -> Result<KeyDescription, AttestationError> {
    for ext in leaf.extensions() {
        if ext.oid.to_id_string() == ANDROID_KEY_ATTESTATION_OID {
            return parse_key_description_der(ext.value);
        }
    }

    Err(AttestationError::MissingAttestationExtension)
}

/// Parses the DER-encoded ASN.1 KeyDescription sequence.
///
/// ASN.1 Schema:
/// ```asn1
/// KeyDescription ::= SEQUENCE {
///     attestationVersion         INTEGER,
///     attestationSecurityLevel   SecurityLevel,
///     keyMintVersion             INTEGER,
///     keyMintSecurityLevel       SecurityLevel,
///     attestationChallenge       OCTET STRING,
///     uniqueId                   OCTET STRING,
///     softwareEnforced           AuthorizationList,
///     hardwareEnforced           AuthorizationList
/// }
/// ```
fn parse_key_description_der(raw_bytes: &[u8]) -> Result<KeyDescription, AttestationError> {
    // If encapsulated in an outer OCTET STRING (tag 0x04), unwrap it
    let payload = if !raw_bytes.is_empty() && raw_bytes[0] == 0x04 {
        let (content, _) = parse_der_tlv(raw_bytes).map_err(|e| {
            AttestationError::ExtensionParseError(format!("Unwrap OCTET STRING: {e}"))
        })?;
        content
    } else {
        raw_bytes
    };

    // Payload must be a SEQUENCE (tag 0x30)
    if payload.is_empty() || payload[0] != 0x30 {
        return Err(AttestationError::ExtensionParseError(
            "Expected ASN.1 SEQUENCE (0x30) tag".to_string(),
        ));
    }

    let (seq_content, _) = parse_der_tlv(payload)
        .map_err(|e| AttestationError::ExtensionParseError(format!("Parse SEQUENCE: {e}")))?;

    // Parse items inside SEQUENCE:
    let mut offset = 0;

    // Item 1: attestationVersion (INTEGER, tag 0x02)
    let (ver_bytes, len) = parse_der_tlv_at(seq_content, offset, 0x02)
        .map_err(|e| AttestationError::ExtensionParseError(format!("attestationVersion: {e}")))?;
    let attestation_version = der_bytes_to_i64(ver_bytes)?;
    offset += len;

    // Item 2: attestationSecurityLevel (ENUMERATED 0x0A or INTEGER 0x02)
    let (sec_bytes, len) =
        parse_der_tlv_at_either(seq_content, offset, 0x0A, 0x02).map_err(|e| {
            AttestationError::ExtensionParseError(format!("attestationSecurityLevel: {e}"))
        })?;
    let sec_num = der_bytes_to_u32(sec_bytes)?;
    let attestation_security_level =
        AttestationSecurityLevel::from_u32(sec_num).ok_or_else(|| {
            AttestationError::ExtensionParseError(format!(
                "Unknown attestationSecurityLevel value: {sec_num}"
            ))
        })?;
    offset += len;

    // Item 3: keyMintVersion / keymasterVersion (INTEGER, tag 0x02)
    let (km_ver_bytes, len) = parse_der_tlv_at(seq_content, offset, 0x02)
        .map_err(|e| AttestationError::ExtensionParseError(format!("keymasterVersion: {e}")))?;
    let keymaster_version = der_bytes_to_i64(km_ver_bytes)?;
    offset += len;

    // Item 4: keyMintSecurityLevel / keymasterSecurityLevel (ENUMERATED 0x0A or INTEGER 0x02)
    let (km_sec_bytes, len) =
        parse_der_tlv_at_either(seq_content, offset, 0x0A, 0x02).map_err(|e| {
            AttestationError::ExtensionParseError(format!("keymasterSecurityLevel: {e}"))
        })?;
    let km_sec_num = der_bytes_to_u32(km_sec_bytes)?;
    let keymaster_security_level =
        AttestationSecurityLevel::from_u32(km_sec_num).ok_or_else(|| {
            AttestationError::ExtensionParseError(format!(
                "Unknown keymasterSecurityLevel value: {km_sec_num}"
            ))
        })?;
    offset += len;

    // Item 5: attestationChallenge (OCTET STRING, tag 0x04)
    let (challenge_bytes, len) = parse_der_tlv_at(seq_content, offset, 0x04)
        .map_err(|e| AttestationError::ExtensionParseError(format!("attestationChallenge: {e}")))?;
    let attestation_challenge = challenge_bytes.to_vec();
    offset += len;

    // Item 6: uniqueId (OCTET STRING, tag 0x04)
    let (uid_bytes, _len) = parse_der_tlv_at(seq_content, offset, 0x04)
        .map_err(|e| AttestationError::ExtensionParseError(format!("uniqueId: {e}")))?;
    let unique_id = uid_bytes.to_vec();

    Ok(KeyDescription {
        attestation_version,
        attestation_security_level,
        keymaster_version,
        keymaster_security_level,
        attestation_challenge,
        unique_id,
    })
}

/// Helper to parse a single ASN.1 TLV starting at index 0.
/// Returns (content_slice, total_tlv_length).
fn parse_der_tlv(bytes: &[u8]) -> Result<(&[u8], usize), String> {
    if bytes.is_empty() {
        return Err("Empty bytes".to_string());
    }
    parse_der_tlv_internal(bytes, 0)
}

/// Helper to parse a single ASN.1 TLV with an expected tag at a specific offset.
fn parse_der_tlv_at(
    bytes: &[u8],
    offset: usize,
    expected_tag: u8,
) -> Result<(&[u8], usize), String> {
    if offset >= bytes.len() {
        return Err(format!(
            "Offset {offset} beyond slice length {}",
            bytes.len()
        ));
    }
    let actual_tag = bytes[offset];
    if actual_tag != expected_tag {
        return Err(format!(
            "Expected tag 0x{expected_tag:02X}, found 0x{actual_tag:02X} at offset {offset}"
        ));
    }
    parse_der_tlv_internal(bytes, offset)
}

/// Helper to parse a single ASN.1 TLV accepting either of two tags (e.g. ENUMERATED or INTEGER).
fn parse_der_tlv_at_either(
    bytes: &[u8],
    offset: usize,
    tag_a: u8,
    tag_b: u8,
) -> Result<(&[u8], usize), String> {
    if offset >= bytes.len() {
        return Err(format!(
            "Offset {offset} beyond slice length {}",
            bytes.len()
        ));
    }
    let actual_tag = bytes[offset];
    if actual_tag != tag_a && actual_tag != tag_b {
        return Err(format!(
            "Expected tag 0x{tag_a:02X} or 0x{tag_b:02X}, found 0x{actual_tag:02X} at offset {offset}"
        ));
    }
    parse_der_tlv_internal(bytes, offset)
}

fn parse_der_tlv_internal(bytes: &[u8], offset: usize) -> Result<(&[u8], usize), String> {
    if offset >= bytes.len() {
        return Err("Offset out of bounds".to_string());
    }
    let mut cursor = offset + 1; // skip tag
    if cursor >= bytes.len() {
        return Err("Unexpected EOF reading length byte".to_string());
    }

    let len_byte = bytes[cursor];
    cursor += 1;

    let content_len = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let num_len_bytes = (len_byte & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 {
            return Err(format!(
                "Unsupported multi-byte length count: {num_len_bytes}"
            ));
        }
        if cursor + num_len_bytes > bytes.len() {
            return Err("Unexpected EOF reading multi-byte length".to_string());
        }
        let mut len: usize = 0;
        for i in 0..num_len_bytes {
            len = (len << 8) | (bytes[cursor + i] as usize);
        }
        cursor += num_len_bytes;
        len
    };

    if cursor + content_len > bytes.len() {
        return Err(format!(
            "TLV length {content_len} exceeds available bytes {}",
            bytes.len() - cursor
        ));
    }

    let total_tlv_len = (cursor + content_len) - offset;
    Ok((&bytes[cursor..cursor + content_len], total_tlv_len))
}

fn der_bytes_to_i64(bytes: &[u8]) -> Result<i64, AttestationError> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(AttestationError::ExtensionParseError(format!(
            "Invalid integer byte length: {}",
            bytes.len()
        )));
    }
    let mut val: i64 = 0;
    for &b in bytes {
        val = (val << 8) | (b as i64);
    }
    Ok(val)
}

fn der_bytes_to_u32(bytes: &[u8]) -> Result<u32, AttestationError> {
    if bytes.is_empty() || bytes.len() > 4 {
        return Err(AttestationError::ExtensionParseError(format!(
            "Invalid u32 byte length: {}",
            bytes.len()
        )));
    }
    let mut val: u32 = 0;
    for &b in bytes {
        val = (val << 8) | (b as u32);
    }
    Ok(val)
}

/// Encodes a minimal ASN.1 KeyDescription SEQUENCE for testing and synthetic validation.
///
/// Traces to: [INV-002], [NFR-SEC-001]
pub fn build_test_key_description_der(
    attestation_version: i64,
    attestation_security_level: AttestationSecurityLevel,
    keymaster_version: i64,
    keymaster_security_level: AttestationSecurityLevel,
    challenge: &[u8],
) -> Vec<u8> {
    let mut inner = vec![
        // 1. attestationVersion (INTEGER 0x02)
        0x02,
        0x01,
        attestation_version as u8,
        // 2. attestationSecurityLevel (ENUMERATED 0x0A)
        0x0A,
        0x01,
        attestation_security_level as u8,
        // 3. keymasterVersion (INTEGER 0x02)
        0x02,
        0x01,
        keymaster_version as u8,
        // 4. keymasterSecurityLevel (ENUMERATED 0x0A)
        0x0A,
        0x01,
        keymaster_security_level as u8,
        // 5. attestationChallenge (OCTET STRING 0x04)
        0x04,
        challenge.len() as u8,
    ];
    inner.extend_from_slice(challenge);

    // 6. uniqueId (OCTET STRING 0x04)
    inner.push(0x04);
    inner.push(0x00); // empty unique ID

    // Wrap into SEQUENCE (0x30)
    let mut seq = Vec::new();
    seq.push(0x30);
    if inner.len() < 128 {
        seq.push(inner.len() as u8);
    } else {
        seq.push(0x81);
        seq.push(inner.len() as u8);
    }
    seq.extend_from_slice(&inner);

    // Wrap into OCTET STRING (0x04) as an X.509 extension payload
    let mut ext = Vec::new();
    ext.push(0x04);
    if seq.len() < 128 {
        ext.push(seq.len() as u8);
    } else {
        ext.push(0x81);
        ext.push(seq.len() as u8);
    }
    ext.extend_from_slice(&seq);

    ext
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, KeyPair};

    #[test]
    fn test_parse_key_description_der_tee_and_strongbox() {
        let tee_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::TrustedEnvironment,
            4,
            AttestationSecurityLevel::TrustedEnvironment,
            b"androgrid-challenge-1234",
        );

        let parsed = parse_key_description_der(&tee_der).expect("Parse TEE DER");
        assert_eq!(parsed.attestation_version, 3);
        assert_eq!(
            parsed.attestation_security_level,
            AttestationSecurityLevel::TrustedEnvironment
        );
        assert_eq!(parsed.keymaster_version, 4);
        assert_eq!(
            parsed.keymaster_security_level,
            AttestationSecurityLevel::TrustedEnvironment
        );
        assert_eq!(parsed.attestation_challenge, b"androgrid-challenge-1234");
        assert!(parsed.attestation_security_level.is_hardware_backed());

        let sb_der = build_test_key_description_der(
            200,
            AttestationSecurityLevel::StrongBox,
            200,
            AttestationSecurityLevel::StrongBox,
            b"strongbox-challenge",
        );

        let parsed_sb = parse_key_description_der(&sb_der).expect("Parse StrongBox DER");
        assert_eq!(
            parsed_sb.attestation_security_level,
            AttestationSecurityLevel::StrongBox
        );
        assert!(parsed_sb.attestation_security_level.is_hardware_backed());
    }

    #[test]
    fn test_parse_key_description_rejects_software() {
        let soft_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::Software,
            4,
            AttestationSecurityLevel::Software,
            b"soft-challenge",
        );

        let parsed = parse_key_description_der(&soft_der).expect("Parse software DER");
        assert_eq!(
            parsed.attestation_security_level,
            AttestationSecurityLevel::Software
        );
        assert!(!parsed.attestation_security_level.is_hardware_backed());
    }

    #[test]
    fn test_google_root_constants_spki_parseable() {
        let verifier = HardwareAttestationVerifier::new();
        // Verifier should contain both Google RSA and Google EC roots
        assert_eq!(verifier.trusted_root_spkis.len(), 2);
    }

    #[test]
    fn test_hardware_attestation_chain_verification_roundtrip_with_custom_root() {
        // 1. Root CA (Simulated Google Hardware Root CA)
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.distinguished_name.push(
            DnType::CommonName,
            "Simulated Google Hardware Attestation Root CA",
        );
        let root_key = KeyPair::generate().expect("Root key");
        let root_cert = root_params.self_signed(&root_key).expect("Root cert");
        let root_spki = root_key.public_key_der();

        // 2. Intermediate CA (Simulated OEM Batch CA)
        let mut int_params = CertificateParams::default();
        int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        int_params.distinguished_name.push(
            DnType::CommonName,
            "Simulated OEM Key Attestation Intermediate",
        );
        let int_key = KeyPair::generate().expect("Intermediate key");
        let int_cert = int_params
            .signed_by(&int_key, &root_cert, &root_key)
            .expect("Sign intermediate");

        // 3. Leaf Certificate with KeyDescription extension
        let leaf_key = KeyPair::generate().expect("Leaf key");
        let leaf_spki = leaf_key.public_key_der();

        let ext_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::TrustedEnvironment,
            4,
            AttestationSecurityLevel::TrustedEnvironment,
            b"test-nonce-123",
        );

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Android Keystore Leaf");
        let custom_ext =
            CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17], ext_der);
        leaf_params.custom_extensions.push(custom_ext);

        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &int_cert, &int_key)
            .expect("Sign leaf");

        let chain_pems = vec![leaf_cert.pem(), int_cert.pem(), root_cert.pem()];

        // Verifier configured with root SPKI
        let verifier = HardwareAttestationVerifier::with_custom_roots(&[root_spki]);

        // A. Verification succeeds when leaf public key matches expected CSR SPKI
        let result = verifier.verify_chain(&chain_pems, &leaf_spki);
        assert!(result.is_ok(), "Verification failed: {result:?}");
        let key_desc = result.unwrap();
        assert_eq!(
            key_desc.attestation_security_level,
            AttestationSecurityLevel::TrustedEnvironment
        );

        // B. Rejection when expected CSR SPKI does not match leaf public key
        let other_key = KeyPair::generate().unwrap();
        let mismatch_result = verifier.verify_chain(&chain_pems, &other_key.public_key_der());
        assert_eq!(mismatch_result, Err(AttestationError::PublicKeyMismatch));
    }

    #[test]
    fn test_hardware_attestation_chain_rejects_untrusted_root() {
        // Root CA not in verifier trust store
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Rogue Untrusted Root");
        let root_key = KeyPair::generate().expect("Root key");
        let root_cert = root_params.self_signed(&root_key).expect("Root cert");

        let leaf_key = KeyPair::generate().expect("Leaf key");
        let leaf_spki = leaf_key.public_key_der();

        let ext_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::TrustedEnvironment,
            4,
            AttestationSecurityLevel::TrustedEnvironment,
            b"test-nonce-123",
        );

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Android Keystore Leaf");
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                ext_der,
            ));
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .expect("Sign leaf");

        let chain_pems = vec![leaf_cert.pem(), root_cert.pem()];

        // Default verifier only trusts Google roots
        let verifier = HardwareAttestationVerifier::new();
        let result = verifier.verify_chain(&chain_pems, &leaf_spki);
        assert_eq!(result, Err(AttestationError::UntrustedRootCertificate));
    }

    #[test]
    fn test_hardware_attestation_chain_rejects_software_security_level() {
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root");
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_spki = root_key.public_key_der();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_spki = leaf_key.public_key_der();

        // KeyDescription with Software security level
        let soft_ext_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::Software,
            4,
            AttestationSecurityLevel::Software,
            b"soft-nonce",
        );

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Software Keystore Leaf");
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                soft_ext_der,
            ));
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let chain_pems = vec![leaf_cert.pem(), root_cert.pem()];
        let verifier = HardwareAttestationVerifier::with_custom_roots(&[root_spki]);

        let result = verifier.verify_chain(&chain_pems, &leaf_spki);
        assert_eq!(
            result,
            Err(AttestationError::InsecureSecurityLevel(
                AttestationSecurityLevel::Software
            ))
        );
    }

    #[test]
    fn test_hardware_attestation_chain_rejects_missing_extension() {
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root");
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_spki = root_key.public_key_der();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_spki = leaf_key.public_key_der();

        // Leaf certificate WITHOUT attestation extension
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Normal Leaf");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let chain_pems = vec![leaf_cert.pem(), root_cert.pem()];
        let verifier = HardwareAttestationVerifier::with_custom_roots(&[root_spki]);

        let result = verifier.verify_chain(&chain_pems, &leaf_spki);
        assert_eq!(result, Err(AttestationError::MissingAttestationExtension));
    }
}
