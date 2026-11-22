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
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b+YsV\
    9FPQywiyw8EQRTkJ9u3qwfnI4DGoSLlBqClTXJfgfCcZvs60FikNMHnu4fkRzObf\
    gDkU2KNXezT9/RQ+XvNslxPHrHCowhGr";

/// Maximum allowed certificates in an attestation chain (leaf + up to 5 intermediates/roots).
pub const MAX_ATTESTATION_CHAIN_LEN: usize = 6;

/// Maximum allowed total PEM byte size for attestation certificates (32 KiB).
pub const MAX_ATTESTATION_PEM_BYTES: usize = 32 * 1024;

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
    /// Key generation origin parsed from hardwareEnforced AuthorizationList (tag 702).
    /// Value 0 indicates KM_ORIGIN_GENERATED (hardware-generated).
    pub origin: Option<u32>,
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

    #[error("Certificate at index {0} is not a CA (BasicConstraints cA:TRUE required for non-leaf certs)")]
    InvalidCaConstraints(usize),

    #[error("Certificate at index {0} lacks keyCertSign in KeyUsage extension")]
    MissingKeyCertSign(usize),

    #[error("Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) found on non-leaf certificate at index {0}")]
    AttestationExtensionOnIntermediate(usize),

    #[error("Signature algorithm mismatch: outer {outer} != inner TBS {inner}")]
    SignatureAlgorithmMismatch { outer: String, inner: String },

    #[error(
        "Attestation challenge mismatch: expected challenge does not match certificate challenge"
    )]
    ChallengeMismatch,

    #[error(
        "Invalid key origin {0}: KM_ORIGIN_GENERATED (0) required, IMPORTED software keys rejected"
    )]
    InvalidKeyOrigin(u32),

    #[error("Missing KM_TAG_ORIGIN [702] in hardwareEnforced authorization list")]
    MissingOriginTag,

    #[error("Attestation certificate chain length {0} exceeds maximum limit of {1}")]
    ChainTooLong(usize, usize),

    #[error("Attestation certificate chain PEM byte size {0} exceeds maximum limit of {1}")]
    PayloadTooLarge(usize, usize),
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
        let rsa_der = pem::parse(format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            GOOGLE_ROOT_CA_RSA_SPKI_B64
        ))
        .expect("Valid hardcoded Google RSA root SPKI");
        trusted.insert(rsa_der.contents().to_vec());

        // Load Google EC root SPKI
        let ec_der = pem::parse(format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            GOOGLE_ROOT_CA_EC_SPKI_B64
        ))
        .expect("Valid hardcoded Google EC root SPKI");
        trusted.insert(ec_der.contents().to_vec());

        Self {
            trusted_root_spkis: trusted,
        }
    }

    /// Constructs a verifier that trusts ONLY the provided custom roots,
    /// excluding Google's default production roots. Ideal for hermetic lab and integration tests.
    ///
    /// # Arguments
    /// * `custom_root_spkis` - Slice of DER-encoded SubjectPublicKeyInfo byte vectors.
    pub fn with_exclusive_custom_roots(custom_root_spkis: &[Vec<u8>]) -> Self {
        let mut trusted = HashSet::new();
        for spki in custom_root_spkis {
            trusted.insert(spki.clone());
        }
        Self {
            trusted_root_spkis: trusted,
        }
    }

    /// Constructs a verifier that includes Google's default production roots
    /// plus additional custom roots.
    ///
    /// # Arguments
    /// * `custom_root_spkis` - Slice of DER-encoded SubjectPublicKeyInfo byte vectors.
    pub fn with_additional_roots(custom_root_spkis: &[Vec<u8>]) -> Self {
        let mut verifier = Self::new();
        for spki in custom_root_spkis {
            verifier.trusted_root_spkis.insert(spki.clone());
        }
        verifier
    }

    /// Backwards-compatible alias for `with_additional_roots`.
    pub fn with_custom_roots(custom_root_spkis: &[Vec<u8>]) -> Self {
        Self::with_additional_roots(custom_root_spkis)
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
        expected_challenge: Option<&[u8]>,
    ) -> Result<KeyDescription, AttestationError> {
        let total_bytes: usize = chain_pems.iter().map(|s| s.len()).sum();
        if total_bytes > MAX_ATTESTATION_PEM_BYTES {
            return Err(AttestationError::PayloadTooLarge(
                total_bytes,
                MAX_ATTESTATION_PEM_BYTES,
            ));
        }

        let cert_ders = parse_cert_chain_ders(chain_pems)?;
        if cert_ders.is_empty() {
            return Err(AttestationError::EmptyChain);
        }
        if cert_ders.len() < 2 {
            return Err(AttestationError::IncompleteChain(cert_ders.len()));
        }
        if cert_ders.len() > MAX_ATTESTATION_CHAIN_LEN {
            return Err(AttestationError::ChainTooLong(
                cert_ders.len(),
                MAX_ATTESTATION_CHAIN_LEN,
            ));
        }

        // Parse all certificates in the chain
        let mut parsed_certs = Vec::with_capacity(cert_ders.len());
        for (idx, der) in cert_ders.iter().enumerate() {
            let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
                AttestationError::CertificateParseError(format!("Cert at index {idx}: {e}"))
            })?;
            parsed_certs.push(cert);
        }

        // RFC 5280 & Google Attestation Path Validation:
        // Ensure that intermediate and root certs are CAs, have keyCertSign,
        // and that NO non-leaf certificate (index > 0) carries the attestation extension.
        for (idx, cert) in parsed_certs.iter().enumerate().skip(1) {
            // Check BasicConstraints CA:TRUE
            if !cert.is_ca() {
                return Err(AttestationError::InvalidCaConstraints(idx));
            }

            // Check KeyUsage keyCertSign if KeyUsage extension is present
            match cert.key_usage() {
                Ok(Some(ku_ext)) => {
                    if !ku_ext.value.key_cert_sign() {
                        return Err(AttestationError::MissingKeyCertSign(idx));
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(AttestationError::CertificateParseError(format!(
                        "Cert at index {idx} has malformed KeyUsage extension: {e}"
                    )));
                }
            }

            // Reject if attestation extension appears on any non-leaf certificate
            if cert
                .extensions()
                .iter()
                .any(|ext| ext.oid.to_id_string() == ANDROID_KEY_ATTESTATION_OID)
            {
                return Err(AttestationError::AttestationExtensionOnIntermediate(idx));
            }
        }

        // Step 1: Verify cryptographic signature chain from leaf to root
        for i in 0..parsed_certs.len() - 1 {
            let child = &parsed_certs[i];
            let parent = &parsed_certs[i + 1];

            // RFC 5280 §4.1.1.2: Signature algorithm matching
            if child.signature_algorithm != child.tbs_certificate.signature {
                return Err(AttestationError::SignatureAlgorithmMismatch {
                    outer: child.signature_algorithm.algorithm.to_id_string(),
                    inner: child.tbs_certificate.signature.algorithm.to_id_string(),
                });
            }

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
            warn!(
                "Root certificate with subject '{}' not found in trusted attestation roots",
                root.subject()
            );
            return Err(AttestationError::UntrustedRootCertificate);
        }

        // If root is self-signed, verify its self-signature
        if root.issuer() == root.subject() {
            if root.signature_algorithm != root.tbs_certificate.signature {
                return Err(AttestationError::SignatureAlgorithmMismatch {
                    outer: root.signature_algorithm.algorithm.to_id_string(),
                    inner: root.tbs_certificate.signature.algorithm.to_id_string(),
                });
            }
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
        if !key_desc.keymaster_security_level.is_hardware_backed() {
            return Err(AttestationError::InsecureSecurityLevel(
                key_desc.keymaster_security_level,
            ));
        }

        // Step 6: Verify key origin in hardwareEnforced list (KM_ORIGIN_GENERATED == 0)
        match key_desc.origin {
            Some(0) => {} // KM_ORIGIN_GENERATED
            Some(other) => return Err(AttestationError::InvalidKeyOrigin(other)),
            None => return Err(AttestationError::MissingOriginTag),
        }

        // Step 7: Staged challenge verification
        if let Some(expected) = expected_challenge {
            if key_desc.attestation_challenge != expected {
                return Err(AttestationError::ChallengeMismatch);
            }
        } else {
            warn!("Attestation challenge verification bypassed for legacy client compatibility");
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
            if parent_key_bytes.len() != 65 {
                return Err(AttestationError::UnsupportedSignatureAlgorithm(format!(
                    "ECDSA P-256 SHA-256 requires 65-byte uncompressed P-256 parent key, found {}",
                    parent_key_bytes.len()
                )));
            }
            if let Some(params) = &parent_spki.algorithm.parameters {
                if let Ok(oid) = params.as_oid() {
                    let oid_str = oid.to_id_string();
                    if oid_str != "1.2.840.10045.3.1.7" {
                        return Err(AttestationError::UnsupportedSignatureAlgorithm(format!(
                            "Expected ECDSA P-256 curve (1.2.840.10045.3.1.7), found {oid_str}"
                        )));
                    }
                }
            }
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
            if parent_key_bytes.len() != 97 {
                return Err(AttestationError::UnsupportedSignatureAlgorithm(format!(
                    "ECDSA P-384 SHA-384 requires 97-byte uncompressed P-384 parent key, found {}",
                    parent_key_bytes.len()
                )));
            }
            if let Some(params) = &parent_spki.algorithm.parameters {
                if let Ok(oid) = params.as_oid() {
                    let oid_str = oid.to_id_string();
                    if oid_str != "1.3.132.0.34" {
                        return Err(AttestationError::UnsupportedSignatureAlgorithm(format!(
                            "Expected ECDSA P-384 curve (1.3.132.0.34), found {oid_str}"
                        )));
                    }
                }
            }
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
    let (uid_bytes, uid_len) = parse_der_tlv_at(seq_content, offset, 0x04)
        .map_err(|e| AttestationError::ExtensionParseError(format!("uniqueId: {e}")))?;
    let unique_id = uid_bytes.to_vec();
    offset += uid_len;

    // Item 7: softwareEnforced (SEQUENCE, tag 0x30)
    let origin = if offset < seq_content.len() {
        let (_sw_bytes, sw_len) = parse_der_tlv_at(seq_content, offset, 0x30)
            .map_err(|e| AttestationError::ExtensionParseError(format!("softwareEnforced: {e}")))?;
        offset += sw_len;

        // Item 8: hardwareEnforced (SEQUENCE, tag 0x30)
        if offset < seq_content.len() {
            let (hw_bytes, _hw_len) = parse_der_tlv_at(seq_content, offset, 0x30).map_err(|e| {
                AttestationError::ExtensionParseError(format!("hardwareEnforced: {e}"))
            })?;
            parse_origin_from_authorization_list(hw_bytes)?
        } else {
            None
        }
    } else {
        None
    };

    Ok(KeyDescription {
        attestation_version,
        attestation_security_level,
        keymaster_version,
        keymaster_security_level,
        attestation_challenge,
        unique_id,
        origin,
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
    // DER INTEGER is signed two's complement.
    // If the leading bit of the most significant byte is 1, sign-extend with -1 (all 1s).
    let mut val: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
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

fn parse_der_length_and_value(bytes: &[u8]) -> Result<(&[u8], usize), String> {
    if bytes.is_empty() {
        return Err("Empty length bytes".to_string());
    }
    let len_byte = bytes[0];
    let (content_len, len_bytes_count) = if len_byte < 128 {
        (len_byte as usize, 1)
    } else {
        let num_len_bytes = (len_byte & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 {
            return Err(format!("Unsupported multi-byte length: {num_len_bytes}"));
        }
        if 1 + num_len_bytes > bytes.len() {
            return Err("Unexpected EOF reading length".to_string());
        }
        let mut len = 0;
        for i in 0..num_len_bytes {
            len = (len << 8) | (bytes[1 + i] as usize);
        }
        (len, 1 + num_len_bytes)
    };
    if len_bytes_count + content_len > bytes.len() {
        return Err(format!(
            "Content length {content_len} exceeds remaining bytes {}",
            bytes.len() - len_bytes_count
        ));
    }
    Ok((
        &bytes[len_bytes_count..len_bytes_count + content_len],
        len_bytes_count + content_len,
    ))
}

fn parse_origin_from_authorization_list(
    auth_list_content: &[u8],
) -> Result<Option<u32>, AttestationError> {
    let mut cursor = 0;
    while cursor < auth_list_content.len() {
        if cursor + 3 <= auth_list_content.len()
            && (auth_list_content[cursor] == 0xBF || auth_list_content[cursor] == 0x9F)
            && auth_list_content[cursor + 1] == 0x85
            && auth_list_content[cursor + 2] == 0x3E
        {
            let is_explicit = auth_list_content[cursor] == 0xBF;
            cursor += 3;
            let (content, _total_len) = parse_der_length_and_value(&auth_list_content[cursor..])
                .map_err(|e| AttestationError::ExtensionParseError(format!("Origin tag: {e}")))?;
            if is_explicit {
                let (int_bytes, _) = parse_der_tlv_at(content, 0, 0x02).map_err(|e| {
                    AttestationError::ExtensionParseError(format!("Origin INTEGER: {e}"))
                })?;
                let origin_val = der_bytes_to_u32(int_bytes)?;
                return Ok(Some(origin_val));
            } else {
                let origin_val = der_bytes_to_u32(content)?;
                return Ok(Some(origin_val));
            }
        } else {
            let first = auth_list_content[cursor];
            let tag_len = if (first & 0x1F) == 0x1F {
                let mut t = 1;
                while cursor + t < auth_list_content.len()
                    && (auth_list_content[cursor + t] & 0x80) != 0
                {
                    t += 1;
                }
                t + 1
            } else {
                1
            };
            cursor += tag_len;
            if cursor >= auth_list_content.len() {
                break;
            }
            let (_, total_len) = parse_der_length_and_value(&auth_list_content[cursor..])
                .map_err(|e| AttestationError::ExtensionParseError(format!("Skip tag: {e}")))?;
            cursor += total_len;
        }
    }
    Ok(None)
}

#[cfg(any(test, feature = "test-utils"))]
fn encode_der_integer(val: i64) -> Vec<u8> {
    if (0..128).contains(&val) {
        vec![0x02, 0x01, val as u8]
    } else if (128..=32767).contains(&val) {
        let b1 = ((val >> 8) & 0xFF) as u8;
        let b2 = (val & 0xFF) as u8;
        if (b1 & 0x80) != 0 {
            vec![0x02, 0x03, 0x00, b1, b2]
        } else {
            vec![0x02, 0x02, b1, b2]
        }
    } else {
        let mut bytes = Vec::new();
        let mut n = val;
        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        bytes.reverse();
        if bytes.is_empty() {
            bytes.push(0x00);
        } else if (bytes[0] & 0x80) != 0 {
            bytes.insert(0, 0x00);
        }
        let mut res = vec![0x02, bytes.len() as u8];
        res.extend_from_slice(&bytes);
        res
    }
}

/// Encodes a minimal ASN.1 KeyDescription SEQUENCE for testing and synthetic validation.
///
/// Traces to: [INV-002], [NFR-SEC-001]
#[cfg(any(test, feature = "test-utils"))]
pub fn build_test_key_description_der(
    attestation_version: i64,
    attestation_security_level: AttestationSecurityLevel,
    keymaster_version: i64,
    keymaster_security_level: AttestationSecurityLevel,
    challenge: &[u8],
) -> Vec<u8> {
    build_test_key_description_der_with_origin(
        attestation_version,
        attestation_security_level,
        keymaster_version,
        keymaster_security_level,
        challenge,
        0, // KM_ORIGIN_GENERATED
    )
}

/// Encodes a KeyDescription SEQUENCE with a custom key generation origin value.
#[cfg(any(test, feature = "test-utils"))]
pub fn build_test_key_description_der_with_origin(
    attestation_version: i64,
    attestation_security_level: AttestationSecurityLevel,
    keymaster_version: i64,
    keymaster_security_level: AttestationSecurityLevel,
    challenge: &[u8],
    origin: u32,
) -> Vec<u8> {
    let mut inner = Vec::new();

    // 1. attestationVersion (INTEGER 0x02)
    inner.extend_from_slice(&encode_der_integer(attestation_version));

    // 2. attestationSecurityLevel (ENUMERATED 0x0A)
    inner.push(0x0A);
    inner.push(0x01);
    inner.push(attestation_security_level as u8);

    // 3. keymasterVersion (INTEGER 0x02)
    inner.extend_from_slice(&encode_der_integer(keymaster_version));

    // 4. keymasterSecurityLevel (ENUMERATED 0x0A)
    inner.push(0x0A);
    inner.push(0x01);
    inner.push(keymaster_security_level as u8);

    // 5. attestationChallenge (OCTET STRING 0x04)
    inner.push(0x04);
    inner.push(challenge.len() as u8);
    inner.extend_from_slice(challenge);

    // 6. uniqueId (OCTET STRING 0x04)
    inner.push(0x04);
    inner.push(0x00);

    // 7. softwareEnforced (SEQUENCE 0x30)
    inner.push(0x30);
    inner.push(0x00);

    // 8. hardwareEnforced (SEQUENCE 0x30) containing tag [702] EXPLICIT INTEGER (origin)
    let hw_inner = vec![0xBF, 0x85, 0x3E, 0x03, 0x02, 0x01, origin as u8];
    inner.push(0x30);
    inner.push(hw_inner.len() as u8);
    inner.extend_from_slice(&hw_inner);

    // Wrap into outer SEQUENCE (0x30)
    let mut seq = Vec::new();
    seq.push(0x30);
    if inner.len() < 128 {
        seq.push(inner.len() as u8);
    } else {
        seq.push(0x81);
        seq.push(inner.len() as u8);
    }
    seq.extend_from_slice(&inner);

    seq
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };

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
        use x509_parser::x509::SubjectPublicKeyInfo;

        let rsa_pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            GOOGLE_ROOT_CA_RSA_SPKI_B64
        );
        let rsa_der = pem::parse(rsa_pem).expect("Valid RSA PEM").into_contents();
        let (_, rsa_spki) = SubjectPublicKeyInfo::from_der(&rsa_der).expect("Parseable RSA SPKI");
        assert_eq!(
            rsa_spki.algorithm.algorithm.to_id_string(),
            "1.2.840.113549.1.1.1"
        ); // rsaEncryption

        let ec_pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            GOOGLE_ROOT_CA_EC_SPKI_B64
        );
        let ec_der = pem::parse(ec_pem).expect("Valid EC PEM").into_contents();
        let (_, ec_spki) = SubjectPublicKeyInfo::from_der(&ec_der).expect("Parseable EC SPKI");
        assert_eq!(
            ec_spki.algorithm.algorithm.to_id_string(),
            "1.2.840.10045.2.1"
        ); // id-ecPublicKey
        assert_eq!(ec_der.len(), 120);

        let verifier = HardwareAttestationVerifier::new();
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
        let result = verifier.verify_chain(&chain_pems, &leaf_spki, None);
        assert!(result.is_ok(), "Verification failed: {result:?}");
        let key_desc = result.unwrap();
        assert_eq!(
            key_desc.attestation_security_level,
            AttestationSecurityLevel::TrustedEnvironment
        );
        assert_eq!(key_desc.origin, Some(0));

        // B. Rejection when expected CSR SPKI does not match leaf public key
        let other_key = KeyPair::generate().unwrap();
        let mismatch_result = verifier.verify_chain(&chain_pems, &other_key.public_key_der(), None);
        assert_eq!(mismatch_result, Err(AttestationError::PublicKeyMismatch));
    }

    #[test]
    fn test_leaf_as_ca_chain_extension_forgery_rejected() {
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root");
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_spki = root_key.public_key_der();

        // Intermediate cert that is NOT a CA (cA:FALSE / NoCa)
        let mut int_params = CertificateParams::default();
        int_params.is_ca = IsCa::NoCa;
        int_params
            .distinguished_name
            .push(DnType::CommonName, "Attacker Phone Leaf Key Claiming CA");
        let int_key = KeyPair::generate().unwrap();
        let int_cert = int_params
            .signed_by(&int_key, &root_cert, &root_key)
            .unwrap();

        // Forged leaf cert signed by the non-CA cert
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_spki = leaf_key.public_key_der();
        let ext_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::StrongBox,
            3,
            AttestationSecurityLevel::StrongBox,
            b"fake-challenge",
        );
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                ext_der,
            ));
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &int_cert, &int_key)
            .unwrap();

        let chain_pems = vec![leaf_cert.pem(), int_cert.pem(), root_cert.pem()];
        let verifier = HardwareAttestationVerifier::with_custom_roots(&[root_spki]);

        let result = verifier.verify_chain(&chain_pems, &leaf_spki, None);
        assert_eq!(result, Err(AttestationError::InvalidCaConstraints(1)));
    }

    #[test]
    fn test_intermediate_with_attestation_extension_rejected() {
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root");
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_spki = root_key.public_key_der();

        // Intermediate CA that carries the attestation extension (forbidden on non-leaf)
        let ext_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::TrustedEnvironment,
            4,
            AttestationSecurityLevel::TrustedEnvironment,
            b"nonce",
        );
        let mut int_params = CertificateParams::default();
        int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        int_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                ext_der.clone(),
            ));
        let int_key = KeyPair::generate().unwrap();
        let int_cert = int_params
            .signed_by(&int_key, &root_cert, &root_key)
            .unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_spki = leaf_key.public_key_der();
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                ext_der,
            ));
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &int_cert, &int_key)
            .unwrap();

        let chain_pems = vec![leaf_cert.pem(), int_cert.pem(), root_cert.pem()];
        let verifier = HardwareAttestationVerifier::with_custom_roots(&[root_spki]);

        let result = verifier.verify_chain(&chain_pems, &leaf_spki, None);
        assert_eq!(
            result,
            Err(AttestationError::AttestationExtensionOnIntermediate(1))
        );
    }

    #[test]
    fn test_hardware_attestation_chain_rejects_untrusted_root() {
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

        let verifier = HardwareAttestationVerifier::new();
        let result = verifier.verify_chain(&chain_pems, &leaf_spki, None);
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

        // KeyDescription with Software attestation security level
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

        let result = verifier.verify_chain(&chain_pems, &leaf_spki, None);
        assert_eq!(
            result,
            Err(AttestationError::InsecureSecurityLevel(
                AttestationSecurityLevel::Software
            ))
        );

        // KeyDescription with TEE attestation but Software keymaster level
        let soft_km_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::TrustedEnvironment,
            4,
            AttestationSecurityLevel::Software,
            b"soft-km-nonce",
        );
        let mut leaf_params_km = CertificateParams::default();
        leaf_params_km
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                soft_km_der,
            ));
        let leaf_cert_km = leaf_params_km
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let chain_pems_km = vec![leaf_cert_km.pem(), root_cert.pem()];
        let result_km = verifier.verify_chain(&chain_pems_km, &leaf_spki, None);
        assert_eq!(
            result_km,
            Err(AttestationError::InsecureSecurityLevel(
                AttestationSecurityLevel::Software
            ))
        );
    }

    #[test]
    fn test_hardware_attestation_chain_rejects_imported_key_origin() {
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

        // Origin 2 = KM_ORIGIN_IMPORTED
        let imported_der = build_test_key_description_der_with_origin(
            3,
            AttestationSecurityLevel::TrustedEnvironment,
            4,
            AttestationSecurityLevel::TrustedEnvironment,
            b"imported-nonce",
            2,
        );

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                imported_der,
            ));
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let chain_pems = vec![leaf_cert.pem(), root_cert.pem()];
        let verifier = HardwareAttestationVerifier::with_custom_roots(&[root_spki]);

        let result = verifier.verify_chain(&chain_pems, &leaf_spki, None);
        assert_eq!(result, Err(AttestationError::InvalidKeyOrigin(2)));
    }

    #[test]
    fn test_challenge_verification_match_and_mismatch() {
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

        let ext_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::TrustedEnvironment,
            4,
            AttestationSecurityLevel::TrustedEnvironment,
            b"expected-challenge-nonce",
        );

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                ext_der,
            ));
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let chain_pems = vec![leaf_cert.pem(), root_cert.pem()];
        let verifier = HardwareAttestationVerifier::with_custom_roots(&[root_spki]);

        // Matches expected challenge
        let match_result =
            verifier.verify_chain(&chain_pems, &leaf_spki, Some(b"expected-challenge-nonce"));
        assert!(match_result.is_ok());

        // Mismatches expected challenge
        let mismatch_result =
            verifier.verify_chain(&chain_pems, &leaf_spki, Some(b"wrong-challenge"));
        assert_eq!(mismatch_result, Err(AttestationError::ChallengeMismatch));
    }

    #[test]
    fn test_exclusive_custom_roots_rejects_google_root() {
        let dummy_spki = vec![1, 2, 3, 4, 5];
        let verifier = HardwareAttestationVerifier::with_exclusive_custom_roots(&[dummy_spki]);
        // Must contain only the 1 custom root, zero Google roots
        assert_eq!(verifier.trusted_root_spkis.len(), 1);
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

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Normal Leaf");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let chain_pems = vec![leaf_cert.pem(), root_cert.pem()];
        let verifier = HardwareAttestationVerifier::with_custom_roots(&[root_spki]);

        let result = verifier.verify_chain(&chain_pems, &leaf_spki, None);
        assert_eq!(result, Err(AttestationError::MissingAttestationExtension));
    }

    #[test]
    fn test_intermediate_missing_key_cert_sign_rejected() {
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root");
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_spki = root_key.public_key_der();

        let mut int_params = CertificateParams::default();
        int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        int_params
            .distinguished_name
            .push(DnType::CommonName, "Intermediate Without KeyCertSign");
        // Explicitly set key usages without KeyCertSign
        int_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let int_key = KeyPair::generate().unwrap();
        let int_cert = int_params
            .signed_by(&int_key, &root_cert, &root_key)
            .unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_spki = leaf_key.public_key_der();
        let ext_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::TrustedEnvironment,
            4,
            AttestationSecurityLevel::TrustedEnvironment,
            b"nonce",
        );
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Leaf");
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                ext_der,
            ));
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &int_cert, &int_key)
            .unwrap();

        let chain_pems = vec![leaf_cert.pem(), int_cert.pem(), root_cert.pem()];
        let verifier = HardwareAttestationVerifier::with_custom_roots(&[root_spki]);

        let result = verifier.verify_chain(&chain_pems, &leaf_spki, None);
        assert_eq!(result, Err(AttestationError::MissingKeyCertSign(1)));
    }

    #[test]
    fn test_multi_cert_bundle_exceeding_chain_len_rejected() {
        let mut cert_pems = Vec::new();
        for i in 0..7 {
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(DnType::CommonName, format!("Bundle Cert {i}"));
            let key = KeyPair::generate().unwrap();
            let cert = params.self_signed(&key).unwrap();
            cert_pems.push(cert.pem());
        }

        // Bundle all 7 certs into a single PEM string
        let bundle_single_pem = cert_pems.join("\n");
        let verifier = HardwareAttestationVerifier::new();
        let dummy_spki = vec![0u8; 32];

        // Must reject because total parsed DER certificates (7) > MAX_ATTESTATION_CHAIN_LEN (6)
        let result = verifier.verify_chain(&[bundle_single_pem], &dummy_spki, None);
        assert_eq!(
            result,
            Err(AttestationError::ChainTooLong(7, MAX_ATTESTATION_CHAIN_LEN))
        );
    }

    #[test]
    fn test_der_bytes_to_i64_two_complement() {
        assert_eq!(der_bytes_to_i64(&[0x01]).unwrap(), 1);
        assert_eq!(der_bytes_to_i64(&[0x00, 0x80]).unwrap(), 128);
        assert_eq!(der_bytes_to_i64(&[0x00, 0xFF]).unwrap(), 255);
        assert_eq!(der_bytes_to_i64(&[0xFF]).unwrap(), -1);
        assert_eq!(der_bytes_to_i64(&[0xFE]).unwrap(), -2);
        assert_eq!(der_bytes_to_i64(&[0x80]).unwrap(), -128);
    }

    #[test]
    fn test_signature_algorithm_mismatch_rejected() {
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
        let ext_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::TrustedEnvironment,
            4,
            AttestationSecurityLevel::TrustedEnvironment,
            b"nonce",
        );
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Leaf");
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                ext_der,
            ));
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        // Tamper with the outer signature algorithm OID in the leaf certificate DER
        let mut leaf_der = leaf_cert.der().to_vec();
        // ecdsa-with-SHA256 OID bytes: 06 08 2A 86 48 CE 3D 04 03 02
        let oid_pattern = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
        let matches: Vec<usize> = leaf_der
            .windows(oid_pattern.len())
            .enumerate()
            .filter(|(_, window)| *window == oid_pattern)
            .map(|(idx, _)| idx)
            .collect();
        // There are at least two occurrences: inner (TBS) and outer. Tamper with the last (outer) one.
        assert!(matches.len() >= 2);
        let outer_oid_pos = *matches.last().unwrap();
        // Change last byte from 0x02 (SHA-256) to 0x03 (SHA-384)
        leaf_der[outer_oid_pos + oid_pattern.len() - 1] = 0x03;

        let tampered_leaf_pem = pem::encode(&pem::Pem::new("CERTIFICATE", leaf_der));
        let chain_pems = vec![tampered_leaf_pem, root_cert.pem()];
        let verifier = HardwareAttestationVerifier::with_custom_roots(&[root_spki]);

        let result = verifier.verify_chain(&chain_pems, &leaf_spki, None);
        assert!(matches!(
            result,
            Err(AttestationError::SignatureAlgorithmMismatch { .. })
        ));
    }
}
