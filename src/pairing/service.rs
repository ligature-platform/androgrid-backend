//! Orchestrator Bootstrap Enrollment Service (gRPC & HTTP)
//!
//! Provides the single non-mTLS bootstrap exchange where unprovisioned worker
//! nodes redeem an ephemeral pairing token and PKCS#10 CSR to receive their mTLS credentials.
//!
//! Traces to: AG-SPEC-2026-V2 Section 2.3, [INV-002], [NFR-SEC-001], [REQ-OP-001]

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tonic::{Request, Response as TonicResponse, Status};
use tracing::{error, info, warn};

use crate::pairing::attestation::{AttestationError, HardwareAttestationVerifier};
use crate::pairing::signer::{CaSigner, SignedWorkerCert, SignerError};
use crate::pairing::token::{PairingError, PairingTokenStore, RedeemActionError};
use crate::proto::androgrid::v1::enrollment_service_server::EnrollmentService;
use crate::proto::androgrid::v1::{EnrollWorkerRequest, EnrollWorkerResponse};

/// HTTP JSON request body for device bootstrap enrollment.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpEnrollRequest {
    /// Single-use ephemeral pairing token.
    pub pairing_token: String,

    /// Mobile worker node identifier.
    pub node_id: String,

    /// PEM-encoded PKCS#10 Certificate Signing Request.
    pub csr_pem: String,

    /// Optional PEM-encoded Android KeyStore hardware attestation certificate chain.
    #[serde(default)]
    pub attestation_certificate_chain_pem: Vec<String>,
}

/// HTTP JSON response body for device bootstrap enrollment.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct HttpEnrollResponse {
    /// Whether enrollment and certificate issuance succeeded.
    pub success: bool,

    /// PEM-encoded signed client certificate (if successful).
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub client_cert_pem: String,

    /// PEM-encoded Root CA certificate for pinning (if successful).
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub ca_cert_pem: String,

    /// Error description if enrollment failed.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error_message: String,
}

/// Maximum number of certificates allowed in an attestation chain PEM submission.
pub use crate::pairing::attestation::{MAX_ATTESTATION_CHAIN_LEN, MAX_ATTESTATION_PEM_BYTES};

/// Shared application state for bootstrap enrollment services.
#[derive(Clone)]
pub struct EnrollmentContext {
    pub token_store: Arc<PairingTokenStore>,
    pub signer: Arc<CaSigner>,
    pub enforce_hardware_attestation: bool,
    pub require_attestation_challenge: bool,
    pub attestation_verifier: Arc<HardwareAttestationVerifier>,
}

/// Unified enrollment error distinguishing token/rate-limit errors from CSR signing and attestation errors.
pub enum EnrollFailure {
    Pairing(PairingError),
    Signer(SignerError),
    Attestation(AttestationError),
}

impl std::fmt::Display for EnrollFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollFailure::Pairing(e) => e.fmt(f),
            EnrollFailure::Signer(e) => e.fmt(f),
            EnrollFailure::Attestation(e) => e.fmt(f),
        }
    }
}

impl EnrollmentContext {
    /// Constructs a new EnrollmentContext with default hardware attestation settings.
    pub fn new(token_store: Arc<PairingTokenStore>, signer: Arc<CaSigner>) -> Self {
        Self {
            token_store,
            signer,
            enforce_hardware_attestation: false,
            require_attestation_challenge: false,
            attestation_verifier: Arc::new(HardwareAttestationVerifier::new()),
        }
    }

    /// Constructs an EnrollmentContext with explicit hardware attestation enforcement policy and verifier.
    pub fn with_hardware_attestation(
        token_store: Arc<PairingTokenStore>,
        signer: Arc<CaSigner>,
        enforce_hardware_attestation: bool,
        require_attestation_challenge: bool,
        attestation_verifier: Option<Arc<HardwareAttestationVerifier>>,
    ) -> Self {
        Self {
            token_store,
            signer,
            enforce_hardware_attestation,
            require_attestation_challenge,
            attestation_verifier: attestation_verifier
                .unwrap_or_else(|| Arc::new(HardwareAttestationVerifier::new())),
        }
    }

    /// Atomically validates the pairing token, verifies the KeyStore hardware attestation chain
    /// (if enforced or provided), signs the worker CSR, and marks the token as redeemed
    /// only after certificate issuance succeeds.
    ///
    /// Traces to: [INV-001], [INV-002], [NFR-SEC-001], [REQ-OP-001]
    pub fn redeem_and_sign(
        &self,
        token: &str,
        node_id: &str,
        csr_pem: &str,
        attestation_chain_pem: &[String],
    ) -> Result<SignedWorkerCert, EnrollFailure> {
        self.token_store
            .redeem_with(token, node_id, |_| {
                if self.enforce_hardware_attestation && attestation_chain_pem.is_empty() {
                    return Err(EnrollFailure::Attestation(
                        AttestationError::AttestationRequired,
                    ));
                }

                if !attestation_chain_pem.is_empty() {
                    if attestation_chain_pem.len() > MAX_ATTESTATION_CHAIN_LEN {
                        return Err(EnrollFailure::Attestation(AttestationError::ChainTooLong(
                            attestation_chain_pem.len(),
                            MAX_ATTESTATION_CHAIN_LEN,
                        )));
                    }

                    let total_bytes: usize = attestation_chain_pem.iter().map(|s| s.len()).sum();
                    if total_bytes > MAX_ATTESTATION_PEM_BYTES {
                        return Err(EnrollFailure::Attestation(
                            AttestationError::PayloadTooLarge(
                                total_bytes,
                                MAX_ATTESTATION_PEM_BYTES,
                            ),
                        ));
                    }

                    let csr_spki =
                        CaSigner::extract_p256_csr_spki(csr_pem).map_err(EnrollFailure::Signer)?;

                    let expected_challenge = if self.require_attestation_challenge {
                        let digest = ring::digest::digest(
                            &ring::digest::SHA256,
                            format!("{token}:{node_id}").as_bytes(),
                        );
                        Some(digest)
                    } else {
                        None
                    };

                    self.attestation_verifier
                        .verify_chain(
                            attestation_chain_pem,
                            &csr_spki,
                            expected_challenge.as_ref().map(|d| d.as_ref()),
                        )
                        .map_err(EnrollFailure::Attestation)?;
                }

                self.signer
                    .sign_worker_csr(csr_pem, node_id)
                    .map_err(EnrollFailure::Signer)
            })
            .map_err(|err| match err {
                RedeemActionError::Pairing(e) => EnrollFailure::Pairing(e),
                RedeemActionError::Action(e) => e,
            })
    }
}

/// Tonic gRPC implementation of the EnrollmentService.
///
/// Traces to: [INV-002], [NFR-SEC-001], [REQ-OP-001]
pub struct EnrollmentServiceImpl {
    context: EnrollmentContext,
}

impl EnrollmentServiceImpl {
    /// Constructs a new EnrollmentServiceImpl with the provided context.
    pub fn new(token_store: Arc<PairingTokenStore>, signer: Arc<CaSigner>) -> Self {
        Self {
            context: EnrollmentContext::new(token_store, signer),
        }
    }

    /// Constructs an EnrollmentServiceImpl with a pre-configured EnrollmentContext.
    pub fn with_context(context: EnrollmentContext) -> Self {
        Self { context }
    }
}

#[tonic::async_trait]
impl EnrollmentService for EnrollmentServiceImpl {
    async fn enroll_worker(
        &self,
        request: Request<EnrollWorkerRequest>,
    ) -> Result<TonicResponse<EnrollWorkerResponse>, Status> {
        let req = request.into_inner();
        let token = req.pairing_token.trim();
        let node_id = req.node_id.trim();
        let csr_pem = req.csr_pem.trim();

        if token.is_empty() {
            return Ok(TonicResponse::new(EnrollWorkerResponse {
                success: false,
                client_cert_pem: String::new(),
                ca_cert_pem: String::new(),
                error_message: "Pairing token cannot be empty".to_string(),
            }));
        }

        if node_id.is_empty() {
            return Ok(TonicResponse::new(EnrollWorkerResponse {
                success: false,
                client_cert_pem: String::new(),
                ca_cert_pem: String::new(),
                error_message: "Node identifier cannot be empty".to_string(),
            }));
        }

        if csr_pem.is_empty() {
            return Ok(TonicResponse::new(EnrollWorkerResponse {
                success: false,
                client_cert_pem: String::new(),
                ca_cert_pem: String::new(),
                error_message: "CSR PEM cannot be empty".to_string(),
            }));
        }

        info!(node_id = %node_id, "Processing gRPC worker enrollment request [REQ-OP-001]");

        match self.context.redeem_and_sign(
            token,
            node_id,
            csr_pem,
            &req.attestation_certificate_chain_pem,
        ) {
            Ok(signed) => {
                info!(node_id = %node_id, "Successfully issued mTLS client certificate [INV-002]");
                Ok(TonicResponse::new(EnrollWorkerResponse {
                    success: true,
                    client_cert_pem: signed.client_cert_pem,
                    ca_cert_pem: signed.ca_cert_pem,
                    error_message: String::new(),
                }))
            }
            Err(EnrollFailure::Pairing(e)) => {
                warn!(node_id = %node_id, error = %e, "Enrollment token redemption rejected");
                Ok(TonicResponse::new(EnrollWorkerResponse {
                    success: false,
                    client_cert_pem: String::new(),
                    ca_cert_pem: String::new(),
                    error_message: e.to_string(),
                }))
            }
            Err(EnrollFailure::Signer(e)) => {
                error!(node_id = %node_id, error = %e, "Failed to sign worker CSR");
                Ok(TonicResponse::new(EnrollWorkerResponse {
                    success: false,
                    client_cert_pem: String::new(),
                    ca_cert_pem: String::new(),
                    error_message: e.to_string(),
                }))
            }
            Err(EnrollFailure::Attestation(e)) => {
                warn!(node_id = %node_id, error = %e, "Worker hardware attestation rejected");
                Ok(TonicResponse::new(EnrollWorkerResponse {
                    success: false,
                    client_cert_pem: String::new(),
                    ca_cert_pem: String::new(),
                    error_message: e.to_string(),
                }))
            }
        }
    }
}

/// Builds an Axum Router exposing the HTTP enrollment endpoint.
///
/// Traces to: [INV-002], [NFR-SEC-001], [REQ-OP-001]
pub fn enrollment_http_router(context: EnrollmentContext) -> Router {
    Router::new()
        .route("/api/v1/enroll", post(handle_http_enroll))
        .route("/api/v1/pairing/enroll", post(handle_http_enroll))
        .with_state(context)
}

/// Axum HTTP handler processing bootstrap enrollment submissions.
async fn handle_http_enroll(
    State(context): State<EnrollmentContext>,
    Json(payload): Json<HttpEnrollRequest>,
) -> Response {
    let token = payload.pairing_token.trim();
    let node_id = payload.node_id.trim();
    let csr_pem = payload.csr_pem.trim();

    if token.is_empty() || node_id.is_empty() || csr_pem.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(HttpEnrollResponse {
                success: false,
                client_cert_pem: String::new(),
                ca_cert_pem: String::new(),
                error_message: "pairing_token, node_id, and csr_pem must all be non-empty"
                    .to_string(),
            }),
        )
            .into_response();
    }

    info!(node_id = %node_id, "Processing HTTP worker enrollment request [REQ-OP-001]");

    match context.redeem_and_sign(
        token,
        node_id,
        csr_pem,
        &payload.attestation_certificate_chain_pem,
    ) {
        Ok(signed) => {
            info!(node_id = %node_id, "Successfully issued mTLS client certificate via HTTP [INV-002]");
            (
                StatusCode::OK,
                Json(HttpEnrollResponse {
                    success: true,
                    client_cert_pem: signed.client_cert_pem,
                    ca_cert_pem: signed.ca_cert_pem,
                    error_message: String::new(),
                }),
            )
                .into_response()
        }
        Err(EnrollFailure::Pairing(e)) => {
            warn!(node_id = %node_id, error = %e, "HTTP enrollment token redemption rejected");
            let status = match e {
                PairingError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
                PairingError::TokenExpired { .. } => StatusCode::GONE,
                PairingError::TokenAlreadyRedeemed => StatusCode::CONFLICT,
                PairingError::PairingDisabled => StatusCode::FORBIDDEN,
                _ => StatusCode::UNAUTHORIZED,
            };

            (
                status,
                Json(HttpEnrollResponse {
                    success: false,
                    client_cert_pem: String::new(),
                    ca_cert_pem: String::new(),
                    error_message: e.to_string(),
                }),
            )
                .into_response()
        }
        Err(EnrollFailure::Signer(e)) => {
            error!(node_id = %node_id, error = %e, "Failed to sign worker CSR via HTTP");
            (
                StatusCode::BAD_REQUEST,
                Json(HttpEnrollResponse {
                    success: false,
                    client_cert_pem: String::new(),
                    ca_cert_pem: String::new(),
                    error_message: e.to_string(),
                }),
            )
                .into_response()
        }
        Err(EnrollFailure::Attestation(e)) => {
            warn!(node_id = %node_id, error = %e, "HTTP worker hardware attestation rejected");
            (
                StatusCode::FORBIDDEN,
                Json(HttpEnrollResponse {
                    success: false,
                    client_cert_pem: String::new(),
                    ca_cert_pem: String::new(),
                    error_message: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    fn create_test_context() -> (EnrollmentContext, KeyPair, String) {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "AndroGrid Test Root CA");
        let ca_key = KeyPair::generate().expect("CA key generation");
        let ca_cert = ca_params.self_signed(&ca_key).expect("Self-sign CA cert");

        let signer = Arc::new(
            CaSigner::from_pem(&ca_cert.pem(), &ca_key.serialize_pem())
                .expect("CaSigner initialization"),
        );
        let token_store = Arc::new(PairingTokenStore::default());

        (
            EnrollmentContext::new(token_store, signer),
            ca_key,
            ca_cert.pem(),
        )
    }

    fn generate_test_csr(node_id: &str) -> (String, KeyPair) {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, node_id);
        let key = KeyPair::generate().expect("Worker key generation");
        let csr = params.serialize_request(&key).expect("CSR serialization");
        (csr.pem().expect("CSR PEM"), key)
    }

    #[tokio::test]
    async fn test_grpc_enrollment_lifecycle_and_single_use_enforcement() {
        let (ctx, _ca_key, _ca_pem) = create_test_context();
        let service =
            EnrollmentServiceImpl::new(Arc::clone(&ctx.token_store), Arc::clone(&ctx.signer));

        let node_id = "test-worker-alpha";
        let record = ctx
            .token_store
            .generate_token(Some(node_id.to_string()), Some(300))
            .expect("Token generation");

        let (csr_pem, _worker_key) = generate_test_csr(node_id);

        let req = tonic::Request::new(EnrollWorkerRequest {
            pairing_token: record.token.clone(),
            node_id: node_id.to_string(),
            csr_pem: csr_pem.clone(),
            attestation_certificate_chain_pem: Vec::new(),
        });

        // 1. Initial enrollment must succeed
        let resp = service.enroll_worker(req).await.expect("RPC call");
        let body = resp.into_inner();
        assert!(
            body.success,
            "Enrollment must succeed: {}",
            body.error_message
        );
        assert!(!body.client_cert_pem.is_empty());
        assert!(!body.ca_cert_pem.is_empty());

        // 2. Second enrollment with same token must fail (single-use invariant)
        let repeat_req = tonic::Request::new(EnrollWorkerRequest {
            pairing_token: record.token,
            node_id: node_id.to_string(),
            csr_pem,
            attestation_certificate_chain_pem: Vec::new(),
        });

        let repeat_resp = service.enroll_worker(repeat_req).await.expect("RPC call");
        let repeat_body = repeat_resp.into_inner();
        assert!(!repeat_body.success, "Repeated enrollment must be rejected");
        assert!(repeat_body.error_message.contains("already been redeemed"));
    }

    #[tokio::test]
    async fn test_grpc_enrollment_mismatched_node_id_rejected() {
        let (ctx, _ca_key, _ca_pem) = create_test_context();
        let service =
            EnrollmentServiceImpl::new(Arc::clone(&ctx.token_store), Arc::clone(&ctx.signer));

        let record = ctx
            .token_store
            .generate_token(Some("expected-worker".to_string()), Some(300))
            .expect("Token generation");

        let (csr_pem, _worker_key) = generate_test_csr("impostor-worker");

        let req = tonic::Request::new(EnrollWorkerRequest {
            pairing_token: record.token,
            node_id: "impostor-worker".to_string(),
            csr_pem,
            attestation_certificate_chain_pem: Vec::new(),
        });

        let resp = service.enroll_worker(req).await.expect("RPC call");
        let body = resp.into_inner();
        assert!(!body.success);
        assert!(body.error_message.contains("mismatch"));
    }

    #[tokio::test]
    async fn test_malformed_csr_does_not_burn_pairing_token() {
        let (ctx, _ca_key, _ca_pem) = create_test_context();
        let service =
            EnrollmentServiceImpl::new(Arc::clone(&ctx.token_store), Arc::clone(&ctx.signer));

        let node_id = "worker-retry-csr";
        let record = ctx
            .token_store
            .generate_token(Some(node_id.to_string()), Some(300))
            .expect("Token generation");

        // Submit malformed CSR first
        let bad_req = tonic::Request::new(EnrollWorkerRequest {
            pairing_token: record.token.clone(),
            node_id: node_id.to_string(),
            csr_pem: "NOT A VALID CSR".to_string(),
            attestation_certificate_chain_pem: Vec::new(),
        });
        let bad_resp = service.enroll_worker(bad_req).await.expect("RPC call");
        assert!(!bad_resp.into_inner().success);

        // Retry with valid CSR must succeed using the same token
        let (csr_pem, _key) = generate_test_csr(node_id);
        let good_req = tonic::Request::new(EnrollWorkerRequest {
            pairing_token: record.token,
            node_id: node_id.to_string(),
            csr_pem,
            attestation_certificate_chain_pem: Vec::new(),
        });
        let good_resp = service.enroll_worker(good_req).await.expect("RPC call");
        let body = good_resp.into_inner();
        assert!(
            body.success,
            "Retry with valid CSR must succeed: {}",
            body.error_message
        );
    }

    #[tokio::test]
    async fn test_grpc_enrollment_rejects_missing_attestation_when_enforced() {
        let (base_ctx, _ca_key, _ca_pem) = create_test_context();
        let enforced_ctx = EnrollmentContext::with_hardware_attestation(
            Arc::clone(&base_ctx.token_store),
            Arc::clone(&base_ctx.signer),
            true, // enforce hardware attestation
            false,
            None,
        );
        let service = EnrollmentServiceImpl::with_context(enforced_ctx);

        let node_id = "worker-no-attestation";
        let record = base_ctx
            .token_store
            .generate_token(Some(node_id.to_string()), Some(300))
            .expect("Token generation");

        let (csr_pem, _key) = generate_test_csr(node_id);
        let req = tonic::Request::new(EnrollWorkerRequest {
            pairing_token: record.token.clone(),
            node_id: node_id.to_string(),
            csr_pem: csr_pem.clone(),
            attestation_certificate_chain_pem: Vec::new(), // No attestation chain
        });

        let resp = service.enroll_worker(req).await.expect("RPC call");
        let body = resp.into_inner();
        assert!(
            !body.success,
            "Must reject enrollment without attestation when enforced"
        );
        assert!(body
            .error_message
            .contains("Hardware attestation chain required"));

        // Single-use token must NOT be burned by a failed attestation check
        let retry_token = base_ctx.token_store.redeem_token(&record.token, node_id);
        assert!(
            retry_token.is_ok(),
            "Token should remain unredeemed on attestation rejection"
        );
    }

    #[tokio::test]
    async fn test_grpc_enrollment_rejects_software_attestation_when_enforced() {
        use crate::pairing::attestation::build_test_key_description_der;
        use crate::pairing::attestation::AttestationSecurityLevel;
        use rcgen::CustomExtension;

        let (base_ctx, _ca_key, _ca_pem) = create_test_context();

        // Generate test attestation root
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Hardware Root");
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_spki = root_key.public_key_der();

        let verifier = Arc::new(HardwareAttestationVerifier::with_custom_roots(&[root_spki]));
        let enforced_ctx = EnrollmentContext::with_hardware_attestation(
            Arc::clone(&base_ctx.token_store),
            Arc::clone(&base_ctx.signer),
            true,
            false,
            Some(verifier),
        );
        let service = EnrollmentServiceImpl::with_context(enforced_ctx);

        let node_id = "worker-software-attest";
        let record = base_ctx
            .token_store
            .generate_token(Some(node_id.to_string()), Some(300))
            .expect("Token generation");

        let (csr_pem, worker_key) = generate_test_csr(node_id);

        // Build leaf certificate containing Software security level attestation
        let soft_ext_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::Software,
            4,
            AttestationSecurityLevel::Software,
            b"test-nonce",
        );
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, node_id);
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                soft_ext_der,
            ));
        let leaf_cert = leaf_params
            .signed_by(&worker_key, &root_cert, &root_key)
            .unwrap();

        let chain = vec![leaf_cert.pem(), root_cert.pem()];

        let req = tonic::Request::new(EnrollWorkerRequest {
            pairing_token: record.token.clone(),
            node_id: node_id.to_string(),
            csr_pem: csr_pem.clone(),
            attestation_certificate_chain_pem: chain,
        });

        let resp = service.enroll_worker(req).await.expect("RPC call");
        let body = resp.into_inner();
        assert!(!body.success, "Software attestation must be rejected");
        assert!(body
            .error_message
            .contains("Insecure attestation security level"));
    }

    #[tokio::test]
    async fn test_grpc_enrollment_accepts_valid_hardware_attestation_when_enforced() {
        use crate::pairing::attestation::build_test_key_description_der;
        use crate::pairing::attestation::AttestationSecurityLevel;
        use rcgen::CustomExtension;

        let (base_ctx, _ca_key, _ca_pem) = create_test_context();

        // Generate test attestation root
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Hardware Root");
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_spki = root_key.public_key_der();

        let verifier = Arc::new(HardwareAttestationVerifier::with_custom_roots(&[root_spki]));
        let enforced_ctx = EnrollmentContext::with_hardware_attestation(
            Arc::clone(&base_ctx.token_store),
            Arc::clone(&base_ctx.signer),
            true,
            false,
            Some(verifier),
        );
        let service = EnrollmentServiceImpl::with_context(enforced_ctx);

        let node_id = "worker-hardware-attest";
        let record = base_ctx
            .token_store
            .generate_token(Some(node_id.to_string()), Some(300))
            .expect("Token generation");

        let (csr_pem, worker_key) = generate_test_csr(node_id);

        // Build leaf certificate containing TrustedEnvironment security level attestation
        let tee_ext_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::TrustedEnvironment,
            4,
            AttestationSecurityLevel::TrustedEnvironment,
            b"valid-tee-nonce",
        );
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, node_id);
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                tee_ext_der,
            ));
        let leaf_cert = leaf_params
            .signed_by(&worker_key, &root_cert, &root_key)
            .unwrap();

        let chain = vec![leaf_cert.pem(), root_cert.pem()];

        let req = tonic::Request::new(EnrollWorkerRequest {
            pairing_token: record.token.clone(),
            node_id: node_id.to_string(),
            csr_pem: csr_pem.clone(),
            attestation_certificate_chain_pem: chain,
        });

        let resp = service.enroll_worker(req).await.expect("RPC call");
        let body = resp.into_inner();
        assert!(
            body.success,
            "Hardware attestation must succeed: {}",
            body.error_message
        );
        assert!(!body.client_cert_pem.is_empty());
        assert!(!body.ca_cert_pem.is_empty());
    }

    #[tokio::test]
    async fn test_grpc_enrollment_with_required_challenge_success_and_mismatch() {
        use crate::pairing::attestation::{
            build_test_key_description_der, AttestationSecurityLevel,
        };
        use rcgen::CustomExtension;

        let (base_ctx, _ca_key, _ca_pem) = create_test_context();

        // 1. Root CA setup
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root");
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_spki = root_key.public_key_der();

        let verifier = Arc::new(HardwareAttestationVerifier::with_custom_roots(&[root_spki]));
        let enforced_ctx = EnrollmentContext::with_hardware_attestation(
            Arc::clone(&base_ctx.token_store),
            Arc::clone(&base_ctx.signer),
            true,
            true, // require_attestation_challenge = true
            Some(verifier),
        );
        let service = EnrollmentServiceImpl::with_context(enforced_ctx);

        let node_id = "worker-challenge-test";
        let record = base_ctx
            .token_store
            .generate_token(Some(node_id.to_string()), Some(300))
            .expect("Token generation");

        let (csr_pem, worker_key) = generate_test_csr(node_id);

        // Case A: Matching challenge SHA-256("{token}:{node_id}")
        let matching_digest = ring::digest::digest(
            &ring::digest::SHA256,
            format!("{}:{node_id}", record.token).as_bytes(),
        );
        let valid_ext_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::TrustedEnvironment,
            4,
            AttestationSecurityLevel::TrustedEnvironment,
            matching_digest.as_ref(),
        );
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, node_id);
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                valid_ext_der,
            ));
        let leaf_cert = leaf_params
            .signed_by(&worker_key, &root_cert, &root_key)
            .unwrap();

        let req = tonic::Request::new(EnrollWorkerRequest {
            pairing_token: record.token.clone(),
            node_id: node_id.to_string(),
            csr_pem: csr_pem.clone(),
            attestation_certificate_chain_pem: vec![leaf_cert.pem(), root_cert.pem()],
        });

        let resp = service.enroll_worker(req).await.expect("RPC call");
        let body = resp.into_inner();
        assert!(
            body.success,
            "Matching challenge must succeed: {}",
            body.error_message
        );
        assert!(!body.client_cert_pem.is_empty());

        // Case B: Mismatched challenge
        let record_mismatch = base_ctx
            .token_store
            .generate_token(Some(node_id.to_string()), Some(300))
            .expect("Token generation");
        let wrong_ext_der = build_test_key_description_der(
            3,
            AttestationSecurityLevel::TrustedEnvironment,
            4,
            AttestationSecurityLevel::TrustedEnvironment,
            b"wrong-challenge-nonce",
        );
        let mut wrong_leaf_params = CertificateParams::default();
        wrong_leaf_params
            .distinguished_name
            .push(DnType::CommonName, node_id);
        wrong_leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                wrong_ext_der,
            ));
        let wrong_leaf_cert = wrong_leaf_params
            .signed_by(&worker_key, &root_cert, &root_key)
            .unwrap();

        let req_mismatch = tonic::Request::new(EnrollWorkerRequest {
            pairing_token: record_mismatch.token.clone(),
            node_id: node_id.to_string(),
            csr_pem: csr_pem.clone(),
            attestation_certificate_chain_pem: vec![wrong_leaf_cert.pem(), root_cert.pem()],
        });

        let resp_mismatch = service.enroll_worker(req_mismatch).await.expect("RPC call");
        let body_mismatch = resp_mismatch.into_inner();
        assert!(!body_mismatch.success, "Mismatched challenge must fail");
        assert!(
            body_mismatch.error_message.contains("challenge mismatch"),
            "Error must specify challenge mismatch, got: {}",
            body_mismatch.error_message
        );
    }
}
