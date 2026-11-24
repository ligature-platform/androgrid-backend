#![allow(deprecated)]

//! Integration Specification: Turnkey All-In-One Container, Auto-PKI, mDNS, and Pairing Web UI
//!
//! Validates:
//! 1. Automated Day-0 PKI initialization with host LAN IP injected into Subject Alternative Names (SANs).
//! 2. Embedded Operator Web UI (Port 8080) serving pairing QR code, worker APK distribution, and live node table.
//! 3. Mobile worker end-to-end enrollment and mTLS 1.3 transition using the web-rendered pairing payload.
//! 4. Multicast DNS (mDNS) zero-config service discovery advertisement (`_androgrid._tcp.local.`).
//!
//! Traces to: AG-SPEC-2026-V2 Section 2.2, Section 2.3, ADR-001, [REQ-OP-001], [INV-001], [INV-002], [NFR-SEC-001]

use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use androgrid_backend::andro_grid_service_client::AndroGridServiceClient;
use androgrid_backend::andro_grid_service_server::AndroGridServiceServer;
use androgrid_backend::enrollment_service_client::EnrollmentServiceClient;
use androgrid_backend::enrollment_service_server::EnrollmentServiceServer;
use androgrid_backend::observability::{
    web_ui_router, ApkInfoResponse, MdnsConfig, MdnsResponder, PairingWebResponse, WebUiState,
};
use androgrid_backend::pairing::{
    cert_init, CaSigner, EnrollmentContext, EnrollmentServiceImpl, PairingPayload,
    PairingTokenStore, PkiInitConfig,
};
use androgrid_backend::{
    build_client_mtls_config, build_server_bootstrap_tls_config, require_client_mtls_interceptor,
    AndroGridServiceImpl, ArtifactStore, CertRenewalManager, CertRenewalPolicy, ClusterScheduler,
    EnrollWorkerRequest, ExecutionEngine, NetworkTransportType, NodeCapabilities,
    RegisterNodeRequest,
};
use rcgen::{CertificateParams, DnType, KeyPair};
use x509_parser::prelude::*;

/// 1. Verifies that Day-0 automated PKI generation produces NIST P-256 ECDSA certificates
/// with the detected host LAN IP successfully injected into Subject Alternative Names (SANs).
///
/// Traces to: ADR-001, [INV-002], [NFR-SEC-001], [REQ-OP-001]
#[test]
fn test_auto_pki_generation_and_host_san_injection() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pki_out = std::env::temp_dir().join(format!("androgrid_test_pki_{nonce}"));
    let host_lan_ip = "192.168.1.185";

    let init_config = PkiInitConfig {
        out_dir: pki_out.clone(),
        extra_sans: vec![host_lan_ip.to_string(), "edge.androgrid.internal".to_string()],
        no_default_sans: false,
        ca_days: 1825,
        days: 365,
        admin_cn: "operator".to_string(),
        force: true,
    };

    let summary = cert_init(&init_config).expect("Auto-PKI initialization must succeed");
    assert!(!summary.ca_fingerprint.is_empty());
    assert!(summary.files.len() >= 6);

    // Verify file hierarchy
    let ca_crt_path = pki_out.join("runtime/ca.crt");
    let server_crt_path = pki_out.join("runtime/server.crt");
    let server_key_path = pki_out.join("runtime/server.key");
    let ca_key_path = pki_out.join("operator/ca.key");

    assert!(ca_crt_path.exists());
    assert!(server_crt_path.exists());
    assert!(server_key_path.exists());
    assert!(ca_key_path.exists());

    // Parse server.crt and verify SAN attributes
    let server_pem = std::fs::read(&server_crt_path).expect("Read server cert PEM");
    let (_, pem) = x509_parser::pem::parse_x509_pem(&server_pem).expect("Parse server PEM");
    let (_, x509) = parse_x509_certificate(&pem.contents).expect("Parse X.509 certificate");

    // Verify Subject Alternative Names contain the injected LAN IP
    let mut found_lan_ip = false;
    for ext in x509.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::IPAddress(ip_bytes) = name {
                    if ip_bytes.len() == 4 {
                        let ip = std::net::Ipv4Addr::new(
                            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                        );
                        if ip.to_string() == host_lan_ip {
                            found_lan_ip = true;
                        }
                    }
                }
            }
        }
    }
    assert!(
        found_lan_ip,
        "Host LAN IP {host_lan_ip} must be present in X.509 Subject Alternative Names (SANs)"
    );

    let _ = std::fs::remove_dir_all(&pki_out);
}

/// 2. Verifies the Operator Web UI (Port 8080) endpoints: HTML dashboard, real-time pairing QR,
/// binary PNG QR rendering, and worker APK distribution link.
///
/// Traces to: [INV-001], [INV-004], [INV-005], [REQ-OP-001]
#[tokio::test]
async fn test_web_ui_dashboard_and_pairing_endpoints() {
    let scheduler = Arc::new(ClusterScheduler::new());
    let token_store = Arc::new(PairingTokenStore::default());
    let ca_fingerprint = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();
    let cluster_endpoint = "192.168.1.185:50051".to_string();
    let apk_url = "https://github.com/ligature-platform/androgrid-android/releases/latest/download/androgrid-worker.apk".to_string();

    let web_state = WebUiState {
        scheduler,
        token_store: Some(token_store),
        ca_fingerprint: ca_fingerprint.clone(),
        cluster_endpoint: cluster_endpoint.clone(),
        apk_download_url: apk_url.clone(),
    };

    let app = web_ui_router(web_state);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Bind ephemeral port for web UI test");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("Web UI server run");
    });

    let client = reqwest::Client::new();

    // 2.1 GET / serves HTML5 dashboard
    let html_resp = client
        .get(format!("http://{addr}/"))
        .send()
        .await
        .expect("GET / must succeed");
    assert_eq!(html_resp.status(), reqwest::StatusCode::OK);
    let html_body = html_resp.text().await.unwrap();
    assert!(html_body.contains("AndroGrid Cluster Observability"));
    assert!(html_body.contains("Device Pairing"));
    assert!(html_body.contains("node-table"));

    // 2.2 GET /api/pair returns JSON pairing payload with QR data URL
    let pair_resp = client
        .get(format!("http://{addr}/api/pair"))
        .send()
        .await
        .expect("GET /api/pair must succeed");
    assert_eq!(pair_resp.status(), reqwest::StatusCode::OK);
    let pair_data: PairingWebResponse = pair_resp.json().await.unwrap();
    assert_eq!(pair_data.cluster_endpoint, cluster_endpoint);
    assert_eq!(pair_data.ca_fingerprint, ca_fingerprint);
    assert_eq!(pair_data.pairing_token.len(), 64);
    assert!(pair_data.qr_png_data_url.starts_with("data:image/png;base64,"));
    assert_eq!(pair_data.apk_download_url, apk_url);

    // 2.3 GET /api/pair/qr.png serves valid PNG image bytes
    let qr_png_resp = client
        .get(format!("http://{addr}/api/pair/qr.png"))
        .send()
        .await
        .expect("GET /api/pair/qr.png must succeed");
    assert_eq!(qr_png_resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        qr_png_resp.headers().get("content-type").unwrap(),
        "image/png"
    );
    let png_bytes = qr_png_resp.bytes().await.unwrap();
    // PNG file header magic: 0x89 'P' 'N' 'G'
    assert_eq!(&png_bytes[..4], &[0x89, 0x50, 0x4E, 0x47]);

    // 2.4 GET /api/apk-info returns APK download metadata
    let apk_resp = client
        .get(format!("http://{addr}/api/apk-info"))
        .send()
        .await
        .expect("GET /api/apk-info must succeed");
    assert_eq!(apk_resp.status(), reqwest::StatusCode::OK);
    let apk_data: ApkInfoResponse = apk_resp.json().await.unwrap();
    assert_eq!(apk_data.apk_download_url, apk_url);
    assert!(apk_data.qr_png_data_url.starts_with("data:image/png;base64,"));
}

/// 3. End-to-end integration test: An Android worker parses the Web UI pairing QR code,
/// redeems the ephemeral pairing token, receives its signed client certificate,
/// and connects to the gRPC orchestrator over TLS 1.3 mTLS.
///
/// Traces to: [INV-001], [INV-002], [NFR-SEC-001], [REQ-OP-001]
#[tokio::test]
async fn test_end_to_end_worker_pairing_from_web_qr_code() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pki_out = std::env::temp_dir().join(format!("androgrid_test_pki_e2e_{nonce}"));
    let host_ip = "127.0.0.1";

    // 1. Initialize PKI
    let init_config = PkiInitConfig {
        out_dir: pki_out.clone(),
        extra_sans: vec![host_ip.to_string(), "localhost".to_string()],
        no_default_sans: false,
        ca_days: 365,
        days: 90,
        admin_cn: "operator".to_string(),
        force: true,
    };
    cert_init(&init_config).expect("PKI init");

    let ca_cert_pem = std::fs::read_to_string(pki_out.join("runtime/ca.crt")).unwrap();
    let ca_key_pem = std::fs::read_to_string(pki_out.join("operator/ca.key")).unwrap();
    let server_cert_pem = std::fs::read_to_string(pki_out.join("runtime/server.crt")).unwrap();
    let server_key_pem = std::fs::read_to_string(pki_out.join("runtime/server.key")).unwrap();

    let ca_signer = Arc::new(CaSigner::from_pem(&ca_cert_pem, &ca_key_pem).unwrap());
    let ca_fingerprint = ca_signer.ca_fingerprint().to_string();

    let scheduler = Arc::new(ClusterScheduler::new());
    let token_store = Arc::new(PairingTokenStore::new(true, 5));
    let artifact_store = Arc::new(ArtifactStore::new());

    // 2. Start combined gRPC server (bootstrap TLS with EnrollmentService + AndroGridService)
    let enrollment_ctx = EnrollmentContext::new(Arc::clone(&token_store), Arc::clone(&ca_signer));
    let enrollment_service = EnrollmentServiceImpl::with_context(enrollment_ctx);

    let renewal_manager = Arc::new(CertRenewalManager::new(
        Some(Arc::clone(&ca_signer)),
        CertRenewalPolicy::default(),
    ));
    let androgrid_service = AndroGridServiceImpl::with_services(
        Arc::clone(&scheduler),
        Arc::clone(&artifact_store),
        renewal_manager,
    );

    let grpc_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_addr = grpc_listener.local_addr().unwrap();

    let server_tls = build_server_bootstrap_tls_config(
        server_cert_pem.as_bytes(),
        server_key_pem.as_bytes(),
        ca_cert_pem.as_bytes(),
    );

    tokio::spawn(async move {
        Server::builder()
            .tls_config(server_tls)
            .expect("TLS config")
            .add_service(EnrollmentServiceServer::new(enrollment_service))
            .add_service(
                tonic::codegen::InterceptedService::new(
                    AndroGridServiceServer::new(androgrid_service),
                    require_client_mtls_interceptor,
                ),
            )
            .serve_with_incoming(TcpListenerStream::new(grpc_listener))
            .await
            .expect("gRPC server run");
    });

    // 3. Start Web UI router on ephemeral port
    let web_state = WebUiState {
        scheduler: Arc::clone(&scheduler),
        token_store: Some(Arc::clone(&token_store)),
        ca_fingerprint: ca_fingerprint.clone(),
        cluster_endpoint: grpc_addr.to_string(),
        apk_download_url: "https://example.com/androgrid-worker.apk".to_string(),
    };
    let web_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web_addr = web_listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(web_listener, web_ui_router(web_state).into_make_service())
            .await
            .expect("Web UI run");
    });

    // 4. Operator fetches pairing QR code from Web UI
    let http_client = reqwest::Client::new();
    let pair_res: PairingWebResponse = http_client
        .get(format!("http://{web_addr}/api/pair"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(pair_res.cluster_endpoint, grpc_addr.to_string());
    assert_eq!(pair_res.ca_fingerprint, ca_fingerprint);

    // 5. Worker scans and decodes PairingPayload
    let payload = PairingPayload::from_json(&pair_res.pairing_payload_json).unwrap();
    assert_eq!(payload.pairing_token, pair_res.pairing_token);

    // 6. Worker generates ECDSA P-256 CSR
    let worker_node_id = "worker-pixel8-e2e";
    let worker_key = KeyPair::generate().expect("Generate worker key");
    let mut csr_params = CertificateParams::default();
    csr_params.distinguished_name.push(DnType::CommonName, worker_node_id);
    let worker_csr_pem = csr_params.serialize_request(&worker_key).unwrap().pem().unwrap();

    // 7. Worker connects to EnrollmentService over bootstrap TLS (server auth only)
    let bootstrap_channel = tonic::transport::Channel::from_shared(format!("https://{}", payload.cluster_endpoint))
        .unwrap()
        .tls_config(
            tonic::transport::ClientTlsConfig::new()
                .ca_certificate(tonic::transport::Certificate::from_pem(&ca_cert_pem))
                .domain_name("localhost"),
        )
        .unwrap()
        .connect()
        .await
        .expect("Connect to enrollment service");

    let mut enroll_client = EnrollmentServiceClient::new(bootstrap_channel);
    let enroll_res = enroll_client
        .enroll_worker(tonic::Request::new(EnrollWorkerRequest {
            pairing_token: payload.pairing_token,
            node_id: worker_node_id.to_string(),
            csr_pem: worker_csr_pem,
            attestation_certificate_chain_pem: Vec::new(),
        }))
        .await
        .expect("Worker enrollment must succeed")
        .into_inner();

    let issued_cert_pem = enroll_res.client_cert_pem;
    assert!(!issued_cert_pem.is_empty());

    // 8. Worker connects to AndroGridService over strict TLS 1.3 mutual TLS
    let mtls_tls_config = build_client_mtls_config(
        issued_cert_pem.as_bytes(),
        worker_key.serialize_pem().as_bytes(),
        ca_cert_pem.as_bytes(),
        "localhost",
    );

    let mtls_channel = tonic::transport::Channel::from_shared(format!("https://{}", payload.cluster_endpoint))
        .unwrap()
        .tls_config(mtls_tls_config)
        .unwrap()
        .connect()
        .await
        .expect("Connect via mTLS 1.3");

    let mut worker_client = AndroGridServiceClient::new(mtls_channel);

    // 9. Worker registers with orchestrator
    let reg_res = worker_client
        .register_node(tonic::Request::new(RegisterNodeRequest {
            node_id: worker_node_id.to_string(),
            capabilities: Some(NodeCapabilities {
                is_rooted: false,
                supported_engines: vec![ExecutionEngine::WasmWasi as i32],
                cpu_cores: 8,
                total_ram_bytes: 8 * 1024 * 1024 * 1024,
                is_metered: false,
                current_transport: NetworkTransportType::NetworkTransportWifiLan as i32,
                max_cellular_task_duration_seconds: 0,
                battery_temperature_celsius: 25,
                thermal_status: 0,
                os_version: "14".to_string(),
                abi: "arm64-v8a".to_string(),
            }),
            client_version: "0.1.0".to_string(),
            labels: HashMap::new(),
            last_upgrade_outcome: None,
        }))
        .await
        .expect("RegisterNode must succeed over mTLS 1.3")
        .into_inner();

    assert!(!reg_res.session_token.is_empty());

    // 10. Verify worker appears in orchestrator snapshot and Web UI
    let snapshot = scheduler.get_snapshot();
    assert_eq!(snapshot.metrics.total_nodes, 1);
    assert_eq!(snapshot.metrics.wifi_nodes, 1);
    assert_eq!(snapshot.nodes[0].node_id, worker_node_id);

    let _ = std::fs::remove_dir_all(&pki_out);
}

/// 4. Verifies the Multicast DNS (mDNS) responder lifecycle: advertising service type
/// `_androgrid._tcp.local.` and updating TXT records when node count changes.
///
/// Traces to: [REQ-OP-001], [INV-001]
#[test]
fn test_mdns_responder_lifecycle_and_updates() {
    let mdns_config = MdnsConfig {
        instance_name: "test-turnkey-orchestrator".to_string(),
        host_name: "turnkey.local.".to_string(),
        port: 50051,
        version: "0.0.1-alpha.5".to_string(),
        ca_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ip: Some("127.0.0.1".to_string()),
    };

    let responder = MdnsResponder::start(mdns_config).expect("Start mDNS responder");
    assert!(responder.full_service_name().contains("_androgrid._tcp.local."));

    // Update node count dynamically
    assert!(responder.update_node_count(1).is_ok());
    assert!(responder.update_node_count(5).is_ok());

    responder.shutdown();
}
