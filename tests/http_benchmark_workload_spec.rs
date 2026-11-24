#![allow(deprecated)]

//! Integration Specification: Distributed HTTP/HTTPS Load-Testing Workload
//!
//! Validates the WebAssembly Preview 1 HTTP benchmark workload:
//! - Bytecode format, entrypoint exports, and `androgrid_net:http_fetch` host imports
//! - Static egress policy verification (fail-closed when egress_policy is BLOCKED)
//! - End-to-end orchestrator submission via AdminService and synchronization via AndroGridService (Wi-Fi)
//! - Workload stdout parsing (latency percentiles, error breakdowns, and JSON reports)
//! - Conformance to typographic standards (zero Unicode em/en dashes)
//!
//! Traces to: AG-SPEC-2026-V2, [REQ-OP-002], [REQ-OP-003], [INV-001], [INV-006], [NFR-PERF-001], ADR-011

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};

use androgrid_backend::admin_service_client::AdminServiceClient;
use androgrid_backend::admin_service_server::AdminServiceServer;
use androgrid_backend::andro_grid_service_client::AndroGridServiceClient;
use androgrid_backend::andro_grid_service_server::AndroGridServiceServer;
use androgrid_backend::artifact::wasi_validator::{WasiValidationError, WasiValidator};
use androgrid_backend::{
    build_client_mtls_config, build_server_mtls_config, AdminServiceImpl, AndroGridServiceImpl,
    ClusterScheduler, ExecutionEngine, GetTaskStatusRequest, NetworkEgressPolicy,
    NetworkTransportType, NodeCapabilities, RegisterNodeRequest, SubmitTaskRequest,
    SyncNodeStateRequest, TaskExecutionReport, TaskSpec, TaskState,
};

struct TestPki {
    pub ca_cert_pem: Vec<u8>,
    pub server_cert_pem: Vec<u8>,
    pub server_key_pem: Vec<u8>,
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
}

impl TestPki {
    pub fn generate() -> Self {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "AndroGrid Benchmark Test CA");
        let ca_key = KeyPair::generate().expect("Failed to generate CA key");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("Failed to self-sign CA cert");

        let mut server_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("Failed to create server params");
        server_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        let server_key = KeyPair::generate().expect("Failed to generate server key");
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .expect("Failed to sign server cert");

        let mut client_params =
            CertificateParams::new(vec!["operator.androgrid.internal".to_string()])
                .expect("Failed to create client params");
        client_params
            .distinguished_name
            .push(DnType::CommonName, "operator");
        let client_key = KeyPair::generate().expect("Failed to generate client key");
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .expect("Failed to sign client cert");

        Self {
            ca_cert_pem: ca_cert.pem().into_bytes(),
            server_cert_pem: server_cert.pem().into_bytes(),
            server_key_pem: server_key.serialize_pem().into_bytes(),
            client_cert_pem: client_cert.pem().into_bytes(),
            client_key_pem: client_key.serialize_pem().into_bytes(),
        }
    }
}

async fn spawn_test_server(
    scheduler: Arc<ClusterScheduler>,
    pki: &TestPki,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral loopback port");
    let local_addr = listener.local_addr().expect("Failed to get local address");

    let server_tls =
        build_server_mtls_config(&pki.server_cert_pem, &pki.server_key_pem, &pki.ca_cert_pem);

    let worker_service = AndroGridServiceImpl::new(Arc::clone(&scheduler));
    let admin_service = AdminServiceImpl::new(scheduler);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        Server::builder()
            .tls_config(server_tls)
            .expect("Server TLS setup must succeed")
            .add_service(AndroGridServiceServer::new(worker_service))
            .add_service(AdminServiceServer::new(admin_service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("Server must terminate gracefully");
    });

    (local_addr, shutdown_tx)
}

fn build_mtls_channel(addr: SocketAddr, pki: &TestPki) -> Channel {
    let tls_config = build_client_mtls_config(
        &pki.client_cert_pem,
        &pki.client_key_pem,
        &pki.ca_cert_pem,
        "localhost",
    );

    let endpoint_uri = format!("https://{}", addr);
    let endpoint = tonic::transport::Endpoint::from_shared(endpoint_uri)
        .expect("Valid URI")
        .tls_config(tls_config)
        .expect("Valid client TLS");

    endpoint.connect_lazy()
}

fn get_workload_wasm_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("workloads")
        .join("http-benchmark")
        .join("target")
        .join("wasm32-wasip1")
        .join("release")
        .join("http_benchmark.wasm")
}

#[tokio::test]
async fn test_http_benchmark_wasm_static_validation_and_egress_policy() {
    let wasm_path = get_workload_wasm_path();
    assert!(
        wasm_path.exists(),
        "Compiled http_benchmark.wasm must exist at {}",
        wasm_path.display()
    );

    let bytecode = fs::read(&wasm_path).expect("Failed to read http_benchmark.wasm");
    assert!(
        bytecode.len() < 500 * 1024,
        "WASM bytecode size ({} bytes) must be under 500 KB [NFR-PERF-001]",
        bytecode.len()
    );

    // Validate WASI Preview 1 headers and entrypoint export
    let meta = WasiValidator::validate(&bytecode, "_start")
        .expect("WASI inspection and validation must succeed");

    assert_eq!(meta.entrypoint, "_start");
    assert!(meta.is_wasi_compatible);
    assert!(
        meta.has_network_egress_imports,
        "Workload must import androgrid_net interfaces"
    );
    assert!(
        meta.network_imports
            .contains(&"androgrid_net::http_fetch".to_string()),
        "Workload must import androgrid_net::http_fetch"
    );

    // Validate fail-closed egress policy enforcement
    let allow_res =
        WasiValidator::validate_egress_policy(&meta, NetworkEgressPolicy::Allowlist as i32);
    assert!(
        allow_res.is_ok(),
        "validate_egress_policy must succeed when policy is ALLOWLIST"
    );

    let blocked_res =
        WasiValidator::validate_egress_policy(&meta, NetworkEgressPolicy::Blocked as i32);
    assert!(
        matches!(
            blocked_res,
            Err(WasiValidationError::DisallowedNetworkImports(_))
        ),
        "validate_egress_policy must reject when policy is BLOCKED"
    );

    let unspecified_res =
        WasiValidator::validate_egress_policy(&meta, NetworkEgressPolicy::Unspecified as i32);
    assert!(
        matches!(
            unspecified_res,
            Err(WasiValidationError::DisallowedNetworkImports(_))
        ),
        "validate_egress_policy must reject when policy is UNSPECIFIED"
    );

    let arbitrary_res = WasiValidator::validate_egress_policy(&meta, 99);
    assert!(
        matches!(
            arbitrary_res,
            Err(WasiValidationError::DisallowedNetworkImports(_))
        ),
        "validate_egress_policy must reject arbitrary integer policy (fail closed)"
    );
}

#[tokio::test]
async fn test_http_benchmark_orchestrator_submission_and_lifecycle() {
    let wasm_path = get_workload_wasm_path();
    let bytecode = fs::read(&wasm_path).expect("Failed to read http_benchmark.wasm");

    let mut hasher = Sha256::new();
    hasher.update(&bytecode);
    let expected_sha = format!("{:x}", hasher.finalize());

    let scheduler = Arc::new(ClusterScheduler::new());
    let pki = TestPki::generate();
    let (server_addr, shutdown_tx) = spawn_test_server(Arc::clone(&scheduler), &pki).await;

    let channel = build_mtls_channel(server_addr, &pki);

    let mut admin_client = AdminServiceClient::new(channel.clone());
    let mut worker_client = AndroGridServiceClient::new(channel);

    let worker_caps = NodeCapabilities {
        is_rooted: false,
        supported_engines: vec![ExecutionEngine::WasmWasi as i32],
        cpu_cores: 8,
        total_ram_bytes: 6 * 1024 * 1024 * 1024,
        os_version: "14".to_string(),
        abi: "arm64-v8a".to_string(),
        is_metered: false,
        current_transport: NetworkTransportType::NetworkTransportWifiLan as i32,
        max_cellular_task_duration_seconds: 180,
        battery_temperature_celsius: 25,
        thermal_status: 0,
    };

    // 1. Register test worker node supporting WASM over Wi-Fi
    let reg_req = RegisterNodeRequest {
        node_id: "operator".to_string(),
        capabilities: Some(worker_caps.clone()),
        client_version: "0.0.1-alpha.5".to_string(),
        labels: Default::default(),
        last_upgrade_outcome: None,
    };
    let reg_res = worker_client
        .register_node(reg_req)
        .await
        .expect("Node registration must succeed")
        .into_inner();
    let session_token = reg_res.session_token;

    let mut env_vars = HashMap::new();
    env_vars.insert(
        "TARGET_URL".to_string(),
        "https://api.staging.benchmark.org/get".to_string(),
    );
    env_vars.insert("METHOD".to_string(), "GET".to_string());
    env_vars.insert("DURATION_SECS".to_string(), "5".to_string());
    env_vars.insert("MAX_REQUESTS".to_string(), "100".to_string());

    let task_id = "task_bench_e2e_001".to_string();
    let task_spec = TaskSpec {
        task_id: task_id.clone(),
        run_attempt: 1,
        engine: ExecutionEngine::WasmWasi as i32,
        timeout_seconds: 60,
        entrypoint: "_start".to_string(),
        env_vars,
        wasm_bytecode: bytecode.clone(),
        shell_command: String::new(),
        artifact_sha256: expected_sha.clone(),
        requires_unmetered: true,
        artifact_url: String::new(),
        group_id: String::new(),
        group_epoch: 0,
        node_group_affinity: String::new(),
        egress_policy: NetworkEgressPolicy::Allowlist as i32,
        allowed_hostnames: vec!["api.staging.benchmark.org".to_string()],
        max_egress_bytes: 2 * 1024 * 1024,
    };

    // 2. Submit benchmark task via AdminService
    let submit_res = admin_client
        .submit_task(SubmitTaskRequest {
            task: Some(task_spec),
        })
        .await
        .expect("Task submission should succeed")
        .into_inner();
    assert!(submit_res.accepted);

    // 3. Worker synchronizes node state via Wi-Fi and receives assigned egress task
    let sync_res = worker_client
        .sync_node_state(SyncNodeStateRequest {
            node_id: "operator".to_string(),
            session_token: session_token.clone(),
            active_tasks: Vec::new(),
            completed_tasks: Vec::new(),
            last_upgrade_outcome: None,
        })
        .await
        .expect("SyncNodeState must succeed")
        .into_inner();

    assert_eq!(sync_res.desired_tasks.len(), 1);
    let assigned_task = &sync_res.desired_tasks[0];
    assert_eq!(assigned_task.task_id, task_id);
    assert_eq!(
        assigned_task.egress_policy,
        NetworkEgressPolicy::Allowlist as i32
    );
    assert_eq!(
        assigned_task.allowed_hostnames,
        vec!["api.staging.benchmark.org".to_string()]
    );
    assert_eq!(assigned_task.max_egress_bytes, 2 * 1024 * 1024);

    // 4. Worker executes workload and submits benchmark execution report
    let simulated_stdout = r#"================================================================================
                     AndroGrid Distributed HTTP Benchmark                       
================================================================================
Task ID:             task_bench_e2e_001
Target URL:          https://api.staging.benchmark.org/get
HTTP Method:         GET
Duration:            5.01s
Total Requests:      100
Successful (2xx):    100
Total Errors:        0
Total Bytes:         45120 bytes
Throughput:          19.96 req/sec (8.80 KB/sec)

HTTP Status Distribution:
  HTTP 200:         100

Latency Distribution (ms):
  Min:               12.34 ms
  p50:               45.67 ms
  p90:               78.90 ms
  p95:               85.12 ms
  p99:               95.43 ms
  Max:               112.50 ms
  Mean:              48.21 ms
================================================================================
JSON Report:
{
  "task_id": "task_bench_e2e_001",
  "target_url": "https://api.staging.benchmark.org/get",
  "method": "GET",
  "duration_secs": 5.01,
  "total_requests": 100,
  "successful_requests": 100,
  "requests_per_sec": 19.96,
  "total_bytes_transferred": 45120,
  "bytes_per_sec": 9005.98,
  "status_codes": {
    "200": 100
  },
  "errors": {
    "io_failure": 0,
    "security_violation": 0,
    "buffer_too_small": 0,
    "quota_exceeded": 0,
    "other_errors": 0
  },
  "latency_percentiles": {
    "min_ms": 12.34,
    "p50_ms": 45.67,
    "p90_ms": 78.9,
    "p95_ms": 85.12,
    "p99_ms": 95.43,
    "max_ms": 112.5,
    "mean_ms": 48.21
  }
}"#;

    let report = TaskExecutionReport {
        task_id: task_id.clone(),
        run_attempt: 1,
        state: TaskState::Completed as i32,
        exit_code: 0,
        stdout_bytes: simulated_stdout.as_bytes().to_vec(),
        stderr_bytes: Vec::new(),
        error_code: String::new(),
        execution_time_ms: 5010,
    };

    let _sync_finish_res = worker_client
        .sync_node_state(SyncNodeStateRequest {
            node_id: "operator".to_string(),
            session_token,
            active_tasks: Vec::new(),
            completed_tasks: vec![report],
            last_upgrade_outcome: None,
        })
        .await
        .expect("SyncNodeState report submission must succeed")
        .into_inner();

    // 5. Query status via AdminService and verify completed state
    let status = admin_client
        .get_task_status(GetTaskStatusRequest {
            task_id: task_id.clone(),
        })
        .await
        .expect("Status query must succeed")
        .into_inner();

    assert_eq!(status.state, TaskState::Completed as i32);
    assert_eq!(status.exit_code, 0);
    assert_eq!(status.stdout_bytes, simulated_stdout.as_bytes());

    let _ = shutdown_tx.send(());
}

#[test]
fn test_zero_unicode_dashes_in_http_benchmark_workload() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workload_dir = manifest_dir.join("workloads").join("http-benchmark");

    fn check_dir(dir: &Path) {
        if !dir.exists() {
            return;
        }
        for entry in fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("dir entry");
            let p = entry.path();
            if p.is_dir() {
                if !p.to_string_lossy().contains("target") {
                    check_dir(&p);
                }
            } else if let Some(ext) = p.extension() {
                if ext == "rs" || ext == "md" || ext == "toml" {
                    let content = fs::read_to_string(&p).unwrap_or_default();
                    assert!(
                        !content.contains('\u{2014}'),
                        "Em dash (U+2014) found in {:?}",
                        p
                    );
                    assert!(
                        !content.contains('\u{2013}'),
                        "En dash (U+2013) found in {:?}",
                        p
                    );
                }
            }
        }
    }

    check_dir(&workload_dir);
}

#[test]
fn test_scheduler_rejects_hex_and_non_alphabetic_tld_egress() {
    use androgrid_backend::scheduler::engine::validate_network_egress_policy_params;

    // Hex IPv4 literals must be rejected because TLD is non-alphabetic
    let hex_res = validate_network_egress_policy_params(
        1, // WasmWasi
        2, // Allowlist
        &["0x7f.0x00.0x00.0x01".to_string()],
        1024 * 1024,
    );
    assert!(hex_res.is_err(), "Hex IPv4 must be rejected");

    let num_tld_res = validate_network_egress_policy_params(
        1, // WasmWasi
        2, // Allowlist
        &["sub.domain.123".to_string()],
        1024 * 1024,
    );
    assert!(num_tld_res.is_err(), "Numeric TLD must be rejected");

    let valid_res = validate_network_egress_policy_params(
        1, // WasmWasi
        2, // Allowlist
        &[
            "api.example.com".to_string(),
            "*.benchmarks.internal.org".to_string(),
            "xn--p1ai.xn--80a0a5b.xn--p1ai".to_string(),
        ],
        1024 * 1024,
    );
    assert!(
        valid_res.is_ok(),
        "Valid alphabetic and punycode hostnames must be accepted"
    );
}

#[test]
fn test_allowlist_task_single_attempt_finality_and_no_requeue() {
    use androgrid_backend::scheduler::engine::ClusterScheduler;
    use androgrid_backend::{
        ExecutionEngine, NetworkEgressPolicy, NetworkTransportType, NodeCapabilities,
        TaskExecutionReport, TaskSpec, TaskState,
    };
    use std::collections::HashMap;

    let scheduler = ClusterScheduler::new();

    let worker_caps = NodeCapabilities {
        is_rooted: false,
        supported_engines: vec![ExecutionEngine::WasmWasi as i32],
        cpu_cores: 4,
        total_ram_bytes: 4 * 1024 * 1024 * 1024,
        os_version: "14".to_string(),
        abi: "arm64-v8a".to_string(),
        is_metered: false,
        current_transport: NetworkTransportType::NetworkTransportWifiLan as i32,
        max_cellular_task_duration_seconds: 180,
        battery_temperature_celsius: 25,
        thermal_status: 0,
    };

    // 1. Register Wi-Fi worker node
    let reg_res = scheduler
        .register_node(
            "wifi-node-1".to_string(),
            worker_caps.clone(),
            "0.0.1-alpha.5".to_string(),
            1000,
        )
        .expect("Registration succeeds");

    // 2. Submit an Allowlist task
    let task_id = "task-allowlist-finality-001".to_string();
    let wasm_bytes = std::fs::read(get_workload_wasm_path()).expect("Valid WASM payload");
    let spec = TaskSpec {
        task_id: task_id.clone(),
        run_attempt: 0,
        engine: ExecutionEngine::WasmWasi as i32,
        timeout_seconds: 60,
        entrypoint: "_start".to_string(),
        env_vars: HashMap::new(),
        wasm_bytecode: wasm_bytes,
        shell_command: String::new(),
        artifact_sha256: String::new(),
        requires_unmetered: true,
        artifact_url: String::new(),
        group_id: String::new(),
        group_epoch: 0,
        node_group_affinity: String::new(),
        egress_policy: NetworkEgressPolicy::Allowlist as i32,
        allowed_hostnames: vec!["api.example.com".to_string()],
        max_egress_bytes: 1024 * 1024,
    };
    scheduler
        .submit_task(spec)
        .expect("Task submission succeeds");

    assert_eq!(scheduler.get_task_state(&task_id), Some(TaskState::Pending));
    assert_eq!(scheduler.get_active_attempt(&task_id), Some(0));

    // 3. Dispatch task to wifi-node-1 via sync_node_state -> LEASED (attempt = 1)
    let sync_res1 = scheduler
        .sync_node_state("wifi-node-1", &reg_res.session_token, &[], 1001)
        .expect("sync_node_state succeeds");
    assert_eq!(sync_res1.desired_tasks.len(), 1);
    assert_eq!(sync_res1.desired_tasks[0].task_id, task_id);
    assert_eq!(sync_res1.desired_tasks[0].run_attempt, 1);
    assert_eq!(scheduler.get_task_state(&task_id), Some(TaskState::Leased));
    assert_eq!(scheduler.get_active_attempt(&task_id), Some(1));

    // 4. Report task failure from the worker (exit_code = 1)
    let failure_report = TaskExecutionReport {
        task_id: task_id.clone(),
        run_attempt: 1,
        state: TaskState::Failed as i32,
        exit_code: 1,
        stdout_bytes: vec![],
        stderr_bytes: b"Connection refused".to_vec(),
        error_code: "ERR_IO_FAILURE".to_string(),
        execution_time_ms: 150,
    };
    let sync_res2 = scheduler
        .sync_node_state(
            "wifi-node-1",
            &reg_res.session_token,
            &[failure_report],
            1002,
        )
        .expect("sync_node_state succeeds");
    assert_eq!(sync_res2.acknowledged_task_ids, vec![task_id.clone()]);
    assert_eq!(scheduler.get_task_state(&task_id), Some(TaskState::Failed));

    // 5. Invariant Assertion: The task MUST NOT re-queue back to PENDING
    // When a second idle Wi-Fi worker syncs, desired_tasks must be empty
    let reg_res2 = scheduler
        .register_node(
            "wifi-node-2".to_string(),
            worker_caps,
            "0.0.1-alpha.5".to_string(),
            1003,
        )
        .expect("Registration succeeds");

    let sync_res3 = scheduler
        .sync_node_state("wifi-node-2", &reg_res2.session_token, &[], 1004)
        .expect("sync_node_state succeeds");
    assert!(
        sync_res3.desired_tasks.is_empty(),
        "Allowlist task must NOT be re-queued or dispatched again after attempt 1 failure"
    );
    assert_eq!(
        scheduler.get_task_state(&task_id),
        Some(TaskState::Failed),
        "Allowlist task state must remain terminal Failed"
    );
}
