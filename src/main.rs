//! AndroGrid Control Plane Binary Entry Point
//!
//! Hosts the gRPC control plane service over mutual TLS 1.3 or local loopback,
//! backed by the atomic lock-free ClusterScheduler.
//!
//! Traces to: AG-SPEC-2026-V2 Section 2.2, Section 2.3, [INV-002], [NFR-SEC-001], [NFR-PERF-001]

use clap::Parser;
use std::sync::Arc;
use tokio::signal;
use tonic::transport::Server;
use tracing::{error, info, warn};

use androgrid_backend::admin_service_server::AdminServiceServer;
use androgrid_backend::andro_grid_service_server::AndroGridServiceServer;
use androgrid_backend::enrollment_service_server::EnrollmentServiceServer;
use androgrid_backend::transport::tls::{
    build_bootstrap_rustls_server_config, serve_dual_plane_tls,
};
use androgrid_backend::{
    require_client_mtls_interceptor, web_ui_router, AdminServiceImpl, AndroGridServiceImpl,
    ArtifactServer, ArtifactStore, CaSigner, CertRenewalManager, CertRenewalPolicy, ClusterConfig,
    ClusterScheduler, EnrollmentContext, EnrollmentServiceImpl, MdnsConfig, MdnsResponder,
    PairingTokenStore, RolloutStore, ThermalPolicy, WebUiState,
};

#[derive(Parser, Debug)]
#[command(
    name = "androgrid-backend",
    about = "AndroGrid Control Plane Orchestrator",
    version = env!("CARGO_PKG_VERSION")
)]
struct ServerArgs {
    /// Allow scheduling of insecure root shell tasks (diagnostic / laboratory mode)
    #[arg(long, env = "ANDROGRID_ALLOW_INSECURE_ROOT_TASKS")]
    allow_insecure_root_tasks: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ServerArgs::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Initializing AndroGrid Control Plane...");

    let mut config = match ClusterConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration error: {e}");
            std::process::exit(1);
        }
    };

    if args.allow_insecure_root_tasks {
        config.allow_insecure_root_tasks = true;
    }

    if config.allow_insecure_root_tasks {
        warn!("Insecure root shell execution explicitly ENABLED via --allow-insecure-root-tasks [DIAGNOSTIC MODE]");
    }

    info!(
        listen_addr = %config.listen_addr,
        heartbeat_secs = config.heartbeat_interval_seconds,
        lease_secs = config.lease_timeout_seconds,
        max_frame_mb = config.max_frame_size_bytes / (1024 * 1024),
        allow_insecure_root = config.allow_insecure_root_tasks,
        enforce_hardware_attestation = config.enforce_hardware_attestation,
        require_attestation_challenge = config.require_attestation_challenge,
        "Cluster configuration loaded"
    );

    if config.is_mtls_configured() && !config.enforce_hardware_attestation {
        warn!(
            "Hardware attestation enforcement is DISABLED while mTLS is configured [NFR-SEC-001]"
        );
    }

    let rollout_store = if let Some(ref dir) = config.rollout_storage_dir {
        Arc::new(RolloutStore::with_directory(dir))
    } else {
        Arc::new(RolloutStore::new())
    };

    let scheduler = Arc::new(ClusterScheduler::with_options_and_store(
        config.allow_insecure_root_tasks,
        ThermalPolicy::default(),
        rollout_store,
    ));
    if let Err(e) = scheduler.reconcile_rollouts_from_store() {
        warn!(error = %e, "Failed to reconcile active rollouts from durable store on startup");
    }

    // Periodic lease sweeper for timed-out task leases and worker upgrade leases
    let sweeper_scheduler = Arc::clone(&scheduler);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            interval.tick().await;
            let now_epoch_s = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            sweeper_scheduler.sweep_timed_out_leases(now_epoch_s);
        }
    });

    let artifact_store = if let Some(ref dir) = config.artifact_storage_dir {
        Arc::new(ArtifactStore::with_directory(dir))
    } else {
        Arc::new(ArtifactStore::new())
    };

    let artifact_base_url = config.resolve_artifact_base_url();

    let token_store = Arc::new(PairingTokenStore::new(config.allow_pairing, 5));

    let (ca_signer, ca_fingerprint) = if let (Some(ca_cert_path), Some(ca_key_path)) =
        (&config.tls_ca_cert_path, &config.tls_ca_key_path)
    {
        match (
            tokio::fs::read_to_string(ca_cert_path).await,
            tokio::fs::read_to_string(ca_key_path).await,
        ) {
            (Ok(ca_pem), Ok(ca_key)) => match CaSigner::from_pem(&ca_pem, &ca_key) {
                Ok(signer) => {
                    let fp = signer.ca_fingerprint().to_string();
                    info!(ca_fingerprint = %fp, "Initialized Root CA CSR signer for pairing enrollment [INV-002]");
                    (Some(Arc::new(signer)), fp)
                }
                Err(e) => {
                    if config.allow_pairing || config.allow_cert_renewal {
                        return Err(format!(
                            "Failed to initialize Root CA signer from {}: {e}. \
                             Ensure CA private key is PKCS#8 PEM (openssl genpkey) or disable pairing and cert renewal.",
                            ca_key_path.display()
                        )
                        .into());
                    }
                    warn!(error = %e, "Failed to initialize Root CA signer; enrollment and renewal disabled");
                    (None, String::new())
                }
            },
            (Err(e), _) | (_, Err(e)) => {
                if config.allow_pairing || config.allow_cert_renewal {
                    return Err(format!(
                        "Could not read Root CA cert ({}) or key ({}): {e}",
                        ca_cert_path.display(),
                        ca_key_path.display()
                    )
                    .into());
                }
                warn!(error = %e, "Could not read Root CA cert or key; enrollment and renewal disabled");
                (None, String::new())
            }
        }
    } else {
        (None, String::new())
    };

    let enrollment_ctx = ca_signer.as_ref().map(|signer| {
        EnrollmentContext::with_hardware_attestation(
            Arc::clone(&token_store),
            Arc::clone(signer),
            config.enforce_hardware_attestation,
            config.require_attestation_challenge,
            None,
        )
    });

    let mtls_enabled = config.is_mtls_configured();
    let mtls_guard = ConditionalMtlsInterceptor { mtls_enabled };
    let renewal_manager = Arc::new(CertRenewalManager::new(
        ca_signer.clone(),
        CertRenewalPolicy {
            allow_cert_renewal: config.allow_cert_renewal,
            renewal_window_days: config.cert_renewal_window_days,
            min_ca_extension_days: config.cert_renewal_min_ca_extension_days,
            issued_validity_days: config.cert_renewal_validity_days,
            ..CertRenewalPolicy::default()
        },
    ));
    let service = AndroGridServiceImpl::with_services(
        Arc::clone(&scheduler),
        Arc::clone(&artifact_store),
        Arc::clone(&renewal_manager),
    );
    let service_server = tonic::codegen::InterceptedService::new(
        AndroGridServiceServer::new(service)
            .max_decoding_message_size(config.max_frame_size_bytes)
            .max_encoding_message_size(config.max_frame_size_bytes),
        mtls_guard,
    );

    let cluster_endpoint = config.resolve_cluster_endpoint();
    let effective_artifact_base_url = if mtls_enabled {
        config.resolve_mtls_blob_base_url()
    } else {
        artifact_base_url
    };
    let admin_service = AdminServiceImpl::with_services(
        Arc::clone(&scheduler),
        Arc::clone(&artifact_store),
        effective_artifact_base_url,
        Arc::clone(&token_store),
        ca_fingerprint.clone(),
        cluster_endpoint.clone(),
    );
    let admin_server = tonic::codegen::InterceptedService::new(
        AdminServiceServer::new(admin_service)
            .max_decoding_message_size(config.max_frame_size_bytes)
            .max_encoding_message_size(config.max_frame_size_bytes),
        mtls_guard,
    );

    let (artifact_shutdown_tx, artifact_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let artifact_listener = tokio::net::TcpListener::bind(config.artifact_listen_addr).await?;
    info!(
        artifact_addr = %config.artifact_listen_addr,
        "Starting embedded HTTP static artifact distribution server [NFR-PERF-001], [REQ-OP-003]"
    );
    let http_enrollment_ctx = if mtls_enabled {
        info!("mTLS enabled: plaintext HTTP /api/v1/enroll disabled (use gRPC over TLS 1.3)");
        None
    } else {
        enrollment_ctx.clone()
    };
    ArtifactServer::spawn_full_with_options(
        artifact_listener,
        Arc::clone(&artifact_store),
        Arc::clone(&scheduler),
        http_enrollment_ctx,
        !mtls_enabled,
        artifact_shutdown_rx,
    );

    let (web_shutdown_tx, web_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    if config.enable_web_ui {
        let web_listener = tokio::net::TcpListener::bind(config.web_listen_addr).await?;
        let web_state = WebUiState {
            scheduler: Arc::clone(&scheduler),
            token_store: if config.allow_pairing {
                Some(Arc::clone(&token_store))
            } else {
                None
            },
            ca_fingerprint: ca_fingerprint.clone(),
            cluster_endpoint: cluster_endpoint.clone(),
            apk_download_url: config.apk_download_url.clone(),
        };
        let web_app = web_ui_router(web_state);
        info!(
            web_addr = %config.web_listen_addr,
            "Starting dedicated Operator Web UI & Pairing Dashboard on port 8080 [REQ-OP-001], [INV-004], [INV-005]"
        );
        tokio::spawn(async move {
            let server = axum::serve(web_listener, web_app.into_make_service());
            tokio::select! {
                res = server => {
                    if let Err(e) = res {
                        error!(error = %e, "Web UI server terminated with error");
                    }
                }
                _ = web_shutdown_rx => {
                    info!("Web UI server shutting down gracefully");
                }
            }
        });
    }

    // Initialize mDNS DNS-SD service responder
    let mdns_responder = if config.enable_mdns {
        let mdns_cfg = MdnsConfig {
            instance_name: config.mdns_service_name.clone(),
            host_name: "androgrid.local.".to_string(),
            port: config.listen_addr.port(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ca_fingerprint: ca_fingerprint.clone(),
            ip: if !config.listen_addr.ip().is_unspecified() {
                Some(config.listen_addr.ip().to_string())
            } else {
                std::env::var("ANDROGRID_HOST_IP").ok()
            },
        };
        match MdnsResponder::start(mdns_cfg) {
            Ok(resp) => {
                info!(
                    service = resp.full_service_name(),
                    "Multicast DNS zero-config responder active on port {} [REQ-OP-001]",
                    config.listen_addr.port()
                );
                Some(Arc::new(resp))
            }
            Err(e) => {
                warn!(error = %e, "Failed to start mDNS responder; continuing without LAN discovery");
                None
            }
        }
    } else {
        None
    };

    if let Some(ref responder) = mdns_responder {
        let mdns_sync_resp = Arc::clone(responder);
        let mdns_sync_scheduler = Arc::clone(&scheduler);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            let mut last_count = 0;
            loop {
                interval.tick().await;
                let current_nodes = mdns_sync_scheduler.get_snapshot().metrics.total_nodes;
                if current_nodes != last_count {
                    if let Err(e) = mdns_sync_resp.update_node_count(current_nodes) {
                        warn!(error = %e, "Failed to update mDNS node count");
                    } else {
                        last_count = current_nodes;
                    }
                }
            }
        });
    }

    info!(
        addr = %config.listen_addr,
        "Starting Control Plane service"
    );

    let shutdown_signal = async move {
        #[cfg(unix)]
        let terminate_signal = async {
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(mut stream) => {
                    stream.recv().await;
                }
                Err(e) => {
                    error!(error = %e, "Failed to install SIGTERM signal handler");
                    std::future::pending::<()>().await;
                }
            }
        };

        #[cfg(not(unix))]
        let terminate_signal = std::future::pending::<()>();

        tokio::select! {
            ctrl_c_res = signal::ctrl_c() => {
                if let Err(e) = ctrl_c_res {
                    error!(error = %e, "Failed to install Ctrl+C signal handler");
                }
                info!("Received SIGINT (Ctrl+C). Draining connections and terminating server...");
            }
            _ = terminate_signal => {
                info!("Received SIGTERM. Draining connections and terminating server...");
            }
        }

        let _ = artifact_shutdown_tx.send(());
        let _ = web_shutdown_tx.send(());
        if let Some(resp) = mdns_responder {
            resp.shutdown();
        }
    };

    if mtls_enabled {
        info!("Enforcing dual-plane TLS 1.3 mTLS on gRPC + /v1/blobs [REQ-OP-001], [INV-002], [NFR-SEC-001], ADR-008");
        let ca_path = config.tls_ca_cert_path.as_ref().unwrap();
        let cert_path = config.tls_server_cert_path.as_ref().unwrap();
        let key_path = config.tls_server_key_path.as_ref().unwrap();

        let ca_cert_pem = tokio::fs::read(ca_path).await?;
        let server_cert_pem = tokio::fs::read(cert_path).await?;
        let server_key_pem = tokio::fs::read(key_path).await?;

        let server_tls =
            build_bootstrap_rustls_server_config(&server_cert_pem, &server_key_pem, &ca_cert_pem)
                .map_err(|e| format!("Failed to build dual-plane TLS config: {e}"))?;

        let mut routes = tonic::service::Routes::new(service_server).add_service(admin_server);
        if let Some(ctx) = enrollment_ctx.clone() {
            let enrollment_service = EnrollmentServiceImpl::with_context(ctx);
            let enrollment_server = EnrollmentServiceServer::new(enrollment_service)
                .max_decoding_message_size(config.max_frame_size_bytes)
                .max_encoding_message_size(config.max_frame_size_bytes);
            routes = routes.add_service(enrollment_server);
        }

        let app_router = routes.into_axum_router().merge(ArtifactServer::blob_router(
            Arc::clone(&artifact_store),
            config.max_apk_bytes,
        ));
        let grpc_listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
        serve_dual_plane_tls(grpc_listener, server_tls, app_router, shutdown_signal).await;
    } else {
        warn!("mTLS credentials not specified; binding plaintext service [development mode]");
        let mut router = Server::builder()
            .add_service(service_server)
            .add_service(admin_server);

        if let Some(ctx) = enrollment_ctx.clone() {
            let enrollment_service = EnrollmentServiceImpl::with_context(ctx);
            let enrollment_server = EnrollmentServiceServer::new(enrollment_service)
                .max_decoding_message_size(config.max_frame_size_bytes)
                .max_encoding_message_size(config.max_frame_size_bytes);
            router = router.add_service(enrollment_server);
        }

        router
            .serve_with_shutdown(config.listen_addr, shutdown_signal)
            .await?;
    }

    info!("AndroGrid Control Plane terminated cleanly");
    Ok(())
}

#[derive(Clone, Copy)]
struct ConditionalMtlsInterceptor {
    mtls_enabled: bool,
}

impl tonic::service::Interceptor for ConditionalMtlsInterceptor {
    #[allow(clippy::result_large_err)]
    fn call(&mut self, req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        if self.mtls_enabled {
            require_client_mtls_interceptor(req)
        } else {
            Ok(req)
        }
    }
}
