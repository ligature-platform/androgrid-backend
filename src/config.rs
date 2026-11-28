//! Cluster configuration and environment loading.
//!
//! Traces to: AG-SPEC-2026-V2 Section 2.3, Section 7, [NFR-SEC-001], [NFR-PERF-001]

use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;

use crate::MAX_FRAME_SIZE_BYTES;

/// Configuration loading errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("Invalid socket address format in {var}: {val}")]
    InvalidSocketAddr { var: &'static str, val: String },
    #[error("Invalid integer value in {var}: {val}")]
    InvalidInteger { var: &'static str, val: String },
    #[error("Invalid boolean value in {var}: {val}")]
    InvalidBoolean { var: &'static str, val: String },
    #[error("Invalid certificate renewal policy: {0}")]
    InvalidRenewalPolicy(String),
}

/// Helper parsing boolean environment variables strictly without fail-open defaults.
///
/// Traces to: [REQ-OP-001], [NFR-SEC-001]
pub fn parse_env_bool(var: &'static str, val: &str) -> Result<bool, ConfigError> {
    match val.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::InvalidBoolean {
            var,
            val: val.to_string(),
        }),
    }
}

/// Orchestrator host control plane configuration settings.
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// Socket address for gRPC service binding (default: 127.0.0.1:50051).
    pub listen_addr: SocketAddr,

    /// Optional path to X.509 CA certificate for client mTLS validation.
    pub tls_ca_cert_path: Option<PathBuf>,

    /// Optional path to server certificate PEM.
    pub tls_server_cert_path: Option<PathBuf>,

    /// Optional path to server private key PEM.
    pub tls_server_key_path: Option<PathBuf>,

    /// Optional path to Root CA private key PEM for worker CSR enrollment signing.
    /// Traces to: [INV-002], [NFR-SEC-001]
    pub tls_ca_key_path: Option<PathBuf>,

    /// Whether ephemeral device pairing and bootstrap enrollment are enabled (default: true).
    /// Traces to: [INV-002], [NFR-SEC-001], [REQ-OP-001]
    pub allow_pairing: bool,

    /// Whether in-band mTLS certificate renewal is enabled (default: true).
    /// Decoupled from `allow_pairing` so operators can disable QR onboarding while allowing renewals.
    /// Traces to: [INV-002], [NFR-SEC-001], [REQ-OP-005]
    pub allow_cert_renewal: bool,

    /// Server-side renewal window in days before certificate expiration (default: 30).
    /// Traces to: [INV-002], [REQ-OP-005]
    pub cert_renewal_window_days: u32,

    /// Minimum remaining CA validity required beyond the renewal window in days (default: 7).
    /// Traces to: [INV-002], [REQ-OP-005]
    pub cert_renewal_min_ca_extension_days: u32,

    /// Default validity duration in days for renewed worker certificates (default: 365).
    /// Traces to: [INV-002], [REQ-OP-005]
    pub cert_renewal_validity_days: u32,

    /// Default lifetime in seconds for newly issued pairing tokens (default: 300s).
    pub pairing_token_ttl_seconds: u32,

    /// Declarative heartbeat synchronization interval in seconds (default: 2s).
    pub heartbeat_interval_seconds: u32,

    /// Node lease timeout in seconds before worker is marked offline (default: 10s).
    pub lease_timeout_seconds: u32,

    /// Maximum allowable gRPC message frame payload in bytes (default: 16 MB).
    pub max_frame_size_bytes: usize,

    /// Whether scheduling of insecure root shell tasks is allowed (default: false).
    /// Traces to: [INV-006]
    pub allow_insecure_root_tasks: bool,

    /// Socket address for HTTP static artifact server binding (default: 127.0.0.1:50052).
    /// Traces to: [NFR-PERF-001], [REQ-OP-003]
    pub artifact_listen_addr: SocketAddr,

    /// Optional explicit base URL for worker artifact downloads (e.g. "http://127.0.0.1:50052").
    /// Traces to: [NFR-PERF-001], [REQ-OP-003]
    pub artifact_base_url: Option<String>,

    /// Optional persistent directory on disk for cached WebAssembly artifacts.
    pub artifact_storage_dir: Option<PathBuf>,

    /// Optional directory path for persisting active OTA rollout records.
    /// Traces to: ADR-010, [REQ-OP-001], [NFR-REL-001]
    pub rollout_storage_dir: Option<PathBuf>,

    /// Optional persistent state directory for cluster operational data.
    /// Traces to: [REQ-OP-001], Gate L-02
    pub state_dir: Option<PathBuf>,

    /// Explicit path to the embedded transactional admission database (`admission.redb`).
    /// Traces to: [REQ-OP-001], [REQ-VER-001], Gate L-02
    pub admission_db_path: Option<PathBuf>,

    /// Optional path to an administrator-confirmed historical membership inventory file.
    /// Traces to: [REQ-OP-001], Gate L-02
    pub admission_inventory_path: Option<PathBuf>,

    /// Optional comma-separated list of pre-seeded admitted worker node IDs.
    /// Traces to: [REQ-OP-001], Gate L-02
    pub seeded_admitted_nodes: Option<String>,

    /// Maximum allowed byte length for uploaded APK artifacts (default: 128 MB).
    /// Traces to: [NFR-PERF-001]
    pub max_apk_bytes: usize,

    /// Whether Android KeyStore hardware attestation verification is strictly enforced during enrollment.
    /// When true, enrollment requests lacking valid TEE/StrongBox attestation chains are hard rejected.
    /// Traces to: [INV-001], [INV-002], [NFR-SEC-001]
    pub enforce_hardware_attestation: bool,

    /// Whether the attestation challenge nonce is strictly verified during enrollment.
    /// When true, attestationChallenge must match SHA-256("{pairing_token}:{node_id}").
    /// Default: false (permits staged mobile client rollout without breaking legacy clients).
    /// Traces to: [INV-002], [NFR-SEC-001]
    pub require_attestation_challenge: bool,

    /// Socket address for Operator Web UI HTTP server binding (default: 127.0.0.1:8080).
    /// Traces to: [REQ-OP-001], [INV-004], [INV-005]
    pub web_listen_addr: SocketAddr,

    /// Whether the Operator Web UI server is enabled (default: true).
    /// Traces to: [REQ-OP-001], [INV-004]
    pub enable_web_ui: bool,

    /// Whether the mDNS DNS-SD responder is enabled (default: true).
    /// Traces to: [REQ-OP-001], [INV-001]
    pub enable_mdns: bool,

    /// Instance name advertised via mDNS DNS-SD (default: "androgrid-orchestrator").
    /// Traces to: [REQ-OP-001]
    pub mdns_service_name: String,

    /// URL for downloading the worker APK from GitHub Releases or custom mirror.
    /// Traces to: [REQ-OP-001]
    pub apk_download_url: String,

    /// Optional explicit cluster endpoint (e.g. "192.168.1.100:50051").
    /// Traces to: [REQ-OP-001], [INV-001]
    pub cluster_endpoint: Option<String>,

    /// Optional operator confirmation PIN (e.g. 6-digit numeric PIN).
    /// Traces to: [NFR-SEC-001], [REQ-OP-001]
    pub operator_pin: Option<String>,

    /// Optional operator confirmation token for automated pairing approval.
    /// Traces to: [NFR-SEC-001], [REQ-OP-001]
    pub confirmation_token: Option<String>,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:50051"
                .parse()
                .expect("Default socket address must be valid"),
            tls_ca_cert_path: None,
            tls_server_cert_path: None,
            tls_server_key_path: None,
            tls_ca_key_path: None,
            allow_pairing: true,
            allow_cert_renewal: true,
            cert_renewal_window_days: 30,
            cert_renewal_min_ca_extension_days: 7,
            cert_renewal_validity_days: 365,
            pairing_token_ttl_seconds: 300,
            heartbeat_interval_seconds: 2,
            lease_timeout_seconds: 10,
            max_frame_size_bytes: MAX_FRAME_SIZE_BYTES,
            allow_insecure_root_tasks: false,
            artifact_listen_addr: "127.0.0.1:50052"
                .parse()
                .expect("Default artifact socket address must be valid"),
            artifact_base_url: None,
            artifact_storage_dir: None,
            rollout_storage_dir: None,
            state_dir: None,
            admission_db_path: None,
            admission_inventory_path: None,
            seeded_admitted_nodes: None,
            max_apk_bytes: 128 * 1024 * 1024,
            enforce_hardware_attestation: false,
            require_attestation_challenge: false,
            web_listen_addr: "127.0.0.1:8080"
                .parse()
                .expect("Default web socket address must be valid"),
            enable_web_ui: true,
            enable_mdns: true,
            mdns_service_name: "androgrid-orchestrator".to_string(),
            apk_download_url: "https://github.com/ligature-platform/androgrid-android/releases/latest/download/androgrid-worker.apk".to_string(),
            cluster_endpoint: None,
            operator_pin: None,
            confirmation_token: None,
        }
    }
}

impl ClusterConfig {
    /// Loads configuration from environment variables with fallback to defaults.
    ///
    /// # Environment Variables:
    /// * `ANDROGRID_LISTEN_ADDR` - Socket address to bind (e.g. "0.0.0.0:50051").
    /// * `ANDROGRID_CA_CERT_PATH` - Path to CA certificate PEM for mTLS.
    /// * `ANDROGRID_SERVER_CERT_PATH` - Path to server certificate PEM.
    /// * `ANDROGRID_SERVER_KEY_PATH` - Path to server private key PEM.
    /// * `ANDROGRID_HEARTBEAT_SECS` - Heartbeat interval in seconds.
    /// * `ANDROGRID_LEASE_TIMEOUT_SECS` - Lease timeout in seconds.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut config = Self::default();

        if let Ok(val) = std::env::var("ANDROGRID_LISTEN_ADDR") {
            config.listen_addr = val.parse().map_err(|_| ConfigError::InvalidSocketAddr {
                var: "ANDROGRID_LISTEN_ADDR",
                val,
            })?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_CA_CERT_PATH") {
            config.tls_ca_cert_path = Some(PathBuf::from(val));
        }

        if let Ok(val) = std::env::var("ANDROGRID_SERVER_CERT_PATH") {
            config.tls_server_cert_path = Some(PathBuf::from(val));
        }

        if let Ok(val) = std::env::var("ANDROGRID_SERVER_KEY_PATH") {
            config.tls_server_key_path = Some(PathBuf::from(val));
        }

        if let Ok(val) = std::env::var("ANDROGRID_CA_KEY_PATH") {
            config.tls_ca_key_path = Some(PathBuf::from(val));
        }

        if let Ok(val) = std::env::var("ANDROGRID_ALLOW_PAIRING") {
            config.allow_pairing = parse_env_bool("ANDROGRID_ALLOW_PAIRING", &val)?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_ALLOW_CERT_RENEWAL") {
            config.allow_cert_renewal = parse_env_bool("ANDROGRID_ALLOW_CERT_RENEWAL", &val)?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_CERT_RENEWAL_WINDOW_DAYS") {
            config.cert_renewal_window_days =
                val.parse().map_err(|_| ConfigError::InvalidInteger {
                    var: "ANDROGRID_CERT_RENEWAL_WINDOW_DAYS",
                    val,
                })?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_CERT_RENEWAL_MIN_CA_EXTENSION_DAYS") {
            config.cert_renewal_min_ca_extension_days =
                val.parse().map_err(|_| ConfigError::InvalidInteger {
                    var: "ANDROGRID_CERT_RENEWAL_MIN_CA_EXTENSION_DAYS",
                    val,
                })?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_CERT_RENEWAL_VALIDITY_DAYS") {
            config.cert_renewal_validity_days =
                val.parse().map_err(|_| ConfigError::InvalidInteger {
                    var: "ANDROGRID_CERT_RENEWAL_VALIDITY_DAYS",
                    val,
                })?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_PAIRING_TOKEN_TTL_SECS") {
            config.pairing_token_ttl_seconds =
                val.parse().map_err(|_| ConfigError::InvalidInteger {
                    var: "ANDROGRID_PAIRING_TOKEN_TTL_SECS",
                    val,
                })?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_HEARTBEAT_SECS") {
            config.heartbeat_interval_seconds =
                val.parse().map_err(|_| ConfigError::InvalidInteger {
                    var: "ANDROGRID_HEARTBEAT_SECS",
                    val,
                })?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_LEASE_TIMEOUT_SECS") {
            config.lease_timeout_seconds =
                val.parse().map_err(|_| ConfigError::InvalidInteger {
                    var: "ANDROGRID_LEASE_TIMEOUT_SECS",
                    val,
                })?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_ALLOW_INSECURE_ROOT_TASKS") {
            config.allow_insecure_root_tasks =
                parse_env_bool("ANDROGRID_ALLOW_INSECURE_ROOT_TASKS", &val)?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_ARTIFACT_LISTEN_ADDR") {
            config.artifact_listen_addr =
                val.parse().map_err(|_| ConfigError::InvalidSocketAddr {
                    var: "ANDROGRID_ARTIFACT_LISTEN_ADDR",
                    val,
                })?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_ARTIFACT_BASE_URL") {
            config.artifact_base_url = Some(val);
        }

        if let Ok(val) = std::env::var("ANDROGRID_ARTIFACT_DIR") {
            config.artifact_storage_dir = Some(PathBuf::from(val));
        }

        if let Ok(val) = std::env::var("ANDROGRID_ROLLOUT_DIR") {
            config.rollout_storage_dir = Some(PathBuf::from(val));
        }

        if let Ok(val) = std::env::var("ANDROGRID_STATE_DIR") {
            config.state_dir = Some(PathBuf::from(val));
        }

        if let Ok(val) = std::env::var("ANDROGRID_ADMISSION_DB") {
            config.admission_db_path = Some(PathBuf::from(val));
        }

        if let Ok(val) = std::env::var("ANDROGRID_ADMISSION_INVENTORY") {
            config.admission_inventory_path = Some(PathBuf::from(val));
        }

        if let Ok(val) = std::env::var("ANDROGRID_SEEDED_ADMITTED_NODES") {
            config.seeded_admitted_nodes = Some(val);
        }

        if let Ok(val) = std::env::var("ANDROGRID_MAX_APK_BYTES") {
            config.max_apk_bytes =
                val.parse::<usize>()
                    .map_err(|_| ConfigError::InvalidInteger {
                        var: "ANDROGRID_MAX_APK_BYTES",
                        val,
                    })?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_ENFORCE_HARDWARE_ATTESTATION") {
            config.enforce_hardware_attestation =
                parse_env_bool("ANDROGRID_ENFORCE_HARDWARE_ATTESTATION", &val)?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_REQUIRE_ATTESTATION_CHALLENGE") {
            config.require_attestation_challenge =
                parse_env_bool("ANDROGRID_REQUIRE_ATTESTATION_CHALLENGE", &val)?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_WEB_LISTEN_ADDR") {
            config.web_listen_addr = val.parse().map_err(|_| ConfigError::InvalidSocketAddr {
                var: "ANDROGRID_WEB_LISTEN_ADDR",
                val,
            })?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_ENABLE_WEB_UI") {
            config.enable_web_ui = parse_env_bool("ANDROGRID_ENABLE_WEB_UI", &val)?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_ENABLE_MDNS") {
            config.enable_mdns = parse_env_bool("ANDROGRID_ENABLE_MDNS", &val)?;
        }

        if let Ok(val) = std::env::var("ANDROGRID_MDNS_SERVICE_NAME") {
            config.mdns_service_name = val;
        }

        if let Ok(val) = std::env::var("ANDROGRID_WORKER_APK_URL") {
            config.apk_download_url = val;
        }

        if let Ok(val) = std::env::var("ANDROGRID_CLUSTER_ENDPOINT") {
            config.cluster_endpoint = Some(val);
        } else if let Ok(val) = std::env::var("ANDROGRID_PUBLIC_ENDPOINT") {
            config.cluster_endpoint = Some(val);
        }

        if let Ok(val) = std::env::var("ANDROGRID_OPERATOR_PIN") {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                config.operator_pin = Some(trimmed.to_string());
            }
        }

        if let Ok(val) = std::env::var("ANDROGRID_CONFIRMATION_TOKEN") {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                config.confirmation_token = Some(trimmed.to_string());
            }
        }

        config.validate_renewal_policy()?;
        Ok(config)
    }

    /// Validates certificate renewal configuration bounds.
    ///
    /// Traces to: [INV-002], [REQ-OP-005]
    pub fn validate_renewal_policy(&self) -> Result<(), ConfigError> {
        if self.cert_renewal_validity_days == 0 {
            return Err(ConfigError::InvalidRenewalPolicy(
                "ANDROGRID_CERT_RENEWAL_VALIDITY_DAYS must be greater than 0".to_string(),
            ));
        }
        if self.cert_renewal_window_days >= self.cert_renewal_validity_days {
            return Err(ConfigError::InvalidRenewalPolicy(format!(
                "ANDROGRID_CERT_RENEWAL_WINDOW_DAYS ({}) must be strictly less than ANDROGRID_CERT_RENEWAL_VALIDITY_DAYS ({})",
                self.cert_renewal_window_days, self.cert_renewal_validity_days
            )));
        }
        Ok(())
    }

    /// Resolves the base URL for worker artifact downloads.
    ///
    /// Traces to: [NFR-PERF-001], [REQ-OP-003]
    /// Resolves the canonical database path for the embedded transactional admission store.
    ///
    /// Traces to: [REQ-OP-001], [REQ-VER-001], Gate L-02
    pub fn resolve_admission_db_path(&self) -> PathBuf {
        if let Some(ref p) = self.admission_db_path {
            return p.clone();
        }
        if let Some(ref state_dir) = self.state_dir {
            return state_dir.join("admission.redb");
        }
        if let Some(ref rollout_dir) = self.rollout_storage_dir {
            return rollout_dir.join("admission.redb");
        }
        if let Some(ref artifact_dir) = self.artifact_storage_dir {
            return artifact_dir.join("admission.redb");
        }
        PathBuf::from("androgrid-data")
            .join("state")
            .join("admission.redb")
    }

    pub fn resolve_artifact_base_url(&self) -> String {
        if let Some(ref base) = self.artifact_base_url {
            base.trim_end_matches('/').to_string()
        } else {
            format!("http://{}", self.artifact_listen_addr)
        }
    }

    /// Formats the fully qualified content-addressed download URL for a SHA-256 hash.
    ///
    /// Traces to: [NFR-PERF-001], [REQ-OP-003]
    pub fn format_artifact_url(&self, sha256_hex: &str) -> String {
        let clean_sha = sha256_hex
            .trim()
            .trim_end_matches(".wasm")
            .to_ascii_lowercase();
        format!(
            "{}/artifacts/{clean_sha}.wasm",
            self.resolve_artifact_base_url()
        )
    }

    /// Resolves the mTLS `/v1/blobs` base URL when dual-plane TLS is enabled.
    ///
    /// Prefers `artifact_base_url` (`ANDROGRID_ARTIFACT_BASE_URL`) when configured,
    /// appending `/v1/blobs` if not already present. Otherwise derives an HTTPS URL from
    /// the routable cluster endpoint (`resolve_cluster_endpoint()`), ensuring remote workers
    /// on LAN or WAN reach the correct host IP rather than loopback.
    ///
    /// Traces to: [INV-002], [NFR-PERF-001], ADR-008, [REQ-OP-001]
    pub fn resolve_mtls_blob_base_url(&self) -> String {
        if let Some(ref base) = self.artifact_base_url {
            let trimmed = base.trim_end_matches('/');
            if trimmed.ends_with("/v1/blobs") {
                trimmed.to_string()
            } else {
                format!("{trimmed}/v1/blobs")
            }
        } else {
            let endpoint = self.resolve_cluster_endpoint();
            format!("https://{endpoint}/v1/blobs")
        }
    }

    /// Checks if full mutual TLS credentials are provided in configuration.
    pub fn is_mtls_configured(&self) -> bool {
        self.tls_ca_cert_path.is_some()
            && self.tls_server_cert_path.is_some()
            && self.tls_server_key_path.is_some()
    }

    /// Resolves the routable gRPC cluster endpoint (`host:port`) advertised to mobile workers.
    ///
    /// Prefers explicit `cluster_endpoint` (`ANDROGRID_CLUSTER_ENDPOINT`), followed by
    /// `ANDROGRID_HOST_IP` if `listen_addr` uses an unspecified bind address (`0.0.0.0`, `::`),
    /// auto-detecting the primary outbound physical LAN IP if possible, and falling back
    /// to loopback or bound address.
    ///
    /// Traces to: [REQ-OP-001], [INV-001], [INV-002]
    pub fn resolve_cluster_endpoint(&self) -> String {
        if let Some(ref ep) = self.cluster_endpoint {
            let stripped = crate::pairing::strip_uri_scheme(ep);
            if !stripped.is_empty() {
                return stripped;
            }
        }

        let port = self.listen_addr.port();
        match self.listen_addr.ip() {
            std::net::IpAddr::V4(ip) if ip.is_unspecified() => {
                if let Ok(host_ip) = std::env::var("ANDROGRID_HOST_IP") {
                    let trimmed = host_ip.trim();
                    if !trimmed.is_empty() {
                        return format!("{trimmed}:{port}");
                    }
                }
                if let Some(lan_ip) = detect_outbound_lan_ipv4() {
                    return format!("{lan_ip}:{port}");
                }
                format!("127.0.0.1:{port}")
            }
            std::net::IpAddr::V6(ip) if ip.is_unspecified() => {
                if let Ok(host_ip) = std::env::var("ANDROGRID_HOST_IP") {
                    let trimmed = host_ip.trim();
                    if !trimmed.is_empty() {
                        return format!("{trimmed}:{port}");
                    }
                }
                if let Some(lan_ip) = detect_outbound_lan_ipv4() {
                    return format!("{lan_ip}:{port}");
                }
                format!("[::1]:{port}")
            }
            std::net::IpAddr::V6(ip) => format!("[{ip}]:{port}"),
            std::net::IpAddr::V4(ip) => format!("{ip}:{port}"),
        }
    }
}

/// Attempts to determine the host's primary outbound LAN IPv4 address using
/// an ephemeral UDP routing table query to avoid binding to virtual Hyper-V/WSL/VPN adapters.
///
/// Does not transmit any network packets. Traces to: [REQ-OP-001], [INV-001]
pub fn detect_outbound_lan_ipv4() -> Option<std::net::Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_adheres_to_specification_bounds() {
        let config = ClusterConfig::default();
        assert_eq!(config.listen_addr.port(), 50051);
        assert_eq!(config.heartbeat_interval_seconds, 2);
        assert_eq!(config.lease_timeout_seconds, 10);
        assert_eq!(config.max_frame_size_bytes, 16 * 1024 * 1024);
        assert!(config.allow_pairing);
        assert_eq!(config.pairing_token_ttl_seconds, 300);
        assert!(!config.is_mtls_configured());
    }

    #[test]
    fn test_is_mtls_configured_requires_all_three_components() {
        let mut config = ClusterConfig::default();
        assert!(!config.is_mtls_configured());

        config.tls_ca_cert_path = Some(PathBuf::from("/etc/ca.crt"));
        assert!(!config.is_mtls_configured());

        config.tls_server_cert_path = Some(PathBuf::from("/etc/server.crt"));
        assert!(!config.is_mtls_configured());

        config.tls_server_key_path = Some(PathBuf::from("/etc/server.key"));
        assert!(config.is_mtls_configured());
    }

    #[test]
    fn test_resolve_mtls_blob_base_url_honors_override_and_normalizes_unspecified() {
        let mut config = ClusterConfig {
            listen_addr: "0.0.0.0:50051".parse().unwrap(),
            ..Default::default()
        };
        // Unspecified without host IP env defaults to auto-detected LAN IP or loopback endpoint
        let expected_base = if let Some(lan_ip) = detect_outbound_lan_ipv4() {
            format!("https://{lan_ip}:50051/v1/blobs")
        } else {
            "https://127.0.0.1:50051/v1/blobs".to_string()
        };
        assert_eq!(config.resolve_mtls_blob_base_url(), expected_base);

        // When cluster_endpoint or host IP is set, resolve_mtls_blob_base_url respects it
        config.cluster_endpoint = Some("192.168.1.100:50051".to_string());
        assert_eq!(
            config.resolve_mtls_blob_base_url(),
            "https://192.168.1.100:50051/v1/blobs"
        );

        config.artifact_base_url = Some("https://cluster.example.com/".to_string());
        assert_eq!(
            config.resolve_mtls_blob_base_url(),
            "https://cluster.example.com/v1/blobs"
        );

        config.artifact_base_url = Some("https://cluster.example.com/v1/blobs/".to_string());
        assert_eq!(
            config.resolve_mtls_blob_base_url(),
            "https://cluster.example.com/v1/blobs"
        );
    }

    #[test]
    fn test_web_ui_and_mdns_config_defaults() {
        let config = ClusterConfig::default();
        assert_eq!(config.web_listen_addr.port(), 8080);
        assert!(config.enable_web_ui);
        assert!(config.enable_mdns);
        assert_eq!(config.mdns_service_name, "androgrid-orchestrator");
        assert!(config.apk_download_url.contains("androgrid-worker.apk"));
        assert_eq!(config.resolve_cluster_endpoint(), "127.0.0.1:50051");
    }

    #[test]
    fn test_resolve_cluster_endpoint_with_overrides() {
        let mut config = ClusterConfig {
            listen_addr: "0.0.0.0:50051".parse().unwrap(),
            ..Default::default()
        };
        // Unspecified falls back to auto-detected outbound LAN IP or loopback
        let resolved = config.resolve_cluster_endpoint();
        if let Some(lan_ip) = detect_outbound_lan_ipv4() {
            assert_eq!(resolved, format!("{lan_ip}:50051"));
        } else {
            assert_eq!(resolved, "127.0.0.1:50051");
        }

        // Explicit cluster_endpoint override takes precedence
        config.cluster_endpoint = Some("https://node.edge.androgrid:50051/".to_string());
        assert_eq!(
            config.resolve_cluster_endpoint(),
            "node.edge.androgrid:50051"
        );
    }

    #[test]
    fn test_detect_outbound_lan_ipv4_non_loopback() {
        if let Some(ip) = detect_outbound_lan_ipv4() {
            assert!(!ip.is_loopback());
            assert!(!ip.is_unspecified());
        }
    }

    #[test]
    fn test_parse_env_bool_valid_and_invalid() {
        assert!(parse_env_bool("TEST_VAR", "true").unwrap());
        assert!(parse_env_bool("TEST_VAR", "TRUE").unwrap());
        assert!(parse_env_bool("TEST_VAR", "1").unwrap());
        assert!(parse_env_bool("TEST_VAR", "yes").unwrap());
        assert!(parse_env_bool("TEST_VAR", "on").unwrap());

        assert!(!parse_env_bool("TEST_VAR", "false").unwrap());
        assert!(!parse_env_bool("TEST_VAR", "FALSE").unwrap());
        assert!(!parse_env_bool("TEST_VAR", "0").unwrap());
        assert!(!parse_env_bool("TEST_VAR", "no").unwrap());
        assert!(!parse_env_bool("TEST_VAR", "off").unwrap());

        assert!(matches!(
            parse_env_bool("TEST_VAR", "flase"),
            Err(ConfigError::InvalidBoolean { .. })
        ));
        assert!(matches!(
            parse_env_bool("TEST_VAR", "2"),
            Err(ConfigError::InvalidBoolean { .. })
        ));
        assert!(matches!(
            parse_env_bool("TEST_VAR", "none"),
            Err(ConfigError::InvalidBoolean { .. })
        ));
    }
}
