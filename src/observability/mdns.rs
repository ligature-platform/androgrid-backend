//! Multicast DNS (mDNS) / DNS-SD Service Discovery Responder
//!
//! Advertises the AndroGrid control plane gRPC service on the local area network (LAN)
//! using DNS Service Discovery (`_androgrid._tcp.local.`) on port 50051.
//!
//! Traces to: AG-SPEC-2026-V2 Section 2.2, [REQ-OP-001], [INV-001], [INV-002], [NFR-SEC-001]

use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

/// Service type advertised for zero-configuration discovery on local Wi-Fi networks.
pub const MDNS_SERVICE_TYPE: &str = "_androgrid._tcp.local.";

/// Configuration for mDNS service advertisement.
///
/// Traces to: [REQ-OP-001], [INV-001]
#[derive(Debug, Clone)]
pub struct MdnsConfig {
    /// Instance name of the orchestrator service (e.g. "androgrid-orchestrator").
    pub instance_name: String,
    /// Host name of the orchestrator (e.g. "androgrid.local.").
    pub host_name: String,
    /// Bound gRPC port (default: 50051).
    pub port: u16,
    /// Cluster software version string.
    pub version: String,
    /// Hexadecimal SHA-256 fingerprint of the cluster Root CA certificate.
    pub ca_fingerprint: String,
    /// Optional explicit IP address string to advertise.
    pub ip: Option<String>,
}

impl Default for MdnsConfig {
    fn default() -> Self {
        Self {
            instance_name: "androgrid-orchestrator".to_string(),
            host_name: "androgrid.local.".to_string(),
            port: 50051,
            version: env!("CARGO_PKG_VERSION").to_string(),
            ca_fingerprint: String::new(),
            ip: None,
        }
    }
}

/// Active mDNS service responder managing multicast service announcements.
///
/// Traces to: [REQ-OP-001], [INV-001], [INV-002]
pub struct MdnsResponder {
    daemon: ServiceDaemon,
    config: MdnsConfig,
    full_service_name: String,
    connected_nodes: Arc<AtomicUsize>,
}

impl MdnsResponder {
    /// Initializes and starts advertising the AndroGrid mDNS service.
    ///
    /// Traces to: [REQ-OP-001], [INV-001]
    pub fn start(config: MdnsConfig) -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(|e| format!("Failed to create mDNS daemon: {e}"))?;
        let connected_nodes = Arc::new(AtomicUsize::new(0));

        let mut properties = HashMap::new();
        properties.insert("version".to_string(), config.version.clone());
        properties.insert("nodes".to_string(), "0".to_string());
        properties.insert("name".to_string(), config.instance_name.clone());
        properties.insert("tls".to_string(), "1.3".to_string());
        if !config.ca_fingerprint.is_empty() {
            properties.insert("ca_fingerprint".to_string(), config.ca_fingerprint.clone());
        }

        let ip = config.ip.as_deref().unwrap_or("");
        let host_name = if config.host_name.ends_with('.') {
            config.host_name.clone()
        } else {
            format!("{}.", config.host_name)
        };

        let service_info = ServiceInfo::new(
            MDNS_SERVICE_TYPE,
            &config.instance_name,
            &host_name,
            ip,
            config.port,
            properties,
        )
        .map_err(|e| format!("Failed to construct mDNS ServiceInfo: {e}"))?;

        let full_service_name = service_info.get_fullname().to_string();

        daemon
            .register(service_info)
            .map_err(|e| format!("Failed to register mDNS service: {e}"))?;

        info!(
            service_type = MDNS_SERVICE_TYPE,
            instance = %config.instance_name,
            port = config.port,
            "mDNS DNS-SD responder started [REQ-OP-001]"
        );

        Ok(Self {
            daemon,
            config,
            full_service_name,
            connected_nodes,
        })
    }

    /// Updates the advertised worker node count in mDNS TXT records.
    ///
    /// Traces to: [REQ-OP-001]
    pub fn update_node_count(&self, count: usize) -> Result<(), String> {
        self.connected_nodes.store(count, Ordering::Relaxed);

        let mut properties = HashMap::new();
        properties.insert("version".to_string(), self.config.version.clone());
        properties.insert("nodes".to_string(), count.to_string());
        properties.insert("name".to_string(), self.config.instance_name.clone());
        properties.insert("tls".to_string(), "1.3".to_string());
        if !self.config.ca_fingerprint.is_empty() {
            properties.insert("ca_fingerprint".to_string(), self.config.ca_fingerprint.clone());
        }

        let ip = self.config.ip.as_deref().unwrap_or("");
        let host_name = if self.config.host_name.ends_with('.') {
            self.config.host_name.clone()
        } else {
            format!("{}.", self.config.host_name)
        };

        let service_info = ServiceInfo::new(
            MDNS_SERVICE_TYPE,
            &self.config.instance_name,
            &host_name,
            ip,
            self.config.port,
            properties,
        )
        .map_err(|e| format!("Failed to construct mDNS ServiceInfo: {e}"))?;

        self.daemon
            .register(service_info)
            .map_err(|e| format!("Failed to re-register mDNS service: {e}"))?;

        Ok(())
    }

    /// Returns the full DNS-SD service name string.
    pub fn full_service_name(&self) -> &str {
        &self.full_service_name
    }

    /// Gracefully unregisters and shuts down the mDNS responder daemon.
    ///
    /// Traces to: [REQ-OP-001]
    pub fn shutdown(&self) {
        if let Err(e) = self.daemon.unregister(&self.full_service_name) {
            warn!(error = %e, "Failed to unregister mDNS service during shutdown");
        }
        if let Err(e) = self.daemon.shutdown() {
            warn!(error = %e, "Failed to cleanly shutdown mDNS daemon");
        } else {
            info!("mDNS responder cleanly terminated");
        }
    }
}

impl Drop for MdnsResponder {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.full_service_name);
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdns_config_defaults() {
        let config = MdnsConfig::default();
        assert_eq!(config.instance_name, "androgrid-orchestrator");
        assert_eq!(config.port, 50051);
        assert_eq!(config.version, env!("CARGO_PKG_VERSION"));
        assert!(config.ca_fingerprint.is_empty());
    }

    #[test]
    fn test_mdns_responder_lifecycle() {
        let config = MdnsConfig {
            instance_name: "test-orchestrator".to_string(),
            host_name: "test.local.".to_string(),
            port: 59999,
            version: "0.0.1-test".to_string(),
            ca_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ip: Some("127.0.0.1".to_string()),
        };

        let responder = MdnsResponder::start(config).expect("mDNS start should succeed");
        assert!(responder.full_service_name().contains("_androgrid._tcp.local."));

        let update_res = responder.update_node_count(3);
        assert!(update_res.is_ok(), "Updating node count should succeed");

        responder.shutdown();
    }
}
