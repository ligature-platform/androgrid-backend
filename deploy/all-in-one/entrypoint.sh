#!/bin/sh
# AndroGrid Turnkey All-In-One Container Entrypoint Script
#
# Detects primary host LAN IP from routing tables, automatically initializes Day-0
# ECDSA P-256 TLS 1.3 PKI certificates with correct host SANs, and launches the
# orchestrator daemon with zero manual configuration.
#
# Traces to: AG-SPEC-2026-V2 Section 2.2, Section 2.3, ADR-001, [REQ-OP-001], [INV-001], [INV-002], [NFR-SEC-001]

set -eu

echo "================================================================================"
echo " Starting AndroGrid Turnkey Control Plane Orchestrator"
echo " [REQ-OP-001] [INV-001] [INV-002] [NFR-SEC-001]"
echo "================================================================================"

# Step 1: Detect primary host LAN IP from kernel routing table or interface list
HOST_IP="${ANDROGRID_HOST_IP:-}"

if [ -z "$HOST_IP" ]; then
    # Method A: Query routing table for outbound interface source IP towards gateway
    if command -v ip >/dev/null 2>&1; then
        HOST_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}') || true
        if [ -z "$HOST_IP" ]; then
            HOST_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}') || true
        fi
    fi

    # Method B: Fallback to hostname -I
    if [ -z "$HOST_IP" ] && command -v hostname >/dev/null 2>&1; then
        HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}') || true
    fi

    # Method C: Fallback to loopback
    if [ -z "$HOST_IP" ]; then
        HOST_IP="127.0.0.1"
        echo "(!) Warning: Could not detect host LAN IP from routing tables. Defaulting to 127.0.0.1."
    else
        echo "==> Detected primary host LAN IP: ${HOST_IP}"
    fi
else
    echo "==> Using operator-provided host LAN IP: ${HOST_IP}"
fi

# Step 2: Ensure persistent storage directories exist
DATA_DIR="${ANDROGRID_DATA_DIR:-/data}"
PKI_DIR="${DATA_DIR}/pki"
ARTIFACTS_DIR="${DATA_DIR}/artifacts"

mkdir -p "${PKI_DIR}" "${ARTIFACTS_DIR}"

# Step 3: Check for existing PKI certificates or auto-generate with detected SAN
NEEDS_PKI=0
if [ ! -f "${PKI_DIR}/runtime/server.crt" ] && [ ! -f "${PKI_DIR}/server.crt" ]; then
    NEEDS_PKI=1
fi

if [ "$NEEDS_PKI" -eq 1 ]; then
    if [ ! -f "${PKI_DIR}/ca.crt" ] && [ ! -f "${PKI_DIR}/runtime/ca.crt" ]; then
        echo "==> [Auto-PKI] No TLS certificates found in ${PKI_DIR}."
        echo "==> [Auto-PKI] Initializing ECDSA P-256 TLS 1.3 Root CA and server fullchain with SAN: ${HOST_IP}..."
        androgrid-cli cert init --out "${PKI_DIR}" --san "${HOST_IP}" --force
        echo "==> [Auto-PKI] PKI hierarchy successfully generated in ${PKI_DIR}."
    else
        EXISTING_CA_CERT="${PKI_DIR}/runtime/ca.crt"
        [ -f "${EXISTING_CA_CERT}" ] || EXISTING_CA_CERT="${PKI_DIR}/ca.crt"
        EXISTING_CA_KEY="${PKI_DIR}/operator/ca.key"
        [ -f "${EXISTING_CA_KEY}" ] || EXISTING_CA_KEY="${PKI_DIR}/ca.key"

        if [ -f "${EXISTING_CA_KEY}" ]; then
            echo "==> [Auto-PKI] Existing CA found, issuing server certificate with SAN: ${HOST_IP}..."
            androgrid-cli cert issue server --ca-key "${EXISTING_CA_KEY}" --ca-cert "${EXISTING_CA_CERT}" --out "${PKI_DIR}/server" --san "${HOST_IP}" --force
        else
            echo "ERROR: CA certificate exists at ${EXISTING_CA_CERT} but server certificate and CA key are missing!" >&2
            exit 1
        fi
    fi
else
    echo "==> Existing PKI certificates detected in ${PKI_DIR}."
fi

# Determine cert paths (hierarchical runtime/ vs flat layout)
if [ -f "${PKI_DIR}/runtime/ca.crt" ]; then
    CA_CERT_PATH="${PKI_DIR}/runtime/ca.crt"
    SERVER_CERT_PATH="${PKI_DIR}/runtime/server.crt"
    SERVER_KEY_PATH="${PKI_DIR}/runtime/server.key"
    CA_KEY_PATH="${PKI_DIR}/operator/ca.key"
else
    CA_CERT_PATH="${PKI_DIR}/ca.crt"
    SERVER_CERT_PATH="${PKI_DIR}/server.crt"
    SERVER_KEY_PATH="${PKI_DIR}/server.key"
    CA_KEY_PATH="${PKI_DIR}/ca.key"
fi

# Hardening: Lock Root CA private key strictly to POSIX 0600 permissions [NFR-SEC-001]
if [ -f "${CA_KEY_PATH}" ]; then
    chmod 0600 "${CA_KEY_PATH}" || { echo "ERROR: Failed to enforce POSIX 0600 permissions on ${CA_KEY_PATH}" >&2; exit 1; }
fi
if [ -f "${SERVER_KEY_PATH}" ]; then
    chmod 0600 "${SERVER_KEY_PATH}" || { echo "ERROR: Failed to enforce POSIX 0600 permissions on ${SERVER_KEY_PATH}" >&2; exit 1; }
fi

# Step 4: Seed pre-packaged workloads to artifact store if empty
# Stores workloads under both original name and content-addressed sha256 hash (<hash>.wasm)
if [ -d "/opt/androgrid/workloads" ]; then
    for wasm_file in /opt/androgrid/workloads/*.wasm; do
        if [ -f "$wasm_file" ]; then
            wasm_base=$(basename "$wasm_file")
            if [ ! -f "${ARTIFACTS_DIR}/${wasm_base}" ]; then
                cp "$wasm_file" "${ARTIFACTS_DIR}/" 2>/dev/null || true
            fi
            if command -v sha256sum >/dev/null 2>&1; then
                wasm_hash=$(sha256sum "$wasm_file" | awk '{print $1}')
                if [ -n "$wasm_hash" ] && [ ! -f "${ARTIFACTS_DIR}/${wasm_hash}.wasm" ]; then
                    cp "$wasm_file" "${ARTIFACTS_DIR}/${wasm_hash}.wasm" 2>/dev/null || true
                fi
            fi
        fi
    done
fi

# Step 5: Export runtime environment settings
export ANDROGRID_LISTEN_ADDR="${ANDROGRID_LISTEN_ADDR:-0.0.0.0:50051}"
export ANDROGRID_ARTIFACT_LISTEN_ADDR="${ANDROGRID_ARTIFACT_LISTEN_ADDR:-0.0.0.0:50052}"
export ANDROGRID_WEB_LISTEN_ADDR="${ANDROGRID_WEB_LISTEN_ADDR:-0.0.0.0:8080}"
export ANDROGRID_CA_CERT_PATH="${CA_CERT_PATH}"
export ANDROGRID_SERVER_CERT_PATH="${SERVER_CERT_PATH}"
export ANDROGRID_SERVER_KEY_PATH="${SERVER_KEY_PATH}"
export ANDROGRID_CA_KEY_PATH="${CA_KEY_PATH}"
export ANDROGRID_HOST_IP="${HOST_IP}"
export ANDROGRID_CLUSTER_ENDPOINT="${ANDROGRID_CLUSTER_ENDPOINT:-${HOST_IP}:50051}"
export ANDROGRID_ARTIFACT_DIR="${ARTIFACTS_DIR}"
export ANDROGRID_ALLOW_PAIRING="${ANDROGRID_ALLOW_PAIRING:-true}"
export ANDROGRID_ENABLE_WEB_UI="${ANDROGRID_ENABLE_WEB_UI:-true}"
export ANDROGRID_ENABLE_MDNS="${ANDROGRID_ENABLE_MDNS:-true}"
export RUST_LOG="${RUST_LOG:-info}"

echo "--------------------------------------------------------------------------------"
echo " Service Bindings:"
echo "   - Control Plane (gRPC TLS 1.3 mTLS): ${ANDROGRID_LISTEN_ADDR}"
echo "   - Artifact Store (HTTP Blobs):       ${ANDROGRID_ARTIFACT_LISTEN_ADDR}"
echo "   - Operator Web UI (Pairing & Dash):  http://${HOST_IP}:8080"
echo "   - Multicast DNS (DNS-SD):            5353/UDP (_androgrid._tcp.local.)"
echo "   - Advertised Cluster Endpoint:       ${ANDROGRID_CLUSTER_ENDPOINT}"
echo "================================================================================"

exec androgrid-backend "$@"
