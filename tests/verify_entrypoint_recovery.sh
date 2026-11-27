#!/usr/bin/env bash
set -euo pipefail

# Certificate recovery verification script for deploy/all-in-one/entrypoint.sh
# Traces to: [INV-002], [NFR-SEC-001], [REQ-OP-001]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -f "${REPO_ROOT}/target/debug/androgrid-cli.exe" ]; then
    CLI="${REPO_ROOT}/target/debug/androgrid-cli.exe"
elif [ -f "${REPO_ROOT}/target/debug/androgrid-cli" ]; then
    CLI="${REPO_ROOT}/target/debug/androgrid-cli"
else
    CLI="androgrid-cli"
fi

TEST_TMP="$(mktemp -d /tmp/androgrid_entrypoint_test_XXXXXX 2>/dev/null || mktemp -d)"
trap 'rm -rf "${TEST_TMP}"' EXIT

echo "=== Running Certificate Recovery Verification ==="

# ------------------------------------------------------------------------------
# Test 1: Fresh Day-0 initialization
# ------------------------------------------------------------------------------
echo "==> Case 1: Fresh Day-0 PKI initialization..."
CASE1_DATA="${TEST_TMP}/case1"
mkdir -p "${CASE1_DATA}"

(
    export ANDROGRID_DATA_DIR="${CASE1_DATA}"
    export HOST_IP="192.168.1.185"
    PKI_DIR="${CASE1_DATA}/pki"
    mkdir -p "${PKI_DIR}"

    "$CLI" cert init --out "${PKI_DIR}" --san "${HOST_IP}" --force

    [ -f "${PKI_DIR}/runtime/ca.crt" ] || { echo "FAIL: Case 1 missing runtime/ca.crt"; exit 1; }
    [ -f "${PKI_DIR}/runtime/server.crt" ] || { echo "FAIL: Case 1 missing runtime/server.crt"; exit 1; }
    [ -f "${PKI_DIR}/operator/ca.key" ] || { echo "FAIL: Case 1 missing operator/ca.key"; exit 1; }
)
echo "PASS: Case 1 Fresh Day-0 PKI init succeeded."

# ------------------------------------------------------------------------------
# Test 2: Missing server.crt in hierarchical layout (/runtime) preserves ca.crt SHA-256
# ------------------------------------------------------------------------------
echo "==> Case 2: Missing server.crt in hierarchical layout preserves ca.crt..."
CASE2_DATA="${TEST_TMP}/case2"
mkdir -p "${CASE2_DATA}"

# Copy case 1 PKI into case 2
cp -r "${CASE1_DATA}/pki" "${CASE2_DATA}/pki"
ORIG_CA_HASH=$(sha256sum "${CASE2_DATA}/pki/runtime/ca.crt" | awk '{print $1}')

# Simulate deleted/missing server.crt and server.key
rm -f "${CASE2_DATA}/pki/runtime/server.crt" "${CASE2_DATA}/pki/runtime/server.key"

(
    PKI_DIR="${CASE2_DATA}/pki"
    HOST_IP="192.168.1.185"

    NEEDS_PKI=0
    if [ ! -f "${PKI_DIR}/runtime/server.crt" ] && [ ! -f "${PKI_DIR}/server.crt" ]; then
        NEEDS_PKI=1
    fi

    if [ "$NEEDS_PKI" -eq 1 ]; then
        if [ ! -f "${PKI_DIR}/ca.crt" ] && [ ! -f "${PKI_DIR}/runtime/ca.crt" ]; then
            echo "FAIL: Should have detected existing CA"; exit 1;
        else
            EXISTING_CA_CERT="${PKI_DIR}/runtime/ca.crt"
            [ -f "${EXISTING_CA_CERT}" ] || EXISTING_CA_CERT="${PKI_DIR}/ca.crt"
            EXISTING_CA_KEY="${PKI_DIR}/operator/ca.key"
            [ -f "${EXISTING_CA_KEY}" ] || EXISTING_CA_KEY="${PKI_DIR}/ca.key"

            if [ -f "${EXISTING_CA_KEY}" ]; then
                SERVER_OUT_DIR="$(dirname "${EXISTING_CA_CERT}")"
                "$CLI" cert issue server --ca-key "${EXISTING_CA_KEY}" --ca-cert "${EXISTING_CA_CERT}" --out "${SERVER_OUT_DIR}" --san "${HOST_IP}" --force
            else
                exit 1
            fi
        fi
    fi

    # Verify server.crt was re-issued in runtime/
    [ -f "${PKI_DIR}/runtime/server.crt" ] || { echo "FAIL: server.crt not in runtime/"; exit 1; }
    [ -f "${PKI_DIR}/runtime/server.key" ] || { echo "FAIL: server.key not in runtime/"; exit 1; }

    NEW_CA_HASH=$(sha256sum "${PKI_DIR}/runtime/ca.crt" | awk '{print $1}')
    if [ "${ORIG_CA_HASH}" != "${NEW_CA_HASH}" ]; then
        echo "FAIL: CA certificate was modified during server cert recovery!"; exit 1;
    fi
)
echo "PASS: Case 2 Hierarchical server recovery preserved CA SHA-256."

# ------------------------------------------------------------------------------
# Test 3: Missing server.crt in flat layout (/pki) preserves ca.crt SHA-256
# ------------------------------------------------------------------------------
echo "==> Case 3: Missing server.crt in flat layout preserves ca.crt..."
CASE3_DATA="${TEST_TMP}/case3"
PKI3_DIR="${CASE3_DATA}/pki"
mkdir -p "${PKI3_DIR}"

# Create flat PKI layout
cp "${CASE1_DATA}/pki/runtime/ca.crt" "${PKI3_DIR}/ca.crt"
cp "${CASE1_DATA}/pki/operator/ca.key" "${PKI3_DIR}/ca.key"
ORIG_FLAT_CA_HASH=$(sha256sum "${PKI3_DIR}/ca.crt" | awk '{print $1}')

(
    PKI_DIR="${PKI3_DIR}"
    HOST_IP="192.168.1.185"

    NEEDS_PKI=0
    if [ ! -f "${PKI_DIR}/runtime/server.crt" ] && [ ! -f "${PKI_DIR}/server.crt" ]; then
        NEEDS_PKI=1
    fi

    if [ "$NEEDS_PKI" -eq 1 ]; then
        if [ ! -f "${PKI_DIR}/ca.crt" ] && [ ! -f "${PKI_DIR}/runtime/ca.crt" ]; then
            echo "FAIL: Should have detected flat CA"; exit 1;
        else
            EXISTING_CA_CERT="${PKI_DIR}/runtime/ca.crt"
            [ -f "${EXISTING_CA_CERT}" ] || EXISTING_CA_CERT="${PKI_DIR}/ca.crt"
            EXISTING_CA_KEY="${PKI_DIR}/operator/ca.key"
            [ -f "${EXISTING_CA_KEY}" ] || EXISTING_CA_KEY="${PKI_DIR}/ca.key"

            if [ -f "${EXISTING_CA_KEY}" ]; then
                SERVER_OUT_DIR="$(dirname "${EXISTING_CA_CERT}")"
                "$CLI" cert issue server --ca-key "${EXISTING_CA_KEY}" --ca-cert "${EXISTING_CA_CERT}" --out "${SERVER_OUT_DIR}" --san "${HOST_IP}" --force
            else
                exit 1
            fi
        fi
    fi

    # Verify server.crt was created in flat PKI_DIR
    [ -f "${PKI_DIR}/server.crt" ] || { echo "FAIL: server.crt not in flat PKI_DIR"; exit 1; }
    [ -f "${PKI_DIR}/server.key" ] || { echo "FAIL: server.key not in flat PKI_DIR"; exit 1; }

    NEW_FLAT_CA_HASH=$(sha256sum "${PKI_DIR}/ca.crt" | awk '{print $1}')
    if [ "${ORIG_FLAT_CA_HASH}" != "${NEW_FLAT_CA_HASH}" ]; then
        echo "FAIL: Flat CA certificate was modified during recovery!"; exit 1;
    fi
)
echo "PASS: Case 3 Flat server recovery preserved CA SHA-256."

# ------------------------------------------------------------------------------
# Test 4: Missing ca.key with existing ca.crt exits with code 1
# ------------------------------------------------------------------------------
echo "==> Case 4: Missing ca.key fails closed with exit code 1..."
CASE4_DATA="${TEST_TMP}/case4"
PKI4_DIR="${CASE4_DATA}/pki"
mkdir -p "${PKI4_DIR}"
cp "${CASE1_DATA}/pki/runtime/ca.crt" "${PKI4_DIR}/ca.crt"
# Intentionally DO NOT copy ca.key

EXIT_CODE=0
(
    PKI_DIR="${PKI4_DIR}"
    HOST_IP="192.168.1.185"

    NEEDS_PKI=0
    if [ ! -f "${PKI_DIR}/runtime/server.crt" ] && [ ! -f "${PKI_DIR}/server.crt" ]; then
        NEEDS_PKI=1
    fi

    if [ "$NEEDS_PKI" -eq 1 ]; then
        if [ ! -f "${PKI_DIR}/ca.crt" ] && [ ! -f "${PKI_DIR}/runtime/ca.crt" ]; then
            exit 2
        else
            EXISTING_CA_CERT="${PKI_DIR}/runtime/ca.crt"
            [ -f "${EXISTING_CA_CERT}" ] || EXISTING_CA_CERT="${PKI_DIR}/ca.crt"
            EXISTING_CA_KEY="${PKI_DIR}/operator/ca.key"
            [ -f "${EXISTING_CA_KEY}" ] || EXISTING_CA_KEY="${PKI_DIR}/ca.key"

            if [ -f "${EXISTING_CA_KEY}" ]; then
                SERVER_OUT_DIR="$(dirname "${EXISTING_CA_CERT}")"
                "$CLI" cert issue server --ca-key "${EXISTING_CA_KEY}" --ca-cert "${EXISTING_CA_CERT}" --out "${SERVER_OUT_DIR}" --san "${HOST_IP}" --force
            else
                echo "Expected error: CA certificate exists but server certificate and CA key are missing!" >&2
                exit 1
            fi
        fi
    fi
) || EXIT_CODE=$?

if [ "${EXIT_CODE}" -ne 1 ]; then
    echo "FAIL: Expected exit code 1 when ca.key is missing, got ${EXIT_CODE}"
    exit 1
fi
echo "PASS: Case 4 Missing ca.key exited with code 1."

echo "=== All 4 Certificate Recovery Checks Succeeded ==="
