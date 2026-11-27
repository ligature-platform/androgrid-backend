#!/usr/bin/env bash
set -euo pipefail

# Certificate recovery verification script for deploy/all-in-one/entrypoint.sh
# Traces to: [INV-002], [NFR-SEC-001], [REQ-OP-001]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENTRYPOINT="${REPO_ROOT}/deploy/all-in-one/entrypoint.sh"

TEST_TMP="$(mktemp -d /tmp/androgrid_entrypoint_test_XXXXXX 2>/dev/null || mktemp -d)"
trap 'rm -rf "${TEST_TMP}"' EXIT

MOCK_BIN="${TEST_TMP}/bin"
mkdir -p "${MOCK_BIN}"

# Stub for androgrid-backend that exits cleanly on startup
cat << "BACKEND_EOF" > "${MOCK_BIN}/androgrid-backend"
#!/bin/sh
exit 0
BACKEND_EOF
chmod +x "${MOCK_BIN}/androgrid-backend"

# Locate and copy androgrid-cli executable into MOCK_BIN
if [ -f "${REPO_ROOT}/target/debug/androgrid-cli.exe" ]; then
    cp "${REPO_ROOT}/target/debug/androgrid-cli.exe" "${MOCK_BIN}/androgrid-cli.exe"
elif [ -f "${REPO_ROOT}/target/debug/androgrid-cli" ]; then
    cp "${REPO_ROOT}/target/debug/androgrid-cli" "${MOCK_BIN}/androgrid-cli"
    chmod +x "${MOCK_BIN}/androgrid-cli"
else
    CLI_PATH="$(command -v androgrid-cli || true)"
    if [ -n "${CLI_PATH}" ]; then
        cp "${CLI_PATH}" "${MOCK_BIN}/"
    else
        echo "FAIL: androgrid-cli binary not found in target/debug or PATH" >&2
        exit 1
    fi
fi

export PATH="${MOCK_BIN}:${PATH}"

echo "=== Running Certificate Recovery Verification ==="

# ------------------------------------------------------------------------------
# Test 1: Fresh Day-0 initialization
# ------------------------------------------------------------------------------
echo "==> Case 1: Fresh Day-0 PKI initialization..."
CASE1_DATA="${TEST_TMP}/case1"
mkdir -p "${CASE1_DATA}"

(
    export ANDROGRID_DATA_DIR="${CASE1_DATA}"
    export ANDROGRID_HOST_IP="192.168.1.185"
    bash "${ENTRYPOINT}" >/dev/null 2>&1 || { echo "FAIL: Case 1 entrypoint.sh failed"; exit 1; }
)

[ -f "${CASE1_DATA}/pki/runtime/ca.crt" ] || { echo "FAIL: Case 1 missing runtime/ca.crt"; exit 1; }
[ -f "${CASE1_DATA}/pki/runtime/server.crt" ] || { echo "FAIL: Case 1 missing runtime/server.crt"; exit 1; }
[ -f "${CASE1_DATA}/pki/operator/ca.key" ] || { echo "FAIL: Case 1 missing operator/ca.key"; exit 1; }
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
    export ANDROGRID_DATA_DIR="${CASE2_DATA}"
    export ANDROGRID_HOST_IP="192.168.1.185"
    bash "${ENTRYPOINT}" >/dev/null 2>&1 || { echo "FAIL: Case 2 entrypoint.sh failed"; exit 1; }
)

# Verify server.crt was re-issued in runtime/
[ -f "${CASE2_DATA}/pki/runtime/server.crt" ] || { echo "FAIL: server.crt not in runtime/"; exit 1; }
[ -f "${CASE2_DATA}/pki/runtime/server.key" ] || { echo "FAIL: server.key not in runtime/"; exit 1; }

NEW_CA_HASH=$(sha256sum "${CASE2_DATA}/pki/runtime/ca.crt" | awk '{print $1}')
if [ "${ORIG_CA_HASH}" != "${NEW_CA_HASH}" ]; then
    echo "FAIL: CA certificate was modified during server cert recovery!"; exit 1;
fi
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
    export ANDROGRID_DATA_DIR="${CASE3_DATA}"
    export ANDROGRID_HOST_IP="192.168.1.185"
    bash "${ENTRYPOINT}" >/dev/null 2>&1 || { echo "FAIL: Case 3 entrypoint.sh failed"; exit 1; }
)

# Verify server.crt was created in flat PKI_DIR
[ -f "${PKI3_DIR}/server.crt" ] || { echo "FAIL: server.crt not in flat PKI_DIR"; exit 1; }
[ -f "${PKI3_DIR}/server.key" ] || { echo "FAIL: server.key not in flat PKI_DIR"; exit 1; }

NEW_FLAT_CA_HASH=$(sha256sum "${PKI3_DIR}/ca.crt" | awk '{print $1}')
if [ "${ORIG_FLAT_CA_HASH}" != "${NEW_FLAT_CA_HASH}" ]; then
    echo "FAIL: Flat CA certificate was modified during recovery!"; exit 1;
fi
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
    export ANDROGRID_DATA_DIR="${CASE4_DATA}"
    export ANDROGRID_HOST_IP="192.168.1.185"
    bash "${ENTRYPOINT}" >/dev/null 2>&1
) || EXIT_CODE=$?

if [ "${EXIT_CODE}" -ne 1 ]; then
    echo "FAIL: Expected exit code 1 when ca.key is missing, got ${EXIT_CODE}"
    exit 1
fi
echo "PASS: Case 4 Missing ca.key exited with code 1."

echo "=== All 4 Certificate Recovery Checks Succeeded ==="
