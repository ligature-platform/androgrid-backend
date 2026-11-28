# ADR-012: Operator Pairing Confirmation Gate and Web UI Transport Boundary

## Status
Accepted

## Architectural Scope & Requirements
- **Goal Reference:** G-26
- **Traceability:** `[INV-001]`, `[INV-002]`, `[NFR-SEC-001]`, `[REQ-OP-001]`
- **Standard:** ISO/IEC/IEEE 29148

---

## Context
The AndroGrid turnkey deployment architecture allows operators to rapidly bootstrap control plane nodes and onboard mobile workers via scannable QR codes rendered on an embedded Operator Web UI (port 8080).

Security reviews of the initial turnkey implementation identified two critical vulnerabilities:
1. **Unauthenticated Certificate Issuance:** In turnkey mode (`ANDROGRID_ALLOW_PAIRING=true`), any device on the network could query `/api/pair` and subsequently submit a PKCS#10 CSR to `/api/v1/enroll`, causing the orchestrator to automatically sign a valid X.509 mTLS client certificate against the cluster Root CA without human-in-the-loop verification.
2. **Plaintext Network Boundary Violation:** Exposing the unauthenticated Web UI and pairing API across non-loopback network interfaces over unencrypted HTTP violates the project architectural invariant `[INV-002]` and non-functional security requirement `[NFR-SEC-001]`.

The control plane requires a hardened enrollment architecture that prevents unauthorized certificate minting while preserving zero-friction turnkey onboarding for legitimate operators.

---

## Decision
We enforce a strict two-tier pairing security architecture and reconcile the Web UI transport policy with project security invariants:

### 1. Two-Tier Pairing Boundary
We establish two distinct trust domains for ephemeral worker pairing:
- **Tier 1 (Automated mTLS AdminService):** Administrative callers presenting a verified client certificate with `OU=Control Plane` can invoke `AdminService::GeneratePairingToken`. Tokens issued through this RPC are pre-confirmed (`is_confirmed = true`) by definition of caller authorization, enabling unattended CI/CD automation without manual operator intervention.
- **Tier 2 (Browser & QR Code Onboarding):** Ephemeral pairing tokens generated via the unauthenticated Operator Web UI (`POST /api/pair`) are created in an unconfirmed state (`is_confirmed = false`). Worker CSR submission against an unconfirmed token is hard-rejected with HTTP `403 Forbidden`. The token must be explicitly authorized by an operator via `POST /api/pair/confirm` using an ephemeral 6-digit confirmation PIN before CSR signing is permitted.

### 2. Ephemeral Dynamic PIN Rotation & Credential Safety
- **Per-Session Rotation:** Each browser pairing session generates a unique, cryptographically random 6-digit numeric PIN with a 300-second TTL.
- **Log Demarcation:** The session PIN is emitted strictly to orchestrator console / container logs (`tracing::info!`), accompanied by a truncated 8-character token prefix (`token_prefix = %&record.token[..8]`). Full token values are never logged, and the confirmation PIN is never transmitted over unauthenticated HTTP responses.
- **Constant-Time Verification:** PIN and confirmation token comparisons strictly enforce constant-time equality via `subtle::ConstantTimeEq` to eliminate timing side-channel attacks.

### 3. Anti-CSRF and Rate Limiting
- **Anti-CSRF Header:** All state-mutating Web UI endpoints (`POST /api/pair`, `POST /api/pair/confirm`) require the `X-Requested-With: XMLHttpRequest` header, rejecting unauthorized cross-site requests with HTTP `403 Forbidden`.
- **Per-IP Rate Limiting:** A sliding-window rate limiter tracks failed confirmation attempts per client IP. More than 10 failed attempts within a 300-second window triggers an immediate HTTP `429 Too Many Requests` lockout.
- **Bounded Resource Tracking:** The failed attempt tracker enforces an upper bound of 1,024 client IP entries with proactive TTL pruning and LRU eviction, preventing memory exhaustion attacks.

### 4. Reconciled Web UI Transport Policy
- **Loopback Default:** In strict accordance with `[INV-002]`, the Operator Web UI defaults exclusively to loopback binding (`127.0.0.1:8080`).
- **TLS Fronting Mandate:** Plaintext network pairing is explicitly not an accepted architecture or residual risk. Any binding to non-loopback interfaces for multi-host or remote operation must be fronted by a TLS reverse proxy or ingress controller terminating TLS 1.3.

### 5. Direct Pairing Endpoint Resolution, Embedded KV Admission Store & Onboarding Baseline Admission (Issue #30 / Gate L-02)
- **Unified Endpoint Advertisement:** `resolve_direct_pairing_endpoint()` unifies advertised host/port across mDNS TXT records, Web UI pairing responses (`POST /api/pair`), Web UI QR PNG endpoints (`GET /api/pair/qr`), and `AdminService::GeneratePairingToken`. Precedence is strictly enforced:
  1. Explicit `ANDROGRID_HOST_IP` environment variable override (e.g. for multi-homed hosts, VPNs, or explicit Wi-Fi adapters).
  2. Auto-detected physical outbound non-loopback LAN IPv4 (`detect_outbound_lan_ipv4()`), cleanly bypassing virtual Hyper-V and WSL switches.
  3. Bound listener IP.
- **Direct Payload Attributes & Discovery Availability:** Direct IP and port (`direct_ip`, `direct_port`) are encoded into pairing payloads and QR data, enabling Android workers to connect directly in topologies where router station isolation or mDNS filtering blocks zero-config multicast discovery. If no valid numeric LAN IP exists, mDNS discovery is disabled with an actionable diagnostic rather than advertising empty endpoints.
- **Canonical Scoped Firewall Automation:** Canonical host firewall management scripts are maintained in `androgrid-backend/deploy/setup-firewall.ps1` (Windows Defender with Preview, Check, Apply, Remove, and Private profile targeting) and `androgrid-backend/deploy/setup-firewall.sh` (Linux ufw, firewalld, iptables). Plaintext port 8080 is omitted from firewall rules; for LAN operator dashboard access, a turnkey Caddy TLS 1.3 reverse proxy configuration with mandatory HTTP basic authentication is provided (`androgrid-backend/deploy/caddy/Caddyfile`).
- **Durable Embedded Key-Value Admission Store (`redb` + Protobuf):** Worker node admission records are transactionally persisted to an embedded ACID-compliant `redb` database (`admission.redb`) using Protobuf serialization (`AdmissionRecordProto`). Ordinary startup requires an established database and refuses to silently recreate missing history unless explicitly authorized via `--init-admission-db` (`ANDROGRID_INIT_ADMISSION_DB=1`). Hydration decodes stored records and validates key-to-node_id identity; export fails fast on decode corruption.
- **Bounded Admission Waiting & Fresh Registration Timestamps:** New worker admission is guarded by a single-permit semaphore bounded by a 5000 ms timeout returning retryable `Status::unavailable`. The registration timestamp is recorded when blocking execution actually begins inside `spawn_blocking`, ensuring truthful session timestamps. Existing admitted workers bypass this disk write path entirely.
- **Strict SemVer 2.0.0 Onboarding Baseline Gate:** The cluster scheduler enforces `APPROVED_ONBOARDING_BASELINE = "0.0.1-alpha.6"` using full SemVer 2.0.0 precedence parsing (`semver` crate). Newly onboarding worker nodes joining the cluster below this version baseline are rejected with `FAILED_PRECONDITION` (`OnboardingVersionBelowBaseline`), while malformed versions return `INVALID_ARGUMENT`. Existing admitted members reconnecting below baseline are preserved and never evicted or force-upgraded. Admitted membership is durably persisted across control-plane restarts.
- **Administrator-Confirmed Historical Migration Inventory:** Historical Alpha.5 worker membership can be seeded at boot without forcing mass re-enrollment or fleet-wide updates by supplying an inventory file via `ANDROGRID_ADMISSION_INVENTORY` or `androgrid-data/admitted_nodes.inventory`. Configured inventory missing or commit errors abort startup immediately.

---

## Consequences

### Positive
- Completely eliminates unauthenticated LAN mTLS client certificate minting (`RSK-SEC-01`, `RSK-SEC-02`).
- Neutralizes brute-force attacks via per-session dynamic PIN rotation and per-IP rate limiting (`RSK-AUTH-01`).
- Mitigates Cross-Site Request Forgery (CSRF) via custom header validation.
- Preserves full automated provisioning for operators via pre-confirmed Tier 1 `AdminService` tokens.
- Reconciles Web UI network exposure with project zero-trust invariants.

### Trade-offs
- Operators utilizing the turnkey container must access container console logs or configure an administrative secret to confirm initial pairing sessions.
- Multi-host browser dashboard access requires setting up an external reverse proxy (e.g. Nginx, Caddy, or Cloudflare Tunnel) to supply TLS termination.

---

## Alternatives Considered
- **Plaintext LAN Pairing with Documented Residual Risk:** Rejected. Violates core architectural invariant `[INV-002]` requiring all non-loopback control plane communications to enforce mutual cryptographic verification and encryption.
- **Static Global Process-Lifetime PIN:** Rejected. Leaves the cluster vulnerable to dictionary attacks over the container lifetime and enables denial-of-service against legitimate operators through shared rate-limit windows.
- **Direct PIN Delivery in HTTP Response Payload:** Rejected. Exposing the confirmation PIN in the unauthenticated `POST /api/pair` JSON payload would allow any network client to self-confirm pairing sessions, entirely nullifying the confirmation gate.
