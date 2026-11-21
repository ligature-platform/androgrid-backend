# ADR-009: Android KeyStore Hardware Attestation Chain Verification

## Status
Accepted

## Architectural Scope & Requirements
- Issue Reference: #47 (feat(security): verify Android KeyStore hardware attestation chain during worker enrollment)
- Traceability: [INV-001], [INV-002], [NFR-SEC-001], [REQ-OP-001]
- Standard: ISO/IEC/IEEE 29148

---

## Context
During initial device onboarding, mobile worker nodes invoke the `EnrollWorker` RPC on the bootstrap listener, exchanging an ephemeral pairing token and PKCS#10 Certificate Signing Request (CSR) for a signed internal client certificate (`[INV-002]`, `[NFR-SEC-001]`, `[REQ-OP-001]`).

Prior to this decision, the orchestrator evaluated the validity of the pairing token and verified that the CSR Common Name (CN) matched the target `node_id`. However, the orchestrator did not cryptographically verify the hardware origin of the submitted keypair. Consequently, a compromised environment or software emulator could submit software-generated private keys, precluding the control plane from distinguishing between genuine hardware-isolated Android KeyStore keys (residing inside a Trusted Execution Environment or StrongBox) and software-emulated keys.

---

## Decision
We introduce an Android KeyStore Hardware Attestation verification engine and protocol extension focused strictly on enrollment-time hardware key generation (HardwareKeyOnly scope):

1. **Protobuf Contract Extension (`[INV-001]`, `[INV-002]`):**
   - Extend `EnrollWorkerRequest` in `orchestrator.proto` with an optional backwards-compatible field:
     `repeated string attestation_certificate_chain_pem = 4;`
   - Workers submit their Android KeyStore certificate chain (ordered leaf first, root last) along with the CSR during bootstrap enrollment.

2. **Google Hardware Attestation Root CA Trust Anchoring (`[INV-002]`, `[NFR-SEC-001]`):**
   - The orchestrator validates the cryptographic signature path of the attestation certificate chain up to official Google Hardware Attestation Root CAs (including RSA 4096-bit and ECDSA P-384 root anchors).
   - In private, staging, or lab environments, custom trust anchors can be configured to facilitate hermetic testing via `with_exclusive_custom_roots`.

3. **RFC 5280 Path Validation & Anti-Forgery Constraints:**
   - Enforce `BasicConstraints.cA == true` and `KeyUsage::keyCertSign` on all intermediate certificates.
   - Enforce Google attestation extension ordering: OID `1.3.6.1.4.1.11129.2.1.17` must exist solely on the leaf certificate (index 0) and is prohibited on any intermediate CA.
   - Verify that outer certificate `signatureAlgorithm` matches inner `tbsCertificate.signature` to prevent algorithm substitution attacks.

4. **KeyDescription ASN.1 Inspection (`1.3.6.1.4.1.11129.2.1.17`):**
   - The leaf attestation certificate must contain the standard Android Keymaster / KeyMint KeyDescription extension.
   - The orchestrator asserts that both `attestationSecurityLevel` and `keymasterSecurityLevel` are strictly hardware-backed (`TrustedEnvironment` or `StrongBox`).
   - Parses `hardwareEnforced` `AuthorizationList` for `KM_TAG_ORIGIN [702] == 0` (`KM_ORIGIN_GENERATED`) to guarantee the keypair was generated within hardware and not imported from software.
   - Device bootloader lock status (`deviceLocked`) and verified boot state (`verifiedBootState`) are preserved without hard rejection, ensuring drawer smartphones, developer test hardware, and custom ROMs (such as LineageOS) remain compatible with cluster economics.

5. **Cryptographic Public Key Binding:**
   - The orchestrator extracts the `SubjectPublicKeyInfo` (SPKI) from the attestation leaf certificate and compares it byte-for-byte against the public key extracted from the submitted CSR.
   - If the public keys do not match, enrollment is immediately rejected to prevent attestation forwarding attacks.

6. **Staged Challenge Nonce Support (`ANDROGRID_REQUIRE_ATTESTATION_CHALLENGE`):**
   - Attestation challenge verification supports staged rollout via `require_attestation_challenge`. When enabled, `attestationChallenge` is verified against `SHA-256(pairing_token || node_id)`. When disabled, challenge verification logs a diagnostic notice for legacy client compatibility.

7. **Pre-Authentication DoS Protection & Input Bounding:**
   - Attestation parsing and cryptographic verification execute inside `token_store.redeem_with` only after token validation and rate limiting succeed.
   - Imposes strict bounds on incoming attestation chains: maximum 6 certificates and maximum 32 KiB total PEM bytes.

8. **Cluster Security Policy Enforcement (`ANDROGRID_ENFORCE_HARDWARE_ATTESTATION`):**
   - `ClusterConfig` introduces `enforce_hardware_attestation: bool` (configurable via environment variable `ANDROGRID_ENFORCE_HARDWARE_ATTESTATION`).
   - When enforcement is enabled, enrollment requests lacking a valid, hardware-backed attestation chain are rejected with descriptive diagnostics, while unredeemed pairing tokens remain unburned for legitimate retry attempts.

---

## Consequences

### Positive
- Prevents software emulators and imported software keys from enrolling in clusters enforcing hardware backing.
- Cryptographically verifies that client private keys were generated inside hardware modules (TEE/StrongBox).
- Preserves full support for repurposed drawer smartphones and custom ROMs.
- Protected against pre-authentication CPU exhaustion and leaf-as-CA certificate forgery.
- Fully backwards-compatible with existing development workflows and non-enforced clusters.

### Drawbacks & Blast Radius
- Emulators and development handsets without hardware TEE/StrongBox support cannot enroll when hardware attestation enforcement is active.
- Certificate chain parsing and signature verification add cryptographic compute overhead during the single-use bootstrap enrollment phase (amortized over the multi-month certificate lifetime).

---

## Alternatives Considered
- **In-App Attestation Verification Only:** Rejected because local on-device verification on rooted or compromised devices can be spoofed or bypassed.
- **SafetyNet / Play Integrity API Instead of Key Attestation:** Rejected because Play Integrity requires external Google cloud round-trips and Google Play Services, violating offline, on-premise, and air-gapped cluster operation constraints.
- **Mandatory Bootloader Lock and Verified Boot State:** Rejected for default policy because it would disqualify developer devices and repurposed drawer hardware running community Android builds.
- **Attestation Enforcement on Certificate Renewal in PR #64:** Deferred to a dedicated follow-up issue to isolate PR scope and maintain protocol contract boundaries.
