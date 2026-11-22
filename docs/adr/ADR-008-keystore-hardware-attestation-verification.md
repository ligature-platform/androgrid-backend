# ADR-008 (Obsolete / Superseded): Android KeyStore Hardware Attestation Chain Verification

## Status
Obsolete / Superseded by [ADR-009: Android KeyStore Hardware Attestation Chain Verification](ADR-009-keystore-hardware-attestation-verification.md)

## Context
During initial development of hardware attestation chain verification, this document was drafted under the identifier ADR-008. However, ADR-008 was concurrently assigned to `ADR-008-dual-plane-mtls-blob-distribution.md` (Dual-Plane mTLS Data Architecture for Ephemeral Blob Distribution).

## Decision
This ADR identifier is marked Obsolete / Superseded. The active and normative Architecture Decision Record governing Android KeyStore hardware attestation chain verification is recorded in:
- [ADR-009: Android KeyStore Hardware Attestation Chain Verification](ADR-009-keystore-hardware-attestation-verification.md)

## Consequences
- Preserves chronological sequence and prevents identifier collision with Dual-Plane mTLS Data Architecture (`ADR-008`).
- All architectural invariants ([INV-001], [INV-002]) and security requirements ([NFR-SEC-001], [REQ-OP-001]) are traced and maintained in ADR-009.
