# ADR-013: Supported Backend Compiler Toolchain Pinning to Rust 1.100.1

## Status
Accepted

## Architectural Scope & Requirements
- **Goal Reference:** G-25, G-26
- **Traceability:** `[INV-001]`, `[INV-002]`, `[REQ-OP-001]`, `[REQ-VER-001]`, Gate L-02
- **Standard:** ISO/IEC/IEEE 29148

---

## Context
The AndroGrid backend declared a minimum supported Rust version (MSRV) of `1.82` in `Cargo.toml`. However, key direct and transitive production dependencies require higher compiler baselines:
1. `redb 2.6.4` (embedded MVCC database for durable node admission and Gate L-02) requires Rust 1.85 or later.
2. `time 0.3.55` requires Rust 1.88 or later.
3. `image 0.25.10` requires Rust 1.88 or later.

Attempting to enforce `rust-version = "1.82"` produces build failures during dependency resolution and crate compilation under older toolchains. Meanwhile, the project GitHub Actions continuous integration (CI) workflows execute using the standard Ubuntu environment compiler, `rustc 1.100.1 (ea983d5cf 2026-02-17)`.

The project requires an explicit architectural decision to formalize and pin the supported compiler toolchain rather than allowing silent divergence between repository manifests and CI runners.

---

## Decision
We standardize and pin the backend compiler toolchain baseline to **Rust 1.100.1**:

1. **Manifest Alignment:**
   - Update `rust-version = "1.100.1"` in `androgrid-backend/Cargo.toml`.
   - Ensure `Cargo.lock` remains committed and locked to reproducible dependency versions across development and CI environments.

2. **CI Toolchain Enforcement:**
   - Continuous integration jobs in `.github/workflows/ci.yml` strictly validate that builds, formatting checks (`cargo fmt`), linters (`cargo clippy`), and tests execute against Rust 1.100.1.

3. **Departure Scope:**
   - This departure is strictly confined to the backend control plane (`androgrid-backend`).
   - Android client toolchains continue to be governed by Android Gradle Plugin (AGP), Kotlin 2.0+, and Android NDK r26+ per existing architectural standards.

---

## Consequences
- **Positive:**
  - Full compatibility with modern zero-copy and embedded database dependencies, specifically `redb 2.6.4`.
  - Elimination of compiler version mismatch errors between local development workstations and CI runners.
  - Reproducible hermetic builds enforced by pinned compiler and locked crates.
- **Negative / Constraints:**
  - Operators compiling the backend from source must install Rust 1.100.1 or later via `rustup`.

---

## Requirement Traceability
- `[REQ-VER-001]`: Semantic versioning and toolchain compatibility guarantees.
- `[INV-001]`: Memory safety and strict type guarantees preserved across all control plane components.
- Gate L-02: Durable redb admission store integration validated on supported Rust toolchain.
