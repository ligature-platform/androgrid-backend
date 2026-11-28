# ADR-013: Supported Backend Compiler Toolchain Pinning to Rust 1.100.1

## Status
Accepted

## Architectural Scope & Requirements
- **Goal Reference:** G-25, G-26
- **Traceability:** `[REQ-OP-001]`, `[REQ-VER-001]`, `[NFR-REL-001]`, Gate L-02
- **Standard:** ISO/IEC/IEEE 29148

---

## Context
The AndroGrid backend declared a minimum supported Rust version (MSRV) of `1.82` in `Cargo.toml`. However, key direct and transitive production dependencies require higher compiler baselines:
1. `redb 2.6.4` (embedded MVCC database for durable node admission and Gate L-02) requires Rust 1.85 or later.
2. `time 0.3.55` requires Rust 1.88 or later.
3. `image 0.25.10` requires Rust 1.88 or later.

Attempting to enforce `rust-version = "1.82"` produces build failures during dependency resolution and crate compilation under older toolchains. Meanwhile, the project continuous integration (CI) workflows execute using `rustc 1.100.1 (20ddd0171 2026-11-25)`.

The project requires an explicit architectural decision to formalize and pin the supported compiler toolchain across local development, CI, and release builds.

---

## Decision
We standardize and pin the backend compiler toolchain baseline to **Rust 1.100.1**:

1. **Manifest and Toolchain File Alignment:**
   - Set `rust-version = "1.100.1"` in `androgrid-backend/Cargo.toml`.
   - Provide `rust-toolchain.toml` with `channel = "1.100.1"` to deterministically select the compiler on developer workstations and automated environments.
   - Maintain `Cargo.lock` committed and locked to reproducible dependency versions.

2. **CI Toolchain Enforcement:**
   - Continuous integration jobs in `.github/workflows/ci.yml` explicitly select Rust 1.100.1 (`toolchain: 1.100.1`), ensuring builds, formatting checks (`cargo fmt`), linters (`cargo clippy`), and test suites run on the pinned compiler version.

3. **Departure Scope:**
   - This departure is strictly confined to the backend control plane (`androgrid-backend`).
   - Android client toolchains continue to be governed by Android Gradle Plugin (AGP), Kotlin 2.0+, and Android NDK r26+ per existing architectural standards.

---

## Consequences
- **Positive:**
  - Full compatibility with modern zero-copy and embedded database dependencies, specifically `redb 2.6.4`.
  - Consistent compiler selection across local development environments and CI pipelines via `rust-toolchain.toml`.
  - Predictable dependency resolution using the committed lockfile.
- **Negative / Constraints:**
  - Operators compiling the backend from source must install Rust 1.100.1 or later via `rustup`.

---

## Requirement Traceability
- `[REQ-OP-001]`: Cluster onboarding and control-plane operation verified against the pinned compiler toolchain.
- `[REQ-VER-001]`: Compatible control-plane execution supporting mobile onboarding baseline enforcement.
- `[NFR-REL-001]`: Predictable control plane compilation and test execution.
- Gate L-02: Durable redb admission store integration validated on pinned Rust 1.100.1 toolchain.
