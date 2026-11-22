# ADR-010: Declarative Over-the-Air (OTA) Node Upgrades and Version Synchronization

## Status
Accepted

## Architectural Scope & Requirements
- Issue Reference: #42 ([RFC] Declarative Over-the-Air (OTA) Node Upgrades & Version Synchronization)
- Traceability: [REQ-OP-001], [REQ-OP-002], [INV-001], [INV-002], [INV-003], [ANTI-003], [NFR-POW-001], [NFR-SEC-001]
- Standard: ISO/IEC/IEEE 29148

---

## Context
Worker nodes run as distributed Android services across heterogeneous mobile hardware (drawer phones, testbed rigs, field devices). In production deployments:
1. Devices do not expose listening server sockets or SSH endpoints ([INV-001]), preventing traditional push-based orchestrators (Ansible, SSH, push hooks).
2. Android APK binaries typically measure between 15 MB and 40 MB. Downloading payloads of this magnitude over metered cellular links saturates mobile data caps, incurs unexpected data charges, and drains battery by keeping cellular baseband radios active for extended periods, directly violating [ANTI-003] and [NFR-POW-001].
3. Unrooted consumer hardware requires explicit user confirmation via the Android `PackageInstaller` API, whereas rooted developer nodes or dedicated rack rigs can execute silent unattended updates via package manager shell commands (`pm install -r`).
4. Hardware-backed cryptographic keys generated during bootstrap enrollment inside the Android KeyStore ([INV-002], [NFR-SEC-001], ADR-009) must persist across application upgrades without triggering key invalidation or requiring re-pairing.

Prior to this decision, `UpgradeNodes` was limited to setting a `desired_client_version` string on nodes, leaving binary distribution, integrity verification, rollout pacing, and Android-side installation routing unspecified.

---

## Decision
We implement a comprehensive declarative Over-the-Air (OTA) Node Upgrade subsystem spanning the Host Control Plane and Android Worker nodes:

1. **Protobuf Contract Extension (`NodeUpgradeDirective`):**
   - We extend `androgrid/v1/orchestrator.proto` with explicit declarative upgrade directives:
     - `UpgradeNetworkPolicy`: specifies network interface restrictions (`UPGRADE_NETWORK_POLICY_WIFI_ONLY = 1` vs `UPGRADE_NETWORK_POLICY_ALLOW_CELLULAR = 2`).
     - `UpgradeRolloutStrategy`: specifies rollout pacing (`UPGRADE_ROLLOUT_STRATEGY_IMMEDIATE = 1` vs `UPGRADE_ROLLOUT_STRATEGY_ROLLING = 2`).
     - `NodeUpgradeDirective`: bundles `target_version`, `apk_url`, `apk_sha256`, `network_policy`, `rollout_strategy`, `upgrade_lease_timeout_seconds`, and `drain_before_upgrade`.
   - Embed `NodeUpgradeDirective upgrade_directive` within `SyncNodeStateResponse` (field 6) and `ClaimCellularTaskResponse` (field 4).
   - Extend `UpgradeNodesRequest` with binary distribution parameters (`apk_url`, `apk_sha256`, `network_policy`, `rollout_strategy`, `rollout_percentage`, `lease_timeout_seconds`).

2. **Declarative Pull-Based Delivery ([INV-001]):**
   - The control plane never initiates inbound connections to worker nodes.
   - Workers query the control plane via routine Wi-Fi declarative synchronization (`SyncNodeState`, 2.0s loop per [REQ-OP-002]) or unary cellular spot claims (`ClaimCellularTask` per [REQ-OP-003]).
   - If an active upgrade directive targets the worker and meets transport policy constraints, the directive is attached to the response.

3. **Cellular Radio & Metered Network Protection ([ANTI-003], [NFR-POW-001], [INV-003]):**
   - Default network policy is strictly `UPGRADE_NETWORK_POLICY_WIFI_ONLY`.
   - When a worker connects over metered cellular WAN, the control plane suppresses Wi-Fi-only upgrade directives in both `SyncNodeStateResponse` and `ClaimCellularTaskResponse`.
   - Only when an operator explicitly sets `network_policy = UPGRADE_NETWORK_POLICY_ALLOW_CELLULAR` will the orchestrator serve directives to cellular connections.
   - On the client side, `UpgradeManager` double-checks current network meter status via `ConnectivityManager.isActiveNetworkMetered` and aborts if policy constraints are violated.

4. **Rollout Strategies & State Machine Coordination:**
   - `IMMEDIATE`: All eligible target nodes immediately receive the upgrade directive.
   - `ROLLING`: Canary rollout parameterized by `rollout_percentage` (1% to 100%). The orchestrator calculates the initial canary batch size (`ceil(nodes * pct / 100)`), applies directives to the canary cohort, and holds the remaining nodes in pending state.
   - When upgraded canary nodes reconnect and register with `client_version == target_version` ([REQ-OP-001]), the state machine registers completion, clears the directive, undrains the worker (if drained for upgrade), and automatically promotes subsequent canary cohorts.
   - Upgrade leases are guarded by `upgrade_lease_timeout_seconds` (default 600s). If a node fails to complete the upgrade within the lease window, the lease expires and can be re-dispatched.

5. **Cryptographic Binary Integrity ([NFR-SEC-001]):**
   - The operator supplies an authoritative SHA-256 digest (`apk_sha256`, 64 hex characters) at command invocation.
   - Upon completing the APK download, `UpgradeManager` calculates the SHA-256 hash of the local file before passing it to any installer. If the digest mismatches, the downloaded file is purged and the upgrade aborts.

6. **Heterogeneous Android Installation Routing:**
   - Root Shell (`is_rooted == true`): executes `su -c pm install -r <apkPath>` for silent unattended upgrade in automated testbeds or server-rack Android clusters.
   - Unrooted / Consumer Hardware: launches the system `PackageInstaller` session or `Intent.ACTION_VIEW` / `Intent.ACTION_INSTALL_PACKAGE` with `FLAG_GRANT_READ_URI_PERMISSION`, prompting the user to accept the update while keeping app sandbox data intact.
   - KeyStore Persistence: Android OS package replacement (`pm install -r` or `PackageInstaller`) preserves the application UID and internal data directory (`/data/data/com.androgrid.worker/`), guaranteeing that hardware-backed Android KeyStore private keys and credentials remain intact without re-pairing.

7. **Operator CLI Surface (`androgrid-cli upgrade-nodes`):**
   - Flags: `--target-version`, `--apk-url`, `--apk-sha256`, `--network` (`wifi-only` or `allow-cellular`), `--strategy` (`immediate` or `rolling`), `--rollout-percentage`, `--lease-timeout-seconds`, `--drain`.
   - Targets either an explicit `--node-group` or repeatable `--node-id` arguments.

---

## Consequences

### Positive
- Operators can declaratively roll out cluster-wide or group-specific APK upgrades without physical device access or manual ADB side-loading.
- Metered cellular connections and mobile battery radios remain protected against inadvertent multi-megabyte binary downloads.
- Hardware-backed enrollment keys and mTLS identities survive seamless node upgrades.
- Canary rolling upgrades limit blast radius of faulty APK builds.

### Drawbacks & Blast Radius
- Unrooted consumer devices require user interaction to confirm package updates.
- In-memory canary tracking state does not survive orchestrator restarts until persistent storage is added.
- Requires coordinated schema synchronization across Rust control plane and Android Kotlin codebase.

---

## Alternatives Considered
- **Inbound SSH or ADB Daemon over Wi-Fi:** Rejected because binding listening ports violates [INV-001] (Zero Inbound Mobile Ports) and increases attack surface.
- **Downloading APK over gRPC Streaming:** Rejected in favor of HTTP/HTTPS and content-addressed blob retrieval to avoid saturating gRPC control plane framing and multiplexing limits.
- **Silent Updates on Unrooted Hardware:** Rejected because Android security sandboxing strictly forbids third-party apps from silently installing packages without Device Owner (MDM) enrollment or system platform signatures.
