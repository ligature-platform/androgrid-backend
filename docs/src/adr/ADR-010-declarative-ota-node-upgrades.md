# ADR-010: Declarative Over-the-Air (OTA) Node Upgrades and Version Synchronization

## Status
Proposed

## Architectural Scope & Requirements
- Issue Reference: #42 ([RFC] Declarative Over-the-Air (OTA) Node Upgrades & Version Synchronization)
- Traceability: [REQ-OP-001], [REQ-OP-002], [REQ-OP-003], [REQ-OP-004], [INV-001], [INV-002], [INV-003], [ANTI-003], [NFR-POW-001], [NFR-SEC-001], [NFR-REL-001]
- Standard: ISO/IEC/IEEE 29148

---

## Context
Worker nodes run as distributed Android background services across heterogeneous mobile hardware (drawer phones, testbed rigs, field devices). In production deployments:
1. Devices do not expose listening server sockets or SSH endpoints ([INV-001]), preventing traditional push-based orchestrators (Ansible, SSH, push hooks).
2. Android APK binaries typically measure between 15 MB and 40 MB. Downloading payloads of this magnitude over metered cellular links saturates mobile data caps, incurs unexpected data charges, and drains battery by keeping cellular baseband radios active for extended periods, directly violating [ANTI-003] and [NFR-POW-001].
3. Unrooted consumer hardware requires explicit user confirmation via the Android `PackageInstaller` API, whereas rooted developer nodes or dedicated rack rigs can execute silent unattended updates via package manager shell commands.
4. Hardware-backed cryptographic keys generated during bootstrap enrollment inside the Android KeyStore ([INV-002], [NFR-SEC-001], ADR-009) must persist across application upgrades without triggering key invalidation or requiring re-pairing.
5. In unattended remote environments, failure modes must be strictly contained:
   - Process termination during package replacement must not orphan the node.
   - Non-retryable installation rejections (signature mismatch, downgrade rejection, corrupt archive) must not cause infinite download-and-fail loops that exhaust bandwidth and battery.
   - Control-plane restarts mid-canary rollout must not lose rollout state or blast the remaining fleet in a split-brain promotion.
   - Downloading an APK matching an operator-supplied SHA-256 hash does not prove signature compatibility with the installed package; executing an invalid APK could fail or break KeyStore continuity.

Prior to this decision, `UpgradeNodes` was limited to setting an ephemeral `desired_client_version` string on nodes, leaving binary distribution, integrity verification, rollout durability, terminal failure handling, process survival, and Android-side installation routing unspecified.

---

## Decision
We implement a comprehensive, declarative, and hardened Over-the-Air (OTA) Node Upgrade subsystem spanning the Host Control Plane and Android Worker nodes:

### 1. Protobuf Contract Extension (`NodeUpgradeDirective` & `LastUpgradeOutcome`)
We extend `androgrid/v1/orchestrator.proto` with explicit declarative upgrade directives and structured client feedback:
- `UpgradeNetworkPolicy`: specifies network interface restrictions (`UPGRADE_NETWORK_POLICY_WIFI_ONLY = 1` vs `UPGRADE_NETWORK_POLICY_ALLOW_CELLULAR = 2`).
- `UpgradeRolloutStrategy`: specifies rollout pacing (`UPGRADE_ROLLOUT_STRATEGY_IMMEDIATE = 1` vs `UPGRADE_ROLLOUT_STRATEGY_ROLLING = 2`).
- `NodeUpgradeDirective`: bundles `target_version`, `apk_url`, `apk_sha256`, `network_policy`, `rollout_strategy`, `upgrade_lease_timeout_seconds`, and `drain_before_upgrade`.
- `UpgradeInstallStatus`: structured outcome statuses (`UPGRADE_INSTALL_STATUS_UNSPECIFIED = 0`, `UPGRADE_INSTALL_STATUS_SUCCEEDED = 1`, `UPGRADE_INSTALL_STATUS_FAILED_TRANSIENT = 2`, `UPGRADE_INSTALL_STATUS_TERMINALLY_REJECTED = 3`).
- `LastUpgradeOutcome`: reports `target_version`, `apk_sha256`, `status`, `error_code`, `error_message`, and `attempt_count`.
- Bidirectional integration:
  - `NodeUpgradeDirective upgrade_directive` is attached to `SyncNodeStateResponse` (field 6) and `ClaimCellularTaskResponse` (field 4).
  - `LastUpgradeOutcome last_upgrade_outcome` is attached to `RegisterNodeRequest` (field 5), `SyncNodeStateRequest` (field 5), and `ClaimCellularTaskRequest` (field 8).
  - Dynamic client version reporting: `ClaimCellularTaskRequest` includes `client_version` (field 7) in parity with `RegisterNodeRequest` and `SyncNodeStateRequest`.
  - `UpgradeNodesRequest` carries `apk_url`, `apk_sha256`, `network_policy`, `rollout_strategy`, `rollout_percentage`, `lease_timeout_seconds`, and `drain_before_upgrade`.

### 2. Declarative Pull-Based Delivery ([INV-001])
- The control plane never initiates inbound connections to worker nodes.
- Workers poll the control plane via routine Wi-Fi declarative synchronization (`SyncNodeState`, 2.0s loop per [REQ-OP-002]) or unary cellular spot claims (`ClaimCellularTask` per [REQ-OP-003]).
- If an active upgrade directive targets the worker and meets transport policy constraints, the directive is attached to the synchronization response.

### 3. Deterministic Post-Install Process Survival & Lifecycle Revival
- When a node installs a package upgrade, Android's `PackageManagerService` terminates the existing worker process mid-execution. Spawning detached background subshells (e.g., `nohup sh -c ...`) is strictly rejected because Linux kernel cgroups bound to the app are SIGKILLed by `killProcessGroup` during package replacement.
- Deterministic process survival is guaranteed via the Android platform contract:
  - `PackageReplacedReceiver` is statically declared in `AndroidManifest.xml` listening for the system broadcast `android.intent.action.MY_PACKAGE_REPLACED`.
  - Android `ActivityManagerService` delivers this broadcast immediately after package replacement completes.
  - Upon receiving `MY_PACKAGE_REPLACED`, the receiver inspects `UpgradeLedger` to reconcile pending upgrades, checks `ClusterSettingsRepository`, and invokes `ContextCompat.startForegroundService(...)` when cluster participation is active.
  - OEM ROM Fallback: If `startForegroundService` throws `ForegroundServiceStartNotAllowedException` on Android 12-16 due to background start restrictions, the receiver immediately catches the exception and enqueues an expedited `PackageReplacedRecoveryWorker` via Jetpack WorkManager (`OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST`) to reliably bootstrap service recovery. Recovery attempts are capped at 3 runs.
  - API 28-30 Compatibility: `PackageReplacedRecoveryWorker` implements `getForegroundInfo()` to support foreground service execution across older API levels.
  - Battery Optimization Exemption: `AndroidManifest.xml` declares `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, and `UpgradeManager` verifies battery optimization exemption to prevent OEM sleep killing.
  - Jetpack WorkManager background spot workers resume automatically via their built-in SQLite job store.

### 4. Terminal Failure Reporting, Loop Prevention & Canary Promotion Halt
- The Android client maintains an on-device `UpgradeLedger` backed by `SharedPreferences` in `MODE_PRIVATE` with in-memory mutex synchronization (`synchronized` / `Mutex`), keyed by `(target_version, apk_sha256)`.
- Rejection classification:
  - Non-retryable errors (`INSTALL_FAILED_VERSION_DOWNGRADE`, `INSTALL_FAILED_UPDATE_INCOMPATIBLE`, `SIGNATURE_MISMATCH`, `CORRUPT_ARCHIVE`, `ABI_MISMATCH`) are marked `TERMINALLY_REJECTED`.
  - Once marked `TERMINALLY_REJECTED`, the client aborts immediately on subsequent directives for that digest without re-downloading bytes.
  - Transient failures (e.g., download timeout, temporary storage lock) are capped at a maximum of 3 attempts with exponential backoff (60s, 300s, 600s) before escalating to `TERMINALLY_REJECTED`.
  - WorkManager Backoff Coordination: `UpgradeManager` returns `BackoffSuppressed(remainingBackoffMs)` when an attempt is requested while an exponential backoff delay remains active. `UpgradeDownloadWorker` translates this into `Result.retry()` so WorkManager can cleanly back off rather than treating transient delays as permanent terminal failures.
- Control Plane Authentication & Canary Promotion Halt:
  - Outcome reports in `SyncNodeStateRequest` are authenticated against `session_token` prior to processing to prevent unauthenticated outcome spoofing.
  - When the control plane receives `TERMINALLY_REJECTED` in `last_upgrade_outcome`, `record_node_upgrade_failure` immediately clears the directive for that node, suppresses further directives, and marks the active rollout as `is_halted = true`.
  - Transient failures on canary nodes (`FailedTransient`) maintain the node in `in_flight_node_ids` without evicting it or clearing the worker directive, allowing client retries without stalling canary progression or prematurely halting the rollout.
  - Canary promotion in `promote_next_canary_if_ready` is suspended when `is_halted = true`, preventing faulty APK builds from advancing to subsequent cohorts.

### 5. Durable Rollout State & Control Plane Restart Reconciliation
- Unique Rollout File Keys: Active rollout descriptors (`rollout_id`, `target_version`, `apk_url`, `apk_sha256`, `network_policy`, `rollout_strategy`, `rollout_percentage`, `eligible_node_ids`, `in_flight_node_ids`, `completed_node_ids`, `failed_node_ids`, `is_halted`) are persisted to durable storage via `RolloutStore` prior to directive dispatch. Storage files and in-memory maps are keyed by `rollout_id` (`rollout_{sanitized_rollout_id}.json`) rather than `target_version`, preventing file collisions and state clobbering when multiple rollouts target the same version.
- Atomic File Persistence: `RolloutStore` writes state using a staging temporary file (`.tmp`), invokes `sync_all()` to ensure physical disk commit, and atomically replaces the primary file using `fs::rename`, preventing corruption across power failures or crashes.
- Upon orchestrator startup, `reconcile_rollouts_from_store` reloads persisted rollouts from disk and reconciles them against connecting worker registrations.
- Reconnect Staging Protection: On orchestrator startup and worker reconnection, `register_node_full` matches directives and desired versions strictly against `rollout.in_flight_node_ids.contains(&node_id)`. Staged or eligible nodes that have not yet been promoted do not receive premature directives, preserving canary pacing across orchestrator restarts. Furthermore, `drained_for_upgrade` is initialized from `matched_draining` so auto-undraining works correctly upon upgrade completion.
- Periodic Lease Sweeper: A background Tokio timer task sweeps timed-out upgrade leases periodically (every 2 seconds) via `sweep_timed_out_leases`, detecting stalled workers and halting canaries safely.
- Ground-truth evaluation prevents split-brain canary promotion:
  - In-flight nodes that have not yet reported `client_version == target_version` retain their in-flight status and do not trigger promotion of remaining staged nodes.
  - If any node in the active cohort failed terminally, the rollout remains halted across restarts until explicitly cleared or overridden by an operator.

### 6. Null-Safe Pre-Install Signing Certificate Lineage Verification & Security Hardening ([NFR-SEC-001])
- Relying solely on SHA-256 digest validation verifies download integrity but not cryptographic authenticity or signing compatibility.
- Format Validation: SHA-256 strings are validated against a strict 64-character hexadecimal pattern before processing. Plaintext HTTP URLs (`http://`) are strictly rejected; only secure HTTPS or relative cluster blob endpoints (`/v1/blobs/<sha256>`) are permitted.
- Endpoint Resolution: Relative `/v1/blobs/<sha256>` URLs are resolved dynamically against the worker's active cluster endpoint (`baseUrlProvider`), supporting zero-configuration deployments.
- Download Timeout & Safety: APK downloads enforce a 10-minute HTTP call timeout via `OkHttpClient` to prevent indefinite hangs over degraded links, and downloads enforce cluster TLS 1.3 with a 100 MB payload ceiling.
- Secure Staging: Downloaded APKs are stored in an isolated directory (`context.cacheDir/ota/`), rejecting any path traversal attempts.
- FileProvider Scoping: File sharing is restricted strictly to `<cache-path name="ota_apks" path="ota/" />` in `file_paths.xml`.
- Pre-Install Checks: Before invoking installation commands or prompting the user via `PackageInstaller`, `UpgradeManager` inspects the downloaded APK:
  - Reads package archive info using Android `PackageManager.GET_SIGNING_CERTIFICATES`.
  - Null check guard: If `getPackageArchiveInfo` returns `null` (indicating a truncated, corrupt, or unparseable archive), the download is treated as corrupt, the file is immediately purged from disk, and a `CORRUPT_ARCHIVE` terminal failure is recorded.
  - Package Name Matching: Verifies that the archive package name exactly matches `context.packageName`.
  - Monotonic Version Code: Verifies that the archive version code is greater than or equal to the installed version code, preventing silent downgrade failures.
  - Signing Lineage Check: `UpgradeManager` inspects both `apkContentsSigners` and `signingCertificateHistory` on API 28+, comparing SHA-256 digests against currently installed certificates. If either installed or archive certificates are null or empty, verification fails closed.
  - If signing certificates do not match or are missing, the APK is purged, preventing broken UID/KeyStore continuity ([INV-002]) and avoiding root execution of unauthorized binaries.

### 7. Drain-Before-Upgrade Guard & Worker Synchronization
- When `drain_before_upgrade` is set in the directive:
  - The control plane gates directive dispatch until the node reports zero `active_task_ids`.
  - On the client side, `WorkerForegroundService` and `WifiSyncTaskProcessor` activate an `isDrainingForUpgrade` barrier that rejects new task submissions and drains in-flight coroutines before executing the upgrade directive.
  - Two-Phase Queue Drain: Draining awaits completion of both `activeJobs` and `completedReports` queues before executing the upgrade directive, ensuring task execution reports are sent to the control plane before process replacement.
- Asynchronous Sync Loop Decoupling: In `WifiSyncTaskProcessor`, `applySyncResponse` dispatches upgrade processing in a decoupled background coroutine, preventing APK downloads from blocking the 2-second declarative synchronization heartbeat.
- Reliable Client Outcome Delivery: `sentOutcome` is staged in synchronization requests (`SyncNodeStateRequest` and `ClaimCellularTaskRequest`) and cleared from `UpgradeManager` only after verified request transmission, eliminating race conditions that could erase terminal failure reports.
- Unique Work Scheduling: `UpgradeDownloadWorker` uses `enqueueUniqueWork` with `ExistingWorkPolicy.KEEP` to prevent duplicate parallel downloads.

### 8. Root Installation & SELinux Stdin Streaming (`pm install -r -S`)
- Empirical hardware verification on physical Pixel hardware proved that path-based root execution (`su -c pm install -r <apkPath>`) fails when the APK resides in internal application storage (`/data/user/0/com.androgrid.worker/...`) because Android SELinux policy enforces `neverallow system_server app_data_file:file read` (`avc: denied` / `Error: Unable to open file`).
- To avoid copying binaries to insecure world-readable storage (`/sdcard/`), `UpgradeManager` streams the APK binary via standard input using exact byte length:
  `su -c "pm install -r -S <byteSize>"`
  piping bytes directly from internal storage through standard input.
- Monotonic Anti-Rollback: Production root execution strictly omits the `-d` downgrade flag, preserving platform anti-rollback enforcement.
- Process Deadlock & Timeout Prevention: Child process execution utilizes `redirectErrorStream(true)` and asynchronous stream draining via `Dispatchers.IO` to prevent OS pipe deadlocks. Stdin byte copying and stdout capture are wrapped in asynchronous coroutines bounded by a 120-second timeout with `destroyForcibly()` to guarantee runaway processes are cleaned up.
- Empirical hardware testing confirmed that stdin `-S` streaming succeeds with `Success` and zero SELinux denials.

### 9. Cellular Radio Protection & Asynchronous Download Decoupling ([ANTI-003], [NFR-POW-001], [INV-003])
- Default network policy is strictly `UPGRADE_NETWORK_POLICY_WIFI_ONLY`.
- Over metered cellular WAN, Wi-Fi-only directives are suppressed by the control plane.
- Spot-claim socket decoupling:
  - Under `UPGRADE_NETWORK_POLICY_ALLOW_CELLULAR`, `ClaimCellularTask` never downloads APK binaries inline on the spot lease channel.
  - The spot-claim mTLS gRPC channel is always torn down within the strict `< 200 ms` budget mandated by `[NFR-POW-001]`.
  - The cellular directive is handed off to `UpgradeDownloadWorker` via Jetpack WorkManager with constraints (`NetworkType.CONNECTED`, `BatteryNotLow`, `StorageNotLow`), decoupling binary transfer from short-lived spot task leases.

### 10. Operator CLI Surface (`androgrid-cli upgrade-nodes`)
- Flags: `--target-version`, `--apk-url`, `--apk-sha256`, `--network` (`wifi-only` or `allow-cellular`), `--strategy` (`immediate` or `rolling`), `--rollout-percentage`, `--lease-timeout-seconds`, `--drain`.
- Targets either an explicit `--node-group` or repeatable `--node-id` arguments.

---

## Consequences

### Positive
- Zero physical touch: Operators can declaratively roll out cluster-wide or group-specific APK upgrades without physical device access or manual ADB side-loading.
- Robust survival: Nodes automatically revive `WorkerForegroundService` after package manager kills via `MY_PACKAGE_REPLACED`, with WorkManager expedited fallback against OEM restrictions.
- SELinux compliant: Stdin `-S` streaming eliminates `app_data_file` denials without compromising storage isolation.
- Zero infinite loops: `UpgradeLedger` classifies terminal installation failures and suppresses repeated downloads.
- Automated canary blast-radius control: Broken builds halt canary promotion immediately on the control plane.
- Resilient control plane: Rollout descriptors survive orchestrator crashes and restarts without split-brain promotions via atomic disk persistence.
- Cryptographic safety: Signing lineage validation guarantees KeyStore continuity, fail-closed certificate extraction blocks foreign APK execution, and downloads enforce cluster TLS 1.3.
- Baseband radio protection: Ephemeral cellular spot sockets tear down within 200 ms; binary transfers are deferred to Wi-Fi or constrained background workers.
- Graceful drain: In-flight compute tasks complete without interruption prior to package replacement.

### Neutral / Constraints
- Unrooted consumer devices require user interaction to confirm package updates via system `PackageInstaller`.
- Storage directory for `RolloutStore` must be accessible on the host machine running `androgrid-backend`.

### Drawbacks & Mitigations
- Operator responsibility for signing: Operators must sign release APKs with keys matching the fleet's active keystore lineage. Mitigation: Client-side signing certificate check rejects mismatches before any installation attempt.

---

## Alternatives Considered
- **Subshell `nohup sh -c 'pm install ...'`:** Rejected because Android's `killProcessGroup` SIGKILLs all processes inside the app's Linux cgroup during package removal.
- **Path-Based Root Installation (`pm install -r <path>`):** Rejected because Android SELinux strictly forbids `system_server` from reading `app_data_file` paths under `/data/user/0/`, triggering `avc: denied` errors. Stdin `-S` streaming bypasses filesystem path traversal completely.
- **In-Memory Canary Tracking:** Rejected because control plane restarts caused split-brain rollout stalls or unexpected fleet-wide promotions.
- **Inline Binary Download in `ClaimCellularTask`:** Rejected because multi-megabyte transfers over the spot RPC channel violate the `< 200 ms` socket closure invariant `[NFR-POW-001]`.
- **Operator SHA-256 Digest Alone:** Rejected because SHA-256 alone does not verify APK signing certificate compatibility with installed KeyStore credentials.
