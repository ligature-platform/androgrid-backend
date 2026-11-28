//! Core in-memory cluster scheduler and atomic state machine.
//!
//! Traces to: AG-SPEC-2026-V2 Section 2.2, Section 3.1, Section 5.1, Section 6.2,
//! [REQ-OP-001], [REQ-OP-002], [REQ-OP-003], [REQ-OP-004],
//! [INV-004], [INV-005], [INV-006], [ANTI-003], [NFR-REL-001]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tracing::debug;

use crate::scheduler::errors::SchedulingError;
use crate::scheduler::state::{
    NodeGroupRecord, TaskExecutionResult, TaskGroupRecord, TaskRecord, UpgradeRolloutRecord,
    WorkerRecord,
};
use crate::scheduler::thermal::{ThermalAction, ThermalPolicy};
use crate::{
    AssignNodesToGroupRequest, AssignNodesToGroupResponse, CancelTaskGroupResponse,
    ClaimCellularTaskResponse, CreateNodeGroupRequest, CreateNodeGroupResponse, DrainNodesRequest,
    DrainNodesResponse, ExecutionEngine, GetTaskGroupStatusResponse, NetworkEgressPolicy,
    NetworkTransportType, NodeCapabilities, NodeGroup, NodeUpgradeDirective, RegisterNodeResponse,
    ReplaceStrategy, ReplaceTaskGroupRequest, ReplaceTaskGroupResponse,
    SubmitCellularResultResponse, SubmitTaskGroupResponse, SyncNodeStateResponse,
    TaskExecutionReport, TaskGroupSpec, TaskGroupState, TaskGroupSummary, TaskPartitionSpec,
    TaskSpec, TaskState, TaskTemplate, UpdateNodeGroupRequest, UpdateNodeGroupResponse,
    UpgradeNetworkPolicy, UpgradeNodesRequest, UpgradeNodesResponse, UpgradeRolloutStrategy,
};

/// Maximum number of partitions allowed in a single TaskGroup submission or replacement.
pub const MAX_GROUP_PARTITIONS: usize = 1000;

/// Maximum number of NodeGroups allowed in the cluster registry.
/// Traces to: [REQ-OP-001], [NFR-PERF-001]
pub const MAX_NODE_GROUPS: usize = 256;

/// Maximum number of labels or selector entries per worker or NodeGroup.
/// Traces to: [REQ-OP-001], [NFR-PERF-001]
pub const MAX_GROUP_LABELS: usize = 32;

/// Maximum number of node IDs accepted in a single batch assignment/drain/upgrade call.
/// Traces to: [REQ-OP-001], [NFR-PERF-001]
pub const MAX_ASSIGN_NODES_BATCH: usize = 1000;

/// Default maximum allowable task duration on cellular spot connections (180 seconds).
/// Traces to: [INV-005], [ANTI-003]
pub const MAX_CELLULAR_DURATION_SECONDS: u32 = 180;

/// Minimum battery level percentage required for cellular task claims when not charging.
/// Traces to: [REQ-OP-003]
pub const MIN_CELLULAR_BATTERY_PCT: u32 = 20;

/// Default lease timeout in seconds for node registration.
pub const DEFAULT_NODE_LEASE_TIMEOUT_SECONDS: u32 = 10;

/// Default heartbeat interval in seconds for Wi-Fi synchronization loop.
pub const DEFAULT_HEARTBEAT_INTERVAL_SECONDS: u32 = 2;

/// Thread-safe in-memory cluster scheduler.
#[derive(Debug, Clone)]
pub struct ClusterScheduler {
    inner: Arc<RwLock<SchedulerInner>>,
    event_sender: tokio::sync::broadcast::Sender<crate::observability::ClusterEvent>,
    rollout_store: Arc<crate::scheduler::rollout_store::RolloutStore>,
    admission_store: Arc<crate::scheduler::admission_store::DurableAdmissionStore>,
}

/// Canonical approved onboarding version baseline.
///
/// Any newly joining worker node reporting a client version lower than this baseline
/// is refused admission and blocked from receiving compute work until upgraded.
/// Existing already-admitted workers reconnecting are preserved without forced upgrade.
///
/// Traces to: [REQ-VER-001], [REQ-OP-001], Gate L-02
pub const APPROVED_ONBOARDING_BASELINE: &str = "0.0.1-alpha.6";

/// Parses a client version string into a SemVer 2.0.0 Version.
///
/// Strips leading 'v' or 'V' prefixes and whitespace. Rejects malformed version strings.
/// Traces to: [REQ-VER-001]
pub fn parse_client_version(v: &str) -> Result<semver::Version, SchedulingError> {
    let trimmed = v.trim().trim_start_matches(|c| c == 'v' || c == 'V');
    semver::Version::parse(trimmed).map_err(|e| {
        SchedulingError::InvalidClientVersion(format!("Invalid SemVer client version '{v}': {e}"))
    })
}

/// Compares two client version strings according to SemVer 2.0.0 precedence rules.
///
/// Build metadata (+...) is ignored during precedence comparison as per SemVer 2.0.0 Section 10.
/// Traces to: [REQ-VER-001]
pub fn compare_client_versions(v1: &str, v2: &str) -> Result<std::cmp::Ordering, SchedulingError> {
    let mut p1 = parse_client_version(v1)?;
    let mut p2 = parse_client_version(v2)?;
    // SemVer 2.0.0 Section 10: Build metadata MUST be ignored when determining version precedence
    p1.build = semver::BuildMetadata::EMPTY;
    p2.build = semver::BuildMetadata::EMPTY;
    Ok(p1.cmp(&p2))
}

impl Default for ClusterScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
struct SchedulerInner {
    tasks: HashMap<String, TaskRecord>,
    workers: HashMap<String, WorkerRecord>,
    groups: HashMap<String, TaskGroupRecord>,
    node_groups: HashMap<String, NodeGroupRecord>,
    pending_cancellations: HashMap<String, Vec<String>>,
    active_rollouts: HashMap<String, UpgradeRolloutRecord>,
    allow_insecure_root_tasks: bool,
    thermal_policy: ThermalPolicy,
}

impl ClusterScheduler {
    /// Creates a new cluster scheduler with default safety parameters.
    pub fn new() -> Self {
        Self::with_options(false, ThermalPolicy::default())
    }

    /// Creates a cluster scheduler with explicit insecure root task permission and thermal policy.
    ///
    /// Traces to: [INV-006], [NFR-POW-001]
    pub fn with_options(allow_insecure_root_tasks: bool, thermal_policy: ThermalPolicy) -> Self {
        Self::with_options_and_stores(
            allow_insecure_root_tasks,
            thermal_policy,
            Arc::new(crate::scheduler::rollout_store::RolloutStore::new()),
            Arc::new(crate::scheduler::admission_store::DurableAdmissionStore::new_in_memory()),
        )
    }

    /// Creates a cluster scheduler with a dedicated durable rollout store.
    ///
    /// Traces to: ADR-010, [REQ-OP-001], [REQ-OP-002]
    pub fn with_rollout_store(
        rollout_store: Arc<crate::scheduler::rollout_store::RolloutStore>,
    ) -> Self {
        Self::with_options_and_stores(
            false,
            ThermalPolicy::default(),
            rollout_store,
            Arc::new(crate::scheduler::admission_store::DurableAdmissionStore::new_in_memory()),
        )
    }

    /// Creates a cluster scheduler with explicit options and a dedicated durable rollout store.
    ///
    /// Traces to: ADR-010, [INV-006], [REQ-OP-001], [REQ-OP-002]
    pub fn with_options_and_store(
        allow_insecure_root_tasks: bool,
        thermal_policy: ThermalPolicy,
        rollout_store: Arc<crate::scheduler::rollout_store::RolloutStore>,
    ) -> Self {
        Self::with_options_and_stores(
            allow_insecure_root_tasks,
            thermal_policy,
            rollout_store,
            Arc::new(crate::scheduler::admission_store::DurableAdmissionStore::new_in_memory()),
        )
    }

    /// Creates a cluster scheduler with explicit options, rollout store, and durable admission store.
    ///
    /// Traces to: ADR-010, ADR-012, [INV-002], [REQ-OP-001], [REQ-VER-001], Gate L-02
    pub fn with_options_and_stores(
        allow_insecure_root_tasks: bool,
        thermal_policy: ThermalPolicy,
        rollout_store: Arc<crate::scheduler::rollout_store::RolloutStore>,
        admission_store: Arc<crate::scheduler::admission_store::DurableAdmissionStore>,
    ) -> Self {
        let (event_sender, _) = tokio::sync::broadcast::channel(1024);
        Self {
            inner: Arc::new(RwLock::new(SchedulerInner {
                tasks: HashMap::new(),
                workers: HashMap::new(),
                groups: HashMap::new(),
                node_groups: HashMap::new(),
                pending_cancellations: HashMap::new(),
                active_rollouts: HashMap::new(),
                allow_insecure_root_tasks,
                thermal_policy,
            })),
            event_sender,
            rollout_store,
            admission_store,
        }
    }

    /// Checks if a node_id was already admitted to this cluster.
    pub fn is_node_admitted(&self, node_id: &str) -> bool {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        inner.workers.contains_key(node_id) || self.admission_store.is_admitted(node_id)
    }

    /// Returns a reference to the durable admission store.
    pub fn admission_store(
        &self,
    ) -> &Arc<crate::scheduler::admission_store::DurableAdmissionStore> {
        &self.admission_store
    }

    /// Manually marks a node_id as admitted (used in test fixtures and seed data).
    pub fn mark_node_admitted(&self, node_id: &str) {
        let _ = self.admission_store.commit_admission(
            node_id,
            APPROVED_ONBOARDING_BASELINE,
            0,
            crate::scheduler::admission_store::AdmissionSource::AdminSeeded,
        );
    }

    /// Subscribes to real-time cluster broadcast events.
    ///
    /// Traces to: [INV-004], [INV-005], [NFR-REL-001]
    pub fn subscribe_events(
        &self,
    ) -> tokio::sync::broadcast::Receiver<crate::observability::ClusterEvent> {
        self.event_sender.subscribe()
    }

    /// Emits a cluster state transition event to active subscribers.
    ///
    /// Traces to: [INV-004], [INV-005], [NFR-REL-001]
    pub fn emit_event(&self, event: crate::observability::ClusterEvent) {
        let _ = self.event_sender.send(event);
    }

    /// Returns whether scheduling of insecure root shell tasks is allowed.
    pub fn allow_insecure_root_tasks(&self) -> bool {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        inner.allow_insecure_root_tasks
    }

    /// Configures permission for insecure root shell tasks.
    pub fn set_allow_insecure_root_tasks(&self, allow: bool) {
        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        inner.allow_insecure_root_tasks = allow;
    }

    /// Returns the active thermal policy.
    pub fn thermal_policy(&self) -> ThermalPolicy {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        inner.thermal_policy
    }

    /// Updates the active thermal policy.
    pub fn set_thermal_policy(&self, policy: ThermalPolicy) {
        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        inner.thermal_policy = policy;
    }

    /// Registers an Android worker node without custom labels.
    ///
    /// Traces to: [REQ-OP-001], [INV-006], [REQ-VER-002]
    pub fn register_node(
        &self,
        node_id: String,
        capabilities: NodeCapabilities,
        client_version: String,
        now_epoch_ms: u64,
    ) -> Result<RegisterNodeResponse, SchedulingError> {
        self.register_node_with_labels(
            node_id,
            capabilities,
            client_version,
            HashMap::new(),
            now_epoch_ms,
        )
    }

    /// Registers an Android worker node with operator/device labels, enforcing root capabilities
    /// and preserving control-plane group/drain/upgrade state across reconnections.
    ///
    /// Traces to: [REQ-OP-001], [INV-006], [REQ-VER-002]
    pub fn register_node_with_labels(
        &self,
        node_id: String,
        capabilities: NodeCapabilities,
        client_version: String,
        labels: HashMap<String, String>,
        now_epoch_ms: u64,
    ) -> Result<RegisterNodeResponse, SchedulingError> {
        self.register_node_full(
            node_id,
            capabilities,
            client_version,
            labels,
            None,
            now_epoch_ms,
        )
    }

    /// Registers an Android worker node with full upgrade outcome feedback, enforcing root capabilities
    /// and preserving control-plane group/drain/upgrade state across reconnections.
    ///
    /// Traces to: ADR-010, [REQ-OP-001], [INV-006], [REQ-VER-002]
    pub fn register_node_full(
        &self,
        node_id: String,
        mut capabilities: NodeCapabilities,
        client_version: String,
        labels: HashMap<String, String>,
        last_upgrade_outcome: Option<crate::proto::androgrid::v1::LastUpgradeOutcome>,
        now_epoch_ms: u64,
    ) -> Result<RegisterNodeResponse, SchedulingError> {
        if node_id.is_empty()
            || node_id.len() > 128
            || !node_id.bytes().all(|b| (0x21..=0x7E).contains(&b))
        {
            return Err(SchedulingError::InvalidNodeGroupRequest(
                "node_id must be 1..=128 printable non-whitespace ASCII chars".to_string(),
            ));
        }
        if client_version.is_empty()
            || client_version.len() > 128
            || !client_version.bytes().all(|b| (0x21..=0x7E).contains(&b))
        {
            return Err(SchedulingError::InvalidNodeGroupRequest(
                "client_version must be 1..=128 printable non-whitespace ASCII chars".to_string(),
            ));
        }
        let validated_labels = validate_labels(&labels, false)?;
        let mut inner = self.inner.write().expect("RwLock write lock poisoned");

        // Enforce onboarding version baseline gate: newly joining workers must meet or exceed APPROVED_ONBOARDING_BASELINE.
        // Existing members reconnecting are preserved without forced upgrade or eviction.
        // Traces to: [REQ-VER-001], [REQ-OP-001], Gate L-02
        let is_existing_member =
            inner.workers.contains_key(&node_id) || self.admission_store.is_admitted(&node_id);
        if !is_existing_member {
            let ordering = compare_client_versions(&client_version, APPROVED_ONBOARDING_BASELINE)?;
            if ordering == std::cmp::Ordering::Less {
                tracing::warn!(
                    node_id = %node_id,
                    client_version = %client_version,
                    baseline = %APPROVED_ONBOARDING_BASELINE,
                    "Refusing admission to new node below baseline version"
                );
                return Err(SchedulingError::OnboardingVersionBelowBaseline {
                    client_version,
                    min_version: APPROVED_ONBOARDING_BASELINE.to_string(),
                });
            }
            // Commit to durable admission store OUTSIDE the scheduler's central write lock
            drop(inner);
            self.admission_store.commit_admission(
                &node_id,
                &client_version,
                now_epoch_ms,
                crate::scheduler::admission_store::AdmissionSource::FreshOnboarded,
            )?;
            inner = self.inner.write().expect("RwLock write lock poisoned");
        } else if !self.admission_store.is_admitted(&node_id) {
            drop(inner);
            let _ = self.admission_store.commit_admission(
                &node_id,
                &client_version,
                now_epoch_ms,
                crate::scheduler::admission_store::AdmissionSource::FreshOnboarded,
            );
            inner = self.inner.write().expect("RwLock write lock poisoned");
        }

        // Enforce [INV-006]: If device is unrooted, filter supported engines to exclude RootShell
        if !capabilities.is_rooted {
            capabilities
                .supported_engines
                .retain(|&e| e != ExecutionEngine::RootShell as i32);
            if !capabilities
                .supported_engines
                .contains(&(ExecutionEngine::WasmWasi as i32))
            {
                capabilities
                    .supported_engines
                    .push(ExecutionEngine::WasmWasi as i32);
            }
        }

        let session_token = format!("session-{}-{}", node_id, now_epoch_ms);

        let battery_temperature_celsius = capabilities.battery_temperature_celsius;
        let thermal_status = capabilities.thermal_status;

        let (
            explicit_node_group,
            draining,
            drained_for_upgrade,
            active_task_ids,
            desired_client_version,
            upgrade_directive,
            upgrade_lease_deadline_ms,
            upgrade_completed,
        ) = if let Some(existing) = inner.workers.get(&node_id) {
            let (next_desired, upgrade_completed) = match existing.desired_client_version.as_deref()
            {
                Some(target) if target == client_version => (None, true),
                Some(target) => (Some(target.to_string()), false),
                None => (None, false),
            };
            let (next_draining, next_drained_for_upgrade) =
                if upgrade_completed && existing.drained_for_upgrade {
                    (false, false)
                } else {
                    (existing.draining, existing.drained_for_upgrade)
                };
            let (next_directive, next_deadline) = if upgrade_completed {
                (None, 0)
            } else {
                (
                    existing.upgrade_directive.clone(),
                    existing.upgrade_lease_deadline_ms,
                )
            };
            (
                existing.explicit_node_group.clone(),
                next_draining,
                next_drained_for_upgrade,
                existing.active_task_ids.clone(),
                next_desired,
                next_directive,
                next_deadline,
                upgrade_completed,
            )
        } else {
            let pre_pinned = inner
                .node_groups
                .iter()
                .find(|(_, grp)| grp.member_node_ids.contains(&node_id))
                .map(|(gid, _)| gid.clone());

            let mut matched_desired = None;
            let mut matched_directive = None;
            let mut matched_completed = false;
            let mut matched_draining = false;
            let mut matched_deadline = 0;

            for rollout in inner.active_rollouts.values() {
                let is_member = rollout.in_flight_node_ids.contains(&node_id)
                    || rollout.staged_node_ids.contains(&node_id)
                    || rollout.eligible_node_ids.contains(&node_id);

                if is_member && rollout.target_version == client_version {
                    matched_completed = true;
                    break;
                }

                // Hydrate upgrade directive ONLY for actively in-flight nodes to prevent
                // staged nodes from bypassing canary percentage on control-plane restart.
                if rollout.in_flight_node_ids.contains(&node_id) && !rollout.is_halted {
                    matched_desired = Some(rollout.target_version.clone());
                    matched_directive = Some(rollout.directive_template.clone());
                    matched_draining = rollout.drain_before_upgrade;
                    matched_deadline = now_epoch_ms + (rollout.lease_timeout_seconds as u64 * 1000);
                    break;
                }
            }

            (
                pre_pinned,
                matched_draining,
                matched_draining,
                Vec::new(),
                matched_desired,
                matched_directive,
                matched_deadline,
                matched_completed,
            )
        };

        let worker = WorkerRecord {
            node_id: node_id.clone(),
            capabilities,
            session_token: session_token.clone(),
            client_version,
            battery_level_pct: 100,
            is_charging: true,
            battery_temperature_celsius,
            thermal_status,
            last_seen_epoch_ms: now_epoch_ms,
            active_task_ids,
            labels: validated_labels,
            explicit_node_group,
            draining,
            drained_for_upgrade,
            desired_client_version,
            upgrade_directive,
            upgrade_lease_deadline_ms,
        };

        let transport_str = if worker.capabilities.current_transport
            == NetworkTransportType::NetworkTransportWifiLan as i32
        {
            "Wi-Fi LAN".to_string()
        } else {
            "Cellular WAN".to_string()
        };

        let reg_event = crate::observability::ClusterEvent::NodeRegistered {
            node_id: worker.node_id.clone(),
            transport: transport_str,
            is_rooted: worker.capabilities.is_rooted,
            battery_pct: worker.battery_level_pct,
            is_charging: worker.is_charging,
            thermal_status: worker.thermal_status,
            cpu_cores: worker.capabilities.cpu_cores,
            ram_mb: worker.capabilities.total_ram_bytes / (1024 * 1024),
            os_version: worker.capabilities.os_version.clone(),
        };

        // Insert worker BEFORE outcome and promotion processing so mutations are not clobbered
        inner.workers.insert(node_id.clone(), worker);

        if let Some(ref outcome) = last_upgrade_outcome {
            let is_terminal = outcome.status
                == crate::proto::androgrid::v1::UpgradeInstallStatus::TerminallyRejected as i32;
            let is_failed = is_terminal
                || outcome.status
                    == crate::proto::androgrid::v1::UpgradeInstallStatus::FailedTransient as i32;
            if is_failed {
                record_node_upgrade_failure(
                    &mut inner,
                    &node_id,
                    &outcome.target_version,
                    &outcome.error_code,
                    &outcome.error_message,
                    is_terminal,
                    &self.rollout_store,
                );
            }
        }

        if upgrade_completed {
            promote_next_canary_if_ready(&mut inner, &node_id, now_epoch_ms, &self.rollout_store);
        }

        drop(inner);

        self.emit_event(reg_event);

        Ok(RegisterNodeResponse {
            session_token,
            heartbeat_interval_seconds: DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
            lease_timeout_seconds: DEFAULT_NODE_LEASE_TIMEOUT_SECONDS,
        })
    }

    /// Submits a new compute task specification to the pending queue.
    pub fn submit_task(&self, mut spec: TaskSpec) -> Result<(), SchedulingError> {
        spec.allowed_hostnames = spec
            .allowed_hostnames
            .into_iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .collect();
        validate_network_egress_policy(&spec)?;
        if spec.engine == ExecutionEngine::WasmWasi as i32 && !spec.wasm_bytecode.is_empty() {
            if spec.wasm_bytecode.len() < 8 {
                if spec.egress_policy == NetworkEgressPolicy::Allowlist as i32 {
                    return Err(SchedulingError::InvalidNetworkEgress(
                        "Payload too short for WebAssembly header in network egress task"
                            .to_string(),
                    ));
                }
            } else {
                let ep_to_check = if spec.egress_policy == NetworkEgressPolicy::Allowlist as i32 {
                    spec.entrypoint.as_str()
                } else {
                    ""
                };
                let meta = crate::artifact::wasi_validator::WasiValidator::validate(
                    &spec.wasm_bytecode,
                    ep_to_check,
                )
                .map_err(|e| {
                    SchedulingError::InvalidNetworkEgress(format!("WASI validation failed: {e}"))
                })?;
                crate::artifact::wasi_validator::WasiValidator::validate_egress_policy(
                    &meta,
                    spec.egress_policy,
                )
                .map_err(|e| SchedulingError::InvalidNetworkEgress(e.to_string()))?;
            }
        }
        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        let task_id = spec.task_id.clone();
        if is_reserved_group_task_id(&task_id) {
            return Err(SchedulingError::TaskIdCollision(format!(
                "task_id '{}' uses reserved TaskGroup partition format '<group>:e<epoch>:p<index>'",
                task_id
            )));
        }
        if inner.tasks.contains_key(&task_id) {
            return Err(SchedulingError::TaskIdCollision(format!(
                "task_id '{}' already exists",
                task_id
            )));
        }
        validate_node_group_affinity(&inner.node_groups, &spec.node_group_affinity)?;
        let engine_str = match spec.engine {
            1 => "WasmWasi",
            2 => "RootShell",
            3 => "ToyboxUser",
            _ => "Unknown",
        }
        .to_string();
        let submit_event = crate::observability::ClusterEvent::TaskSubmitted {
            task_id: task_id.clone(),
            engine: engine_str,
            timeout_seconds: spec.timeout_seconds,
            requires_unmetered: spec.requires_unmetered,
        };
        inner.tasks.insert(task_id, TaskRecord::new(spec));
        drop(inner);
        self.emit_event(submit_event);
        Ok(())
    }

    /// Claims an eligible task for a cellular spot worker with thermal protection.
    ///
    /// Traces to: [REQ-OP-003], [INV-003], [INV-005], [INV-006], [ANTI-003], [NFR-POW-001]
    pub fn claim_cellular_task(
        &self,
        node_id: &str,
        battery_level_pct: u32,
        is_charging: bool,
        battery_temperature_celsius: i32,
        thermal_status: u32,
        now_epoch_s: u64,
    ) -> Result<ClaimCellularTaskResponse, SchedulingError> {
        self.claim_cellular_task_with_outcome(
            node_id,
            battery_level_pct,
            is_charging,
            battery_temperature_celsius,
            thermal_status,
            now_epoch_s,
            "",
            None,
        )
    }

    /// Claims a cellular task while processing dynamic version reporting and last upgrade outcome telemetry.
    ///
    /// Traces to: [REQ-OP-003], [INV-001], [INV-002], [INV-003], [ANTI-003], [NFR-POW-001]
    #[allow(clippy::too_many_arguments)]
    pub fn claim_cellular_task_with_outcome(
        &self,
        node_id: &str,
        battery_level_pct: u32,
        is_charging: bool,
        battery_temperature_celsius: i32,
        thermal_status: u32,
        now_epoch_s: u64,
        client_version: &str,
        last_upgrade_outcome: Option<crate::LastUpgradeOutcome>,
    ) -> Result<ClaimCellularTaskResponse, SchedulingError> {
        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        let now_epoch_ms = now_epoch_s * 1000;

        // Process cellular upgrade outcome telemetry if present
        if let Some(outcome) = last_upgrade_outcome {
            let is_terminal =
                outcome.status == crate::UpgradeInstallStatus::TerminallyRejected as i32;
            let is_failure = is_terminal
                || outcome.status == crate::UpgradeInstallStatus::FailedTransient as i32;
            if is_failure {
                record_node_upgrade_failure(
                    &mut inner,
                    node_id,
                    &outcome.target_version,
                    &outcome.error_code,
                    &outcome.error_message,
                    is_terminal,
                    &self.rollout_store,
                );
            }
        }

        // Reconcile dynamic client_version and upgrade completion on cellular
        let mut completed_upgrade = false;
        if let Some(worker) = inner.workers.get_mut(node_id) {
            if !client_version.is_empty() {
                worker.client_version = client_version.to_string();
                if let Some(ref desired) = worker.desired_client_version {
                    if desired == client_version {
                        completed_upgrade = true;
                    }
                }
                if completed_upgrade {
                    worker.desired_client_version = None;
                    worker.upgrade_directive = None;
                    worker.upgrade_lease_deadline_ms = 0;
                    if worker.drained_for_upgrade {
                        worker.draining = false;
                        worker.drained_for_upgrade = false;
                    }
                }
            }
        }

        if completed_upgrade {
            promote_next_canary_if_ready(&mut inner, node_id, now_epoch_ms, &self.rollout_store);
        }

        let (is_rooted, policy, allow_root, worker_snapshot, cellular_upgrade_directive) = {
            let worker = inner
                .workers
                .get_mut(node_id)
                .ok_or_else(|| SchedulingError::NodeNotFound(node_id.to_string()))?;

            // Verify battery pre-condition: >= 20% or charging
            if !is_charging && battery_level_pct < MIN_CELLULAR_BATTERY_PCT {
                return Err(SchedulingError::InsufficientBattery {
                    node_id: node_id.to_string(),
                    battery_pct: battery_level_pct,
                });
            }

            worker.battery_level_pct = battery_level_pct;
            worker.is_charging = is_charging;
            worker.battery_temperature_celsius = battery_temperature_celsius;
            worker.thermal_status = thermal_status;
            worker.capabilities.battery_temperature_celsius = battery_temperature_celsius;
            worker.capabilities.thermal_status = thermal_status;
            worker.capabilities.current_transport =
                NetworkTransportType::NetworkTransportCellularWan as i32;
            worker.capabilities.is_metered = true;

            let cellular_directive = if let Some(ref dir) = worker.upgrade_directive {
                if dir.network_policy == UpgradeNetworkPolicy::AllowCellular as i32 {
                    if dir.drain_before_upgrade && !worker.active_task_ids.is_empty() {
                        None
                    } else {
                        Some(dir.clone())
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if worker.draining {
                return Ok(ClaimCellularTaskResponse {
                    task_available: false,
                    task: None,
                    deadline_epoch_seconds: 0,
                    upgrade_directive: cellular_directive,
                });
            }

            let worker_snap = worker.clone();
            (
                worker_snap.capabilities.is_rooted,
                inner.thermal_policy,
                inner.allow_insecure_root_tasks,
                worker_snap,
                cellular_directive,
            )
        };

        // Enforce Thermal Policy Guard: if throttled, apply configured action
        if policy.is_throttled(battery_temperature_celsius, thermal_status) {
            match policy.action {
                ThermalAction::Defer => {
                    return Ok(ClaimCellularTaskResponse {
                        task_available: false,
                        task: None,
                        deadline_epoch_seconds: 0,
                        upgrade_directive: cellular_upgrade_directive,
                    });
                }
                ThermalAction::Reject => {
                    return Err(SchedulingError::ThermalThrottled {
                        node_id: node_id.to_string(),
                        temperature_celsius: battery_temperature_celsius,
                        thermal_status,
                    });
                }
            }
        }

        // Find candidate pending task matching cellular constraints
        let worker_effective_labels = if worker_snapshot.explicit_node_group.is_none() {
            Some(worker_snapshot.effective_labels())
        } else {
            None
        };
        let mut candidate_id: Option<String> = None;
        for (id, record) in inner.tasks.iter() {
            if record.state != TaskState::Pending {
                continue;
            }

            // [ANTI-003]: Tasks requiring unmetered connections must NOT be scheduled to cellular
            if record.spec.requires_unmetered {
                continue;
            }

            // [ANTI-003], [INV-005]: Tasks exceeding 180s must NOT be scheduled to cellular
            if record.spec.timeout_seconds > MAX_CELLULAR_DURATION_SECONDS {
                continue;
            }

            // [ANTI-003], [INV-003], [NFR-POW-001]: Tasks with network egress must NOT be scheduled to cellular spot workers
            if record.spec.egress_policy == NetworkEgressPolicy::Allowlist as i32 {
                continue;
            }

            if !is_task_eligible_for_worker(
                &record.spec,
                is_rooted,
                allow_root,
                &inner.node_groups,
                &worker_snapshot,
                worker_effective_labels.as_ref(),
            ) {
                continue;
            }

            candidate_id = Some(id.clone());
            break;
        }

        match candidate_id {
            Some(task_id) => {
                let record = inner.tasks.get_mut(&task_id).unwrap();
                let effective_duration = record
                    .spec
                    .timeout_seconds
                    .min(MAX_CELLULAR_DURATION_SECONDS);
                let deadline = now_epoch_s + effective_duration as u64;

                // State transition: PENDING -> LEASED
                record.state = TaskState::Leased;
                record.active_attempt = 1;
                record.assigned_node_id = Some(node_id.to_string());
                record.lease_deadline_epoch_s = deadline;

                let mut out_spec = record.spec.clone();
                out_spec.run_attempt = 1;

                if let Some(w) = inner.workers.get_mut(node_id) {
                    w.active_task_ids.push(task_id.clone());
                }

                drop(inner);
                self.emit_event(crate::observability::ClusterEvent::TaskLeased {
                    task_id,
                    node_id: node_id.to_string(),
                    run_attempt: 1,
                });

                Ok(ClaimCellularTaskResponse {
                    task_available: true,
                    task: Some(out_spec),
                    deadline_epoch_seconds: deadline as u32,
                    upgrade_directive: cellular_upgrade_directive,
                })
            }
            None => Ok(ClaimCellularTaskResponse {
                task_available: false,
                task: None,
                deadline_epoch_seconds: 0,
                upgrade_directive: cellular_upgrade_directive,
            }),
        }
    }

    /// Helper to claim cellular spot task with nominal/unreported thermal telemetry (0 deg C, status 0).
    pub fn claim_cellular_task_nominal(
        &self,
        node_id: &str,
        battery_level_pct: u32,
        is_charging: bool,
        now_epoch_s: u64,
    ) -> Result<ClaimCellularTaskResponse, SchedulingError> {
        self.claim_cellular_task(node_id, battery_level_pct, is_charging, 0, 0, now_epoch_s)
    }

    /// Declarative Wi-Fi state synchronization and speculative preemption dispatcher.
    ///
    /// Traces to: [REQ-OP-002], [INV-005], [INV-006], [NFR-POW-001]
    pub fn sync_node_state(
        &self,
        node_id: &str,
        session_token: &str,
        completed_reports: &[TaskExecutionReport],
        now_epoch_ms: u64,
    ) -> Result<SyncNodeStateResponse, SchedulingError> {
        self.sync_node_state_with_outcome(
            node_id,
            session_token,
            completed_reports,
            None,
            now_epoch_ms,
        )
    }

    /// Declarative Wi-Fi state synchronization with upgrade outcome reporting.
    ///
    /// Traces to: ADR-010, [REQ-OP-002], [INV-005], [INV-006], [NFR-POW-001]
    pub fn sync_node_state_with_outcome(
        &self,
        node_id: &str,
        session_token: &str,
        completed_reports: &[TaskExecutionReport],
        last_upgrade_outcome: Option<crate::proto::androgrid::v1::LastUpgradeOutcome>,
        now_epoch_ms: u64,
    ) -> Result<SyncNodeStateResponse, SchedulingError> {
        let mut inner = self.inner.write().expect("RwLock write lock poisoned");

        let (
            is_rooted,
            is_unmetered,
            is_throttled,
            allow_root,
            is_draining,
            desired_version,
            upgrade_directive,
            worker_snapshot,
        ) = {
            if let Some(worker) = inner.workers.get_mut(node_id) {
                if worker.session_token != session_token {
                    return Err(SchedulingError::InvalidSessionToken {
                        node_id: node_id.to_string(),
                        provided: session_token.to_string(),
                    });
                }
                worker.last_seen_epoch_ms = now_epoch_ms;
            } else {
                return Err(SchedulingError::NodeNotFound(node_id.to_string()));
            }

            if let Some(ref outcome) = last_upgrade_outcome {
                let is_terminal = outcome.status
                    == crate::proto::androgrid::v1::UpgradeInstallStatus::TerminallyRejected as i32;
                let is_failed = is_terminal
                    || outcome.status
                        == crate::proto::androgrid::v1::UpgradeInstallStatus::FailedTransient
                            as i32;
                if is_failed {
                    record_node_upgrade_failure(
                        &mut inner,
                        node_id,
                        &outcome.target_version,
                        &outcome.error_code,
                        &outcome.error_message,
                        is_terminal,
                        &self.rollout_store,
                    );
                }
            }

            let policy = inner.thermal_policy;
            let allow_root = inner.allow_insecure_root_tasks;
            let worker = inner
                .workers
                .get(node_id)
                .ok_or_else(|| SchedulingError::NodeNotFound(node_id.to_string()))?;

            let throttled = policy.is_throttled(
                worker.capabilities.battery_temperature_celsius,
                worker.capabilities.thermal_status,
            );
            let unmetered = !worker.capabilities.is_metered;

            let allows_cellular_upgrade = worker
                .upgrade_directive
                .as_ref()
                .map(|d| d.network_policy == UpgradeNetworkPolicy::AllowCellular as i32)
                .unwrap_or(false);

            let upgrade_eligible = unmetered || allows_cellular_upgrade;

            let (desired_version, upgrade_directive) = if upgrade_eligible {
                let directive = if let Some(ref dir) = worker.upgrade_directive {
                    if dir.drain_before_upgrade && !worker.active_task_ids.is_empty() {
                        None
                    } else {
                        Some(dir.clone())
                    }
                } else {
                    None
                };
                (pending_desired_version(worker), directive)
            } else {
                (String::new(), None)
            };

            (
                worker.capabilities.is_rooted,
                unmetered,
                throttled,
                allow_root,
                worker.draining,
                desired_version,
                upgrade_directive,
                worker.clone(),
            )
        };

        let mut acknowledged_ids = Vec::new();
        let mut transition_events = Vec::new();
        let mut touched_groups = Vec::new();

        // Process completed reports submitted via Wi-Fi
        for report in completed_reports {
            if let Some(task) = inner.tasks.get_mut(&report.task_id) {
                // [CR-02]: If task was already cancelled/superseded, drop the result
                // but acknowledge the task_id so the Wi-Fi worker stops retrying
                // without failing healthy tasks in the same SyncNodeState batch.
                if task.state == TaskState::Cancelled {
                    acknowledged_ids.push(report.task_id.clone());
                    continue;
                }

                if task.active_attempt == report.run_attempt
                    && (task.state == TaskState::Leased || task.state == TaskState::Preempted)
                {
                    task.state = if report.exit_code == 0 {
                        TaskState::Completed
                    } else {
                        TaskState::Failed
                    };
                    task.result = Some(TaskExecutionResult {
                        exit_code: report.exit_code,
                        stdout_bytes: report.stdout_bytes.clone(),
                        stderr_bytes: report.stderr_bytes.clone(),
                        error_code: report.error_code.clone(),
                        error_message: String::new(),
                        execution_duration_ms: report.execution_time_ms,
                        committed_by_node_id: node_id.to_string(),
                        committed_attempt: report.run_attempt,
                    });
                    acknowledged_ids.push(report.task_id.clone());
                    if let Some(gid) = &task.group_id {
                        touched_groups.push(gid.clone());
                    }

                    if report.exit_code == 0 {
                        transition_events.push(crate::observability::ClusterEvent::TaskCompleted {
                            task_id: report.task_id.clone(),
                            node_id: node_id.to_string(),
                            run_attempt: report.run_attempt,
                            exit_code: report.exit_code,
                            execution_duration_ms: report.execution_time_ms,
                        });
                    } else {
                        transition_events.push(crate::observability::ClusterEvent::TaskFailed {
                            task_id: report.task_id.clone(),
                            node_id: node_id.to_string(),
                            run_attempt: report.run_attempt,
                            error_code: report.error_code.clone(),
                            error_message: "Wi-Fi worker reported task failure".to_string(),
                        });
                    }
                }
            }
        }

        // Schedule new or preempted tasks for this Wi-Fi node (deferred if thermally throttled or draining)
        let mut desired_tasks = Vec::new();
        let inner_ref = &mut *inner;

        if is_unmetered && !is_throttled && !is_draining {
            let worker_effective_labels = if worker_snapshot.explicit_node_group.is_none() {
                Some(worker_snapshot.effective_labels())
            } else {
                None
            };
            // First priority: dispatch any pending unassigned tasks
            for record in inner_ref.tasks.values_mut() {
                if record.state == TaskState::Pending {
                    if !is_task_eligible_for_worker(
                        &record.spec,
                        is_rooted,
                        allow_root,
                        &inner_ref.node_groups,
                        &worker_snapshot,
                        worker_effective_labels.as_ref(),
                    ) {
                        continue;
                    }
                    record.state = TaskState::Leased;
                    record.active_attempt += 1;
                    record.assigned_node_id = Some(node_id.to_string());
                    let mut spec = record.spec.clone();
                    spec.run_attempt = record.active_attempt;
                    desired_tasks.push(spec);

                    transition_events.push(crate::observability::ClusterEvent::TaskLeased {
                        task_id: record.spec.task_id.clone(),
                        node_id: node_id.to_string(),
                        run_attempt: record.active_attempt,
                    });
                    break;
                }
            }

            // Second priority: [INV-005] Speculative Dual-Assignment
            // If Wi-Fi worker has capacity, preempt slow cellular spot worker
            if desired_tasks.is_empty() {
                for record in inner_ref.tasks.values_mut() {
                    if record.state == TaskState::Leased
                        && record.assigned_node_id.as_deref() != Some(node_id)
                    {
                        // Invariant: ADR-011 strictly disables speculative dual-assignment
                        // for tasks with outbound network egress.
                        if record.spec.egress_policy == NetworkEgressPolicy::Allowlist as i32 {
                            continue;
                        }

                        if !is_task_eligible_for_worker(
                            &record.spec,
                            is_rooted,
                            allow_root,
                            &inner_ref.node_groups,
                            &worker_snapshot,
                            worker_effective_labels.as_ref(),
                        ) {
                            continue;
                        }

                        let original_node_id = record.assigned_node_id.clone();
                        // Preemption state transition: LEASED -> PREEMPTED with run_attempt increment
                        record.state = TaskState::Preempted;
                        record.active_attempt += 1; // Increment attempt (attempt = 2)
                        record.speculative_node_id = Some(node_id.to_string());

                        let mut spec = record.spec.clone();
                        spec.run_attempt = record.active_attempt;
                        desired_tasks.push(spec);

                        transition_events.push(crate::observability::ClusterEvent::TaskPreempted {
                            task_id: record.spec.task_id.clone(),
                            original_node_id,
                            speculative_node_id: node_id.to_string(),
                            new_attempt: record.active_attempt,
                        });
                        break;
                    }
                }
            }
        }

        for gid in touched_groups {
            reconcile_group_state(&mut inner, &gid, now_epoch_ms);
        }

        let cancel_task_ids = inner
            .pending_cancellations
            .remove(node_id)
            .unwrap_or_default();

        drop(inner);
        for ev in transition_events {
            self.emit_event(ev);
        }

        Ok(SyncNodeStateResponse {
            server_epoch_ms: now_epoch_ms,
            desired_tasks,
            cancel_task_ids,
            acknowledged_task_ids: acknowledged_ids,
            desired_client_version: desired_version,
            upgrade_directive,
        })
    }

    /// Submits cellular execution results with atomic CAS consensus and monotonic attempt fencing.
    ///
    /// Traces to: [REQ-OP-004], [INV-004], [NFR-REL-001]
    pub fn submit_cellular_result(
        &self,
        request: &crate::SubmitCellularResultRequest,
    ) -> Result<SubmitCellularResultResponse, SchedulingError> {
        let mut inner = self.inner.write().expect("RwLock write lock poisoned");

        // Check if task was cancelled due to a newer TaskGroup epoch before mutating.
        if let Some(task) = inner.tasks.get(&request.task_id) {
            if task.state == TaskState::Cancelled {
                if let (Some(gid), Some(task_epoch)) = (&task.group_id, task.group_epoch) {
                    if let Some(group) = inner.groups.get(gid) {
                        if task_epoch < group.group_epoch {
                            return Err(SchedulingError::GroupSuperseded {
                                task_id: request.task_id.clone(),
                                group_id: gid.clone(),
                                task_epoch,
                                active_epoch: group.group_epoch,
                            });
                        }
                    }
                }
                return Err(SchedulingError::TaskCancelled(request.task_id.clone()));
            }
            if is_terminal_task_state(task.state) {
                return Err(SchedulingError::AlreadyFinalized(request.task_id.clone()));
            }
        } else {
            return Err(SchedulingError::TaskNotFound(request.task_id.clone()));
        }

        let task = inner
            .tasks
            .get_mut(&request.task_id)
            .expect("task existence verified above");

        // [INV-004]: Atomic monotonic fencing check
        // Submissions bearing run_attempt strictly lower than the latest committed state MUST be dropped
        if request.run_attempt < task.active_attempt {
            return Err(SchedulingError::AttemptStale {
                task_id: request.task_id.clone(),
                submitted: request.run_attempt,
                active: task.active_attempt,
            });
        }

        // Commit atomic CAS transition: LEASED / PREEMPTED -> COMPLETED / FAILED
        task.state = if request.exit_code == 0 {
            TaskState::Completed
        } else {
            TaskState::Failed
        };

        task.result = Some(TaskExecutionResult {
            exit_code: request.exit_code,
            stdout_bytes: request.stdout_bytes.clone(),
            stderr_bytes: request.stderr_bytes.clone(),
            error_code: request.error_code.clone(),
            error_message: request.error_message.clone(),
            execution_duration_ms: request.execution_duration_ms,
            committed_by_node_id: request.node_id.clone(),
            committed_attempt: request.run_attempt,
        });

        let committed_group_id = task.group_id.clone();
        if let Some(gid) = committed_group_id {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            reconcile_group_state(&mut inner, &gid, now_ms);
        }

        drop(inner);

        if request.exit_code == 0 {
            self.emit_event(crate::observability::ClusterEvent::TaskCompleted {
                task_id: request.task_id.clone(),
                node_id: request.node_id.clone(),
                run_attempt: request.run_attempt,
                exit_code: request.exit_code,
                execution_duration_ms: request.execution_duration_ms,
            });
        } else {
            self.emit_event(crate::observability::ClusterEvent::TaskFailed {
                task_id: request.task_id.clone(),
                node_id: request.node_id.clone(),
                run_attempt: request.run_attempt,
                error_code: request.error_code.clone(),
                error_message: request.error_message.clone(),
            });
        }

        Ok(SubmitCellularResultResponse {
            accepted: true,
            status_message: "Committed".to_string(),
        })
    }

    /// Retrieves current state of a task by ID.
    pub fn get_task_state(&self, task_id: &str) -> Option<TaskState> {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        inner.tasks.get(task_id).map(|t| t.state)
    }

    /// Retrieves active run attempt of a task by ID.
    pub fn get_active_attempt(&self, task_id: &str) -> Option<u32> {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        inner.tasks.get(task_id).map(|t| t.active_attempt)
    }

    /// Retrieves committed execution result of a task by ID.
    pub fn get_task_result(&self, task_id: &str) -> Option<TaskExecutionResult> {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        inner.tasks.get(task_id).and_then(|t| t.result.clone())
    }

    /// Retrieves registered capabilities of a worker node by ID.
    pub fn get_worker_capabilities(&self, node_id: &str) -> Option<NodeCapabilities> {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        inner.workers.get(node_id).map(|w| w.capabilities.clone())
    }

    /// Sweeps expired leases and transitions them back to PENDING or TIMED_OUT.
    ///
    /// Traces to: Section 6.2 (LEASED -> TIMED_OUT)
    pub fn sweep_timed_out_leases(&self, now_epoch_s: u64) -> Vec<String> {
        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        let mut expired = Vec::new();

        let mut touched_groups = Vec::new();
        for (id, task) in inner.tasks.iter_mut() {
            if (task.state == TaskState::Leased || task.state == TaskState::Preempted)
                && task.lease_deadline_epoch_s > 0
                && now_epoch_s > task.lease_deadline_epoch_s
            {
                task.state = TaskState::TimedOut;
                expired.push(id.clone());
                if let Some(gid) = &task.group_id {
                    touched_groups.push(gid.clone());
                }
            }
        }
        for gid in touched_groups {
            reconcile_group_state(&mut inner, &gid, now_epoch_s * 1000);
        }

        // Sweep stalled OTA upgrade leases
        let now_epoch_ms = now_epoch_s * 1000;
        let mut timed_out_upgrades = Vec::new();
        for (node_id, worker) in inner.workers.iter_mut() {
            if worker.upgrade_lease_deadline_ms > 0
                && now_epoch_ms > worker.upgrade_lease_deadline_ms
            {
                if let Some(target_ver) = worker.desired_client_version.take() {
                    worker.upgrade_directive = None;
                    worker.upgrade_lease_deadline_ms = 0;
                    if worker.drained_for_upgrade {
                        worker.draining = false;
                        worker.drained_for_upgrade = false;
                    }
                    timed_out_upgrades.push((node_id.clone(), target_ver));
                }
            }
        }

        for (node_id, target_ver) in timed_out_upgrades {
            record_node_upgrade_failure(
                &mut inner,
                &node_id,
                &target_ver,
                "UPGRADE_LEASE_TIMEOUT",
                "Node failed to complete upgrade within designated lease timeout",
                true,
                &self.rollout_store,
            );
        }

        drop(inner);
        for id in &expired {
            self.emit_event(crate::observability::ClusterEvent::TaskTimedOut {
                task_id: id.clone(),
            });
        }

        expired
    }

    /// Lists all registered worker nodes, their capabilities, and last heartbeat timestamps.
    ///
    /// Traces to: [REQ-OP-001], [REQ-OP-004]
    pub fn list_worker_nodes(&self) -> Vec<crate::WorkerNodeInfo> {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        inner
            .workers
            .iter()
            .map(|(node_id, worker)| {
                let effective_btree = worker.effective_labels();
                let node_group =
                    resolve_effective_node_group(&inner.node_groups, worker, &effective_btree)
                        .unwrap_or_default();
                let effective_labels: HashMap<String, String> =
                    effective_btree.into_iter().collect();
                let desired_client_version = pending_desired_version(worker);
                crate::WorkerNodeInfo {
                    node_id: node_id.clone(),
                    capabilities: Some(worker.capabilities.clone()),
                    client_version: worker.client_version.clone(),
                    last_heartbeat_epoch_seconds: worker.last_seen_epoch_ms / 1000,
                    labels: effective_labels,
                    node_group,
                    draining: worker.draining,
                    desired_client_version,
                }
            })
            .collect()
    }

    /// Lists all compute tasks, optionally filtered by lifecycle state.
    ///
    /// Traces to: [REQ-OP-004], [INV-004], [INV-005]
    pub fn list_tasks(&self, state_filter: Option<TaskState>) -> Vec<crate::TaskInfo> {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        inner
            .tasks
            .values()
            .filter(|task| {
                if let Some(filter) = state_filter {
                    task.state == filter
                } else {
                    true
                }
            })
            .map(|task| {
                let (exit_code, execution_duration_ms, error_message) =
                    if let Some(ref r) = task.result {
                        (
                            r.exit_code,
                            r.execution_duration_ms,
                            if r.error_message.is_empty() {
                                None
                            } else {
                                Some(r.error_message.clone())
                            },
                        )
                    } else {
                        (0, 0, None)
                    };

                crate::TaskInfo {
                    task_id: task.spec.task_id.clone(),
                    state: task.state as i32,
                    engine: task.spec.engine,
                    run_attempt: task.active_attempt,
                    assigned_node_id: task.assigned_node_id.clone().unwrap_or_default(),
                    timeout_seconds: task.spec.timeout_seconds,
                    requires_unmetered: task.spec.requires_unmetered,
                    exit_code,
                    execution_duration_ms,
                    error_message: error_message.unwrap_or_default(),
                    speculative_node_id: task.speculative_node_id.clone().unwrap_or_default(),
                    node_group_affinity: task.spec.node_group_affinity.clone(),
                }
            })
            .collect()
    }

    /// Generates a comprehensive point-in-time snapshot of the cluster state.
    ///
    /// Traces to: [REQ-OP-001], [REQ-OP-004], [INV-004], [INV-005]
    pub fn get_snapshot(&self) -> crate::observability::ClusterSnapshot {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut wifi_nodes = 0;
        let mut cellular_nodes = 0;

        let nodes: Vec<crate::observability::WorkerNodeSnapshot> = inner
            .workers
            .values()
            .map(|w| {
                let is_wifi = w.capabilities.current_transport
                    == NetworkTransportType::NetworkTransportWifiLan as i32;
                if is_wifi {
                    wifi_nodes += 1;
                } else {
                    cellular_nodes += 1;
                }

                let thermal_badge = match w.thermal_status {
                    0 => "NOMINAL",
                    1 => "LIGHT",
                    2 => "MODERATE",
                    3 => "SEVERE",
                    _ => "CRITICAL",
                }
                .to_string();

                crate::observability::WorkerNodeSnapshot {
                    node_id: w.node_id.clone(),
                    is_rooted: w.capabilities.is_rooted,
                    transport: if is_wifi {
                        "Wi-Fi LAN".to_string()
                    } else {
                        "Cellular WAN".to_string()
                    },
                    battery_level_pct: w.battery_level_pct,
                    is_charging: w.is_charging,
                    thermal_status: w.thermal_status,
                    thermal_badge,
                    cpu_cores: w.capabilities.cpu_cores,
                    ram_mb: w.capabilities.total_ram_bytes / (1024 * 1024),
                    os_version: w.capabilities.os_version.clone(),
                    abi: w.capabilities.abi.clone(),
                    client_version: w.client_version.clone(),
                    last_seen_epoch_ms: w.last_seen_epoch_ms,
                }
            })
            .collect();

        let mut pending_tasks = 0;
        let mut leased_tasks = 0;
        let mut completed_tasks = 0;
        let mut failed_tasks = 0;
        let mut preempted_tasks = 0;
        let mut timed_out_tasks = 0;
        let mut cancelled_tasks = 0;

        let tasks: Vec<crate::observability::TaskSnapshot> = inner
            .tasks
            .values()
            .map(|t| {
                let state_str = match t.state {
                    TaskState::Pending => {
                        pending_tasks += 1;
                        "Pending"
                    }
                    TaskState::Leased => {
                        leased_tasks += 1;
                        "Leased"
                    }
                    TaskState::Running => {
                        leased_tasks += 1;
                        "Running"
                    }
                    TaskState::Completed => {
                        completed_tasks += 1;
                        "Completed"
                    }
                    TaskState::Failed => {
                        failed_tasks += 1;
                        "Failed"
                    }
                    TaskState::Preempted => {
                        preempted_tasks += 1;
                        "Preempted"
                    }
                    TaskState::TimedOut => {
                        timed_out_tasks += 1;
                        "TimedOut"
                    }
                    TaskState::Cancelled => {
                        cancelled_tasks += 1;
                        "Cancelled"
                    }
                    _ => "Unknown",
                }
                .to_string();

                let engine_str = match t.spec.engine {
                    1 => "WasmWasi",
                    2 => "RootShell",
                    3 => "ToyboxUser",
                    _ => "Unknown",
                }
                .to_string();

                let (exit_code, dur, err_msg) = if let Some(ref res) = t.result {
                    (
                        Some(res.exit_code),
                        Some(res.execution_duration_ms),
                        if res.error_message.is_empty() {
                            None
                        } else {
                            Some(res.error_message.clone())
                        },
                    )
                } else {
                    (None, None, None)
                };

                crate::observability::TaskSnapshot {
                    task_id: t.spec.task_id.clone(),
                    state: state_str,
                    engine: engine_str,
                    run_attempt: t.active_attempt,
                    assigned_node_id: t.assigned_node_id.clone(),
                    speculative_node_id: t.speculative_node_id.clone(),
                    timeout_seconds: t.spec.timeout_seconds,
                    requires_unmetered: t.spec.requires_unmetered,
                    exit_code,
                    execution_duration_ms: dur,
                    error_message: err_msg,
                }
            })
            .collect();

        let metrics = crate::observability::ClusterMetrics {
            total_nodes: nodes.len(),
            wifi_nodes,
            cellular_nodes,
            total_tasks: tasks.len(),
            pending_tasks,
            leased_tasks,
            completed_tasks,
            failed_tasks,
            preempted_tasks,
            timed_out_tasks,
            cancelled_tasks,
        };

        crate::observability::ClusterSnapshot {
            nodes,
            tasks,
            metrics,
            timestamp_epoch_ms: now,
        }
    }

    /// Cancels a task if it is not already in a terminal state.
    ///
    /// Traces to: [REQ-OP-004], Section 6.2 State Machine
    pub fn cancel_task(&self, task_id: &str) -> Result<(), SchedulingError> {
        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        let task = inner
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| SchedulingError::TaskNotFound(task_id.to_string()))?;

        if is_terminal_task_state(task.state) {
            return Err(SchedulingError::AlreadyFinalized(task_id.to_string()));
        }

        if task.group_id.is_some() {
            return Err(SchedulingError::InvalidStateTransition {
                task_id: task_id.to_string(),
                from: format!("{:?}", task.state),
                to: "Cancelled (use CancelTaskGroup for group-owned tasks)".to_string(),
            });
        }

        task.state = TaskState::Failed;
        task.result = Some(TaskExecutionResult {
            exit_code: -1,
            stdout_bytes: Vec::new(),
            stderr_bytes: b"Task cancelled by operator".to_vec(),
            error_code: "TASK_CANCELLED".to_string(),
            error_message: "Task was cancelled by operator".to_string(),
            execution_duration_ms: 0,
            committed_by_node_id: "operator".to_string(),
            committed_attempt: task.active_attempt,
        });
        let cancelled_group_id = task.group_id.clone();
        if let Some(gid) = cancelled_group_id {
            reconcile_group_state(&mut inner, &gid, 0);
        }

        drop(inner);
        self.emit_event(crate::observability::ClusterEvent::TaskCancelled {
            task_id: task_id.to_string(),
        });

        Ok(())
    }

    /// Retrieves complete task lifecycle status and execution outputs.
    ///
    /// Traces to: [REQ-OP-004]
    pub fn get_task_details(
        &self,
        task_id: &str,
    ) -> Option<(TaskState, u32, Option<TaskExecutionResult>)> {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        inner
            .tasks
            .get(task_id)
            .map(|t| (t.state, t.active_attempt, t.result.clone()))
    }

    /// Atomically admits a partitioned TaskGroup at epoch 1.
    ///
    /// Traces to: [REQ-OP-004], [INV-004], [INV-006], [NFR-PERF-001]
    pub fn submit_task_group(
        &self,
        group: TaskGroupSpec,
        now_epoch_ms: u64,
    ) -> Result<SubmitTaskGroupResponse, SchedulingError> {
        validate_group_id(&group.group_id)?;
        validate_partitions(&group.partitions)?;
        let mut template = group.template.ok_or_else(|| {
            SchedulingError::InvalidGroupPartitions("template is required".to_string())
        })?;
        template.allowed_hostnames = template
            .allowed_hostnames
            .into_iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .collect();
        validate_task_template(&template)?;

        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        if template.engine == ExecutionEngine::RootShell as i32 && !inner.allow_insecure_root_tasks
        {
            return Err(SchedulingError::RootShellExecutionDisabled);
        }
        validate_node_group_affinity(&inner.node_groups, &template.node_group_affinity)?;
        if inner.groups.contains_key(&group.group_id) {
            return Err(SchedulingError::GroupAlreadyExists(group.group_id));
        }

        let epoch = 1u64;
        let total = group.partitions.len();
        let mut task_ids = Vec::with_capacity(total);
        inner.tasks.reserve(total);

        for (idx, part) in group.partitions.iter().enumerate() {
            let record = build_partition_task_record(&group.group_id, epoch, idx, &template, part);
            let tid = record.spec.task_id.clone();
            if inner.tasks.contains_key(&tid) {
                return Err(SchedulingError::TaskIdCollision(format!(
                    "partition task_id '{}' already exists",
                    tid
                )));
            }
            task_ids.push(tid.clone());
            inner.tasks.insert(tid, record);
        }

        inner.groups.insert(
            group.group_id.clone(),
            TaskGroupRecord {
                group_id: group.group_id.clone(),
                group_epoch: epoch,
                state: TaskGroupState::Active,
                template,
                current_task_ids: task_ids,
                draining_task_ids: Vec::new(),
                created_at_epoch_ms: now_epoch_ms,
                updated_at_epoch_ms: now_epoch_ms,
            },
        );
        drop(inner);
        self.emit_event(crate::observability::ClusterEvent::TaskGroupSubmitted {
            group_id: group.group_id.clone(),
            group_epoch: epoch,
            total_tasks: total as u32,
        });

        Ok(SubmitTaskGroupResponse {
            accepted: true,
            group_id: group.group_id,
            group_epoch: epoch,
            total_tasks: total as u32,
            message: "TaskGroup accepted and enqueued".to_string(),
        })
    }

    /// Atomically replaces a TaskGroup with a new epoch using IMMEDIATE or DRAIN strategy.
    ///
    /// Traces to: [INV-004], [NFR-REL-001], [INV-006]
    pub fn replace_task_group(
        &self,
        req: ReplaceTaskGroupRequest,
        now_epoch_ms: u64,
    ) -> Result<ReplaceTaskGroupResponse, SchedulingError> {
        validate_group_id(&req.group_id)?;
        validate_partitions(&req.partitions)?;
        let template = req.template.ok_or_else(|| {
            SchedulingError::InvalidGroupPartitions("template is required".to_string())
        })?;
        validate_task_template(&template)?;

        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        if template.engine == ExecutionEngine::RootShell as i32 && !inner.allow_insecure_root_tasks
        {
            return Err(SchedulingError::RootShellExecutionDisabled);
        }
        validate_node_group_affinity(&inner.node_groups, &template.node_group_affinity)?;

        let (current_epoch, current_state, prev_current_ids, prev_draining_ids) = {
            let group = inner
                .groups
                .get(&req.group_id)
                .ok_or_else(|| SchedulingError::GroupNotFound(req.group_id.clone()))?;
            (
                group.group_epoch,
                group.state,
                group.current_task_ids.clone(),
                group.draining_task_ids.clone(),
            )
        };

        if current_state == TaskGroupState::Cancelled
            || current_state == TaskGroupState::Completed
            || current_state == TaskGroupState::Failed
        {
            return Err(SchedulingError::GroupTerminal(req.group_id));
        }

        if let Some(expected) = req.expected_epoch {
            if expected != current_epoch {
                return Err(SchedulingError::GroupEpochConflict {
                    group_id: req.group_id,
                    expected,
                    actual: current_epoch,
                });
            }
        }

        let strategy =
            ReplaceStrategy::try_from(req.strategy).unwrap_or(ReplaceStrategy::Immediate);
        let is_drain = strategy == ReplaceStrategy::Drain;
        let new_epoch = current_epoch + 1;

        let mut cancelled_count = 0u32;
        let mut draining_ids = Vec::new();

        // Force-cancel any leftover tasks from an even older draining epoch so only
        // at most one previous epoch is ever draining concurrently.
        for tid in prev_draining_ids {
            if let Some(task) = inner.tasks.get(&tid).cloned() {
                if !is_terminal_task_state(task.state) {
                    queue_wifi_cancel(&mut inner, &task);
                    if let Some(t) = inner.tasks.get_mut(&tid) {
                        t.state = TaskState::Cancelled;
                    }
                    cancelled_count += 1;
                }
            }
        }

        for tid in prev_current_ids {
            if let Some(task_snapshot) = inner.tasks.get(&tid).cloned() {
                if is_terminal_task_state(task_snapshot.state) {
                    continue;
                }
                if is_drain
                    && (task_snapshot.state == TaskState::Leased
                        || task_snapshot.state == TaskState::Preempted
                        || task_snapshot.state == TaskState::Running)
                {
                    draining_ids.push(tid);
                } else {
                    if task_snapshot.state != TaskState::Pending {
                        queue_wifi_cancel(&mut inner, &task_snapshot);
                    }
                    if let Some(t) = inner.tasks.get_mut(&tid) {
                        t.state = TaskState::Cancelled;
                    }
                    cancelled_count += 1;
                }
            }
        }

        let created_count = req.partitions.len();
        let mut new_task_ids = Vec::with_capacity(created_count);
        inner.tasks.reserve(created_count);
        for (idx, part) in req.partitions.iter().enumerate() {
            let record =
                build_partition_task_record(&req.group_id, new_epoch, idx, &template, part);
            let tid = record.spec.task_id.clone();
            new_task_ids.push(tid.clone());
            inner.tasks.insert(tid, record);
        }

        let draining_count = draining_ids.len() as u32;
        let new_state = if draining_count > 0 {
            TaskGroupState::Draining
        } else {
            TaskGroupState::Active
        };

        if let Some(group) = inner.groups.get_mut(&req.group_id) {
            group.group_epoch = new_epoch;
            group.state = new_state;
            group.template = template;
            group.current_task_ids = new_task_ids;
            group.draining_task_ids = draining_ids;
            group.updated_at_epoch_ms = now_epoch_ms;
        }
        drop(inner);
        self.emit_event(crate::observability::ClusterEvent::TaskGroupReplaced {
            group_id: req.group_id.clone(),
            new_epoch,
            cancelled_tasks: cancelled_count,
            draining_tasks: draining_count,
            created_tasks: created_count as u32,
        });

        Ok(ReplaceTaskGroupResponse {
            accepted: true,
            group_id: req.group_id,
            new_epoch,
            state: new_state as i32,
            cancelled_tasks: cancelled_count,
            draining_tasks: draining_count,
            created_tasks: created_count as u32,
            message: format!("TaskGroup replaced at epoch {}", new_epoch),
        })
    }

    /// Cancels a TaskGroup and all non-terminal tasks across current and draining epochs.
    ///
    /// Traces to: [REQ-OP-004], [INV-004]
    pub fn cancel_task_group(
        &self,
        group_id: &str,
        expected_epoch: Option<u64>,
        now_epoch_ms: u64,
    ) -> Result<CancelTaskGroupResponse, SchedulingError> {
        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        let (epoch, state, all_task_ids) = {
            let group = inner
                .groups
                .get(group_id)
                .ok_or_else(|| SchedulingError::GroupNotFound(group_id.to_string()))?;
            let mut ids = group.current_task_ids.clone();
            ids.extend(group.draining_task_ids.iter().cloned());
            (group.group_epoch, group.state, ids)
        };

        if state == TaskGroupState::Cancelled
            || state == TaskGroupState::Completed
            || state == TaskGroupState::Failed
        {
            return Err(SchedulingError::GroupTerminal(group_id.to_string()));
        }

        if let Some(expected) = expected_epoch {
            if expected != epoch {
                return Err(SchedulingError::GroupEpochConflict {
                    group_id: group_id.to_string(),
                    expected,
                    actual: epoch,
                });
            }
        }

        let mut cancelled_count = 0u32;
        for tid in all_task_ids {
            if let Some(task_snapshot) = inner.tasks.get(&tid).cloned() {
                if !is_terminal_task_state(task_snapshot.state) {
                    if task_snapshot.state != TaskState::Pending {
                        queue_wifi_cancel(&mut inner, &task_snapshot);
                    }
                    if let Some(t) = inner.tasks.get_mut(&tid) {
                        t.state = TaskState::Cancelled;
                    }
                    cancelled_count += 1;
                }
            }
        }

        if let Some(group) = inner.groups.get_mut(group_id) {
            group.state = TaskGroupState::Cancelled;
            group.draining_task_ids.clear();
            group.updated_at_epoch_ms = now_epoch_ms;
        }
        drop(inner);
        self.emit_event(crate::observability::ClusterEvent::TaskGroupCancelled {
            group_id: group_id.to_string(),
            epoch,
            cancelled_tasks: cancelled_count,
        });

        Ok(CancelTaskGroupResponse {
            cancelled: true,
            group_id: group_id.to_string(),
            epoch,
            cancelled_tasks: cancelled_count,
            message: "TaskGroup cancelled".to_string(),
        })
    }

    /// Retrieves aggregate status counters and optional per-partition TaskInfo records.
    ///
    /// Traces to: [REQ-OP-004], [NFR-PERF-001]
    pub fn get_task_group_status(
        &self,
        group_id: &str,
        include_tasks: bool,
    ) -> Result<GetTaskGroupStatusResponse, SchedulingError> {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        let group = inner
            .groups
            .get(group_id)
            .ok_or_else(|| SchedulingError::GroupNotFound(group_id.to_string()))?;

        let mut pending = 0u32;
        let mut leased = 0u32;
        let mut running = 0u32;
        let mut completed = 0u32;
        let mut failed = 0u32;
        let mut timed_out = 0u32;
        let mut cancelled = 0u32;
        let mut preempted = 0u32;
        let mut tasks_out = if include_tasks {
            Vec::with_capacity(group.current_task_ids.len())
        } else {
            Vec::new()
        };

        for tid in &group.current_task_ids {
            if let Some(t) = inner.tasks.get(tid) {
                match t.state {
                    TaskState::Pending => pending += 1,
                    TaskState::Leased => leased += 1,
                    TaskState::Running => running += 1,
                    TaskState::Completed => completed += 1,
                    TaskState::Failed => failed += 1,
                    TaskState::TimedOut => timed_out += 1,
                    TaskState::Cancelled => cancelled += 1,
                    TaskState::Preempted => preempted += 1,
                    TaskState::Unspecified => {}
                }
                if include_tasks {
                    tasks_out.push(task_record_to_info(t));
                }
            }
        }

        let draining_active = group
            .draining_task_ids
            .iter()
            .filter(|tid| {
                inner
                    .tasks
                    .get(*tid)
                    .map(|t| !is_terminal_task_state(t.state))
                    .unwrap_or(false)
            })
            .count() as u32;

        Ok(GetTaskGroupStatusResponse {
            group_id: group.group_id.clone(),
            current_epoch: group.group_epoch,
            state: group.state as i32,
            total_tasks: group.current_task_ids.len() as u32,
            pending_tasks: pending,
            leased_tasks: leased,
            running_tasks: running,
            completed_tasks: completed,
            failed_tasks: failed,
            timed_out_tasks: timed_out,
            cancelled_tasks: cancelled,
            preempted_tasks: preempted,
            previous_epoch_draining_tasks: draining_active,
            tasks: tasks_out,
        })
    }

    /// Lists all registered TaskGroups, optionally filtered by TaskGroupState.
    ///
    /// Traces to: [REQ-OP-004]
    pub fn list_task_groups(&self, state_filter: Option<TaskGroupState>) -> Vec<TaskGroupSummary> {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        let mut summaries = Vec::new();
        for group in inner.groups.values() {
            if let Some(filter) = state_filter {
                if filter != TaskGroupState::Unspecified && group.state != filter {
                    continue;
                }
            }
            let mut completed = 0u32;
            let mut failed = 0u32;
            let mut cancelled = 0u32;
            for tid in &group.current_task_ids {
                if let Some(t) = inner.tasks.get(tid) {
                    match t.state {
                        TaskState::Completed => completed += 1,
                        TaskState::Failed | TaskState::TimedOut => failed += 1,
                        TaskState::Cancelled => cancelled += 1,
                        _ => {}
                    }
                }
            }
            summaries.push(TaskGroupSummary {
                group_id: group.group_id.clone(),
                current_epoch: group.group_epoch,
                state: group.state as i32,
                total_tasks: group.current_task_ids.len() as u32,
                completed_tasks: completed,
                failed_tasks: failed,
                cancelled_tasks: cancelled,
            });
        }
        summaries.sort_by(|a, b| a.group_id.cmp(&b.group_id));
        summaries
    }

    /// Creates a new logical NodeGroup for fleet partitioning and targeted operations.
    ///
    /// Traces to: [REQ-OP-001], [INV-005], [INV-006], [REQ-VER-002], [NFR-REL-001]
    pub fn create_node_group(
        &self,
        req: CreateNodeGroupRequest,
        now_epoch_ms: u64,
    ) -> Result<CreateNodeGroupResponse, SchedulingError> {
        validate_group_id(&req.group_id)?;
        let selector = validate_labels(&req.label_selector, true)?;
        let initial_nodes = validate_node_id_batch(&req.initial_node_ids, true)?;

        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        if inner.node_groups.contains_key(&req.group_id) {
            return Err(SchedulingError::NodeGroupAlreadyExists(req.group_id));
        }
        if inner.node_groups.len() >= MAX_NODE_GROUPS {
            return Err(SchedulingError::NodeGroupLimitExceeded(MAX_NODE_GROUPS));
        }

        let mut member_set = BTreeSet::new();
        for nid in &initial_nodes {
            // Atomically move from any prior explicit group
            for (prior_gid, prior_grp) in inner.node_groups.iter_mut() {
                if prior_gid != &req.group_id && prior_grp.member_node_ids.remove(nid) {
                    prior_grp.updated_at_epoch_ms = now_epoch_ms;
                }
            }
            if let Some(worker) = inner.workers.get_mut(nid) {
                worker.explicit_node_group = Some(req.group_id.clone());
            }
            member_set.insert(nid.clone());
        }

        let record = NodeGroupRecord {
            group_id: req.group_id.clone(),
            description: req.description,
            label_selector: selector,
            member_node_ids: member_set,
            created_at_epoch_ms: now_epoch_ms,
            updated_at_epoch_ms: now_epoch_ms,
        };
        inner.node_groups.insert(req.group_id.clone(), record);
        let inserted = inner
            .node_groups
            .get(&req.group_id)
            .expect("inserted above");
        let proto_group = build_node_group_proto(inserted, &inner.workers);

        Ok(CreateNodeGroupResponse {
            created: true,
            group: Some(proto_group),
            message: format!("NodeGroup '{}' created", req.group_id),
        })
    }

    /// Updates a NodeGroup's description and/or label selector.
    ///
    /// Traces to: [REQ-OP-001], [REQ-VER-002], [NFR-REL-001]
    pub fn update_node_group(
        &self,
        req: UpdateNodeGroupRequest,
        now_epoch_ms: u64,
    ) -> Result<UpdateNodeGroupResponse, SchedulingError> {
        validate_group_id(&req.group_id)?;
        if !req.replace_label_selector && !req.label_selector.is_empty() {
            return Err(SchedulingError::InvalidNodeGroupRequest(
                "label_selector must be empty when replace_label_selector is false".to_string(),
            ));
        }
        let next_selector = if req.replace_label_selector {
            Some(validate_labels(&req.label_selector, true)?)
        } else {
            None
        };

        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        let mut changed = false;
        {
            let group = inner
                .node_groups
                .get_mut(&req.group_id)
                .ok_or_else(|| SchedulingError::NodeGroupNotFound(req.group_id.clone()))?;
            if let Some(desc) = req.description {
                if group.description != desc {
                    group.description = desc;
                    changed = true;
                }
            }
            if let Some(sel) = next_selector {
                if group.label_selector != sel {
                    group.label_selector = sel;
                    changed = true;
                }
            }
            if changed {
                group.updated_at_epoch_ms = now_epoch_ms;
            }
        }

        let record = inner
            .node_groups
            .get(&req.group_id)
            .expect("verified above");
        let proto_group = build_node_group_proto(record, &inner.workers);
        Ok(UpdateNodeGroupResponse {
            updated: true,
            group: Some(proto_group),
            message: format!("NodeGroup '{}' updated", req.group_id),
        })
    }

    /// Lists all registered NodeGroups sorted by group_id.
    ///
    /// Traces to: [REQ-OP-001], [NFR-PERF-001]
    pub fn list_node_groups(&self) -> Vec<NodeGroup> {
        let inner = self.inner.read().expect("RwLock read lock poisoned");
        let cached_workers: Vec<(&WorkerRecord, Option<BTreeMap<String, String>>)> = inner
            .workers
            .values()
            .map(|w| {
                let labels = if w.explicit_node_group.is_none() {
                    Some(w.effective_labels())
                } else {
                    None
                };
                (w, labels)
            })
            .collect();
        let mut out: Vec<NodeGroup> = inner
            .node_groups
            .values()
            .map(|rec| build_node_group_proto_cached(rec, &cached_workers))
            .collect();
        out.sort_by(|a, b| a.group_id.cmp(&b.group_id));
        out
    }

    /// Atomically assigns or unassigns worker node IDs to/from a NodeGroup.
    ///
    /// Traces to: [REQ-OP-001], [NFR-REL-001]
    pub fn assign_nodes_to_group(
        &self,
        req: AssignNodesToGroupRequest,
        now_epoch_ms: u64,
    ) -> Result<AssignNodesToGroupResponse, SchedulingError> {
        validate_group_id(&req.group_id)?;
        let node_ids = validate_node_id_batch(&req.node_ids, false)?;

        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        if !inner.node_groups.contains_key(&req.group_id) {
            return Err(SchedulingError::NodeGroupNotFound(req.group_id));
        }

        let mut affected = 0u32;
        if req.unassign {
            for nid in &node_ids {
                let removed_from_grp = inner
                    .node_groups
                    .get_mut(&req.group_id)
                    .map(|g| g.member_node_ids.remove(nid))
                    .unwrap_or(false);
                let cleared_worker = if let Some(w) = inner.workers.get_mut(nid) {
                    if w.explicit_node_group.as_deref() == Some(&req.group_id) {
                        w.explicit_node_group = None;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                if removed_from_grp || cleared_worker {
                    affected += 1;
                }
            }
            if affected > 0 {
                if let Some(g) = inner.node_groups.get_mut(&req.group_id) {
                    g.updated_at_epoch_ms = now_epoch_ms;
                }
            }
        } else {
            for nid in &node_ids {
                for (prior_gid, prior_grp) in inner.node_groups.iter_mut() {
                    if prior_gid != &req.group_id && prior_grp.member_node_ids.remove(nid) {
                        prior_grp.updated_at_epoch_ms = now_epoch_ms;
                    }
                }
                let inserted = inner
                    .node_groups
                    .get_mut(&req.group_id)
                    .map(|g| g.member_node_ids.insert(nid.clone()))
                    .unwrap_or(false);
                let worker_changed = if let Some(w) = inner.workers.get_mut(nid) {
                    if w.explicit_node_group.as_deref() != Some(&req.group_id) {
                        w.explicit_node_group = Some(req.group_id.clone());
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                if inserted || worker_changed {
                    affected += 1;
                }
            }
            if affected > 0 {
                if let Some(g) = inner.node_groups.get_mut(&req.group_id) {
                    g.updated_at_epoch_ms = now_epoch_ms;
                }
            }
        }

        let record = inner
            .node_groups
            .get(&req.group_id)
            .expect("verified above");
        let proto_group = build_node_group_proto(record, &inner.workers);
        Ok(AssignNodesToGroupResponse {
            success: true,
            group_id: req.group_id.clone(),
            affected_nodes: affected,
            group: Some(proto_group),
            message: if req.unassign {
                format!("Unassigned {} node(s) from '{}'", affected, req.group_id)
            } else {
                format!("Assigned {} node(s) to '{}'", affected, req.group_id)
            },
        })
    }

    /// Drains or undrains targeted worker nodes by NodeGroup or explicit node IDs.
    ///
    /// Traces to: [REQ-OP-002], [REQ-OP-003], [NFR-REL-001]
    pub fn drain_nodes(
        &self,
        req: DrainNodesRequest,
    ) -> Result<DrainNodesResponse, SchedulingError> {
        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        let target_ids = resolve_target_node_ids(&inner, &req.node_group, &req.node_ids)?;

        for nid in &target_ids {
            if let Some(w) = inner.workers.get_mut(nid) {
                w.draining = req.drain;
                w.drained_for_upgrade = false;
            }
        }

        let count = target_ids.len() as u32;
        let action = if req.drain { "Drained" } else { "Undrained" };
        Ok(DrainNodesResponse {
            success: true,
            affected_nodes: count,
            affected_node_ids: target_ids,
            message: format!("{} {} worker node(s)", action, count),
        })
    }

    /// Signals a declarative OTA client upgrade to targeted worker nodes or NodeGroups.
    ///
    /// Traces to: ADR-007, ADR-010, [REQ-OP-001], [REQ-OP-002], [INV-001], [INV-002], [INV-003], [ANTI-003], [NFR-POW-001], [NFR-SEC-001]
    pub fn upgrade_nodes(
        &self,
        req: UpgradeNodesRequest,
    ) -> Result<UpgradeNodesResponse, SchedulingError> {
        let target_version = req.target_version.trim().to_string();
        if target_version.is_empty()
            || target_version.len() > 128
            || !target_version.bytes().all(|b| (0x21..=0x7E).contains(&b))
        {
            return Err(SchedulingError::InvalidNodeGroupRequest(
                "target_version must be 1..=128 printable non-whitespace ASCII chars".to_string(),
            ));
        }

        let apk_url = req.apk_url.trim().to_string();
        if !apk_url.is_empty() {
            if apk_url.len() > 1024 {
                return Err(SchedulingError::InvalidNodeGroupRequest(
                    "apk_url exceeds 1024 characters maximum bound".to_string(),
                ));
            }
            if !apk_url.starts_with("https://") && !apk_url.starts_with("/v1/blobs/") {
                return Err(SchedulingError::InvalidNodeGroupRequest(
                    "apk_url must be an https:// URL or a /v1/blobs/<sha256> endpoint (plaintext http:// is prohibited under mTLS)".to_string(),
                ));
            }
        }

        let apk_sha256 = req.apk_sha256.trim().to_lowercase();
        if !apk_url.is_empty() && apk_sha256.is_empty() {
            return Err(SchedulingError::InvalidNodeGroupRequest(
                "apk_sha256 is required when apk_url is provided".to_string(),
            ));
        }
        if !apk_sha256.is_empty() {
            if apk_sha256.len() != 64 || !apk_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(SchedulingError::InvalidNodeGroupRequest(
                    "apk_sha256 must be a 64-character hexadecimal SHA-256 digest".to_string(),
                ));
            }
            if apk_url.starts_with("/v1/blobs/") {
                let expected_path = format!("/v1/blobs/{apk_sha256}");
                if apk_url != expected_path {
                    return Err(SchedulingError::InvalidNodeGroupRequest(format!(
                        "apk_url '{apk_url}' does not match digest '{apk_sha256}'"
                    )));
                }
            }
        }

        let network_policy = if req.network_policy == 0 {
            UpgradeNetworkPolicy::WifiOnly as i32
        } else {
            req.network_policy
        };

        let rollout_strategy = if req.rollout_strategy == 0 {
            UpgradeRolloutStrategy::Immediate as i32
        } else {
            req.rollout_strategy
        };

        let lease_timeout_seconds = if req.lease_timeout_seconds == 0 {
            600
        } else {
            req.lease_timeout_seconds.min(86400)
        };

        let rollout_pct = if req.rollout_percentage == 0 {
            100
        } else {
            req.rollout_percentage.min(100)
        };

        let directive_template = NodeUpgradeDirective {
            target_version: target_version.clone(),
            apk_url: apk_url.clone(),
            apk_sha256: apk_sha256.clone(),
            network_policy,
            rollout_strategy,
            upgrade_lease_timeout_seconds: lease_timeout_seconds,
            drain_before_upgrade: req.drain_before_upgrade,
        };

        let now_epoch_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let (candidate_ids, eligible_ids) = {
            let inner = self.inner.read().expect("RwLock read lock poisoned");
            let cids = resolve_target_node_ids(&inner, &req.node_group, &req.node_ids)?;
            let mut eids = Vec::new();
            for nid in &cids {
                if let Some(w) = inner.workers.get(nid) {
                    if w.client_version != target_version {
                        eids.push(nid.clone());
                    }
                }
            }
            (cids, eids)
        };

        let total_eligible = eligible_ids.len();
        let (active_cohort, staged_cohort): (Vec<String>, Vec<String>) = if rollout_strategy
            == UpgradeRolloutStrategy::Rolling as i32
            && total_eligible > 0
            && rollout_pct < 100
        {
            let batch_size = (total_eligible * (rollout_pct as usize))
                .div_ceil(100)
                .max(1);
            let (active, staged) = eligible_ids.split_at(batch_size.min(total_eligible));
            (active.to_vec(), staged.to_vec())
        } else {
            (eligible_ids.clone(), Vec::new())
        };

        let rollout_id = format!("rollout-{}-{}", target_version, now_epoch_ms);
        let record = UpgradeRolloutRecord {
            rollout_id: rollout_id.clone(),
            target_version: target_version.clone(),
            directive_template: directive_template.clone(),
            rollout_strategy: if rollout_strategy == UpgradeRolloutStrategy::Rolling as i32 {
                UpgradeRolloutStrategy::Rolling
            } else {
                UpgradeRolloutStrategy::Immediate
            },
            rollout_percentage: rollout_pct,
            eligible_node_ids: eligible_ids.clone(),
            in_flight_node_ids: active_cohort.iter().cloned().collect(),
            completed_node_ids: HashSet::new(),
            failed_node_ids: HashSet::new(),
            staged_node_ids: staged_cohort.into_iter().collect(),
            lease_timeout_seconds,
            drain_before_upgrade: req.drain_before_upgrade,
            is_halted: false,
            halt_reason: None,
            created_at_epoch_ms: now_epoch_ms,
        };

        // Persist to durable storage outside the RwLock write guard
        self.rollout_store
            .save_rollout(&record)
            .map_err(|e| SchedulingError::StorageError(e.to_string()))?;

        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        for nid in &candidate_ids {
            if let Some(w) = inner.workers.get_mut(nid) {
                if w.client_version == target_version {
                    w.desired_client_version = None;
                    w.upgrade_directive = None;
                    w.upgrade_lease_deadline_ms = 0;
                    if w.drained_for_upgrade {
                        w.draining = false;
                        w.drained_for_upgrade = false;
                    }
                }
            }
        }

        let mut targeted = Vec::new();
        for nid in &active_cohort {
            if let Some(w) = inner.workers.get_mut(nid) {
                w.desired_client_version = Some(target_version.clone());
                w.upgrade_directive = Some(directive_template.clone());
                w.upgrade_lease_deadline_ms = now_epoch_ms + (lease_timeout_seconds as u64) * 1000;
                if req.drain_before_upgrade && !w.draining {
                    w.draining = true;
                    w.drained_for_upgrade = true;
                }
                targeted.push(nid.clone());
            }
        }

        inner.active_rollouts.insert(rollout_id, record);

        let count = targeted.len() as u32;
        let eligible_count = total_eligible as u32;
        Ok(UpgradeNodesResponse {
            success: true,
            targeted_nodes: count,
            targeted_node_ids: targeted,
            target_version: target_version.clone(),
            message: format!(
                "Signaled upgrade to '{}' for {} worker node(s) ({} eligible, {} in-flight)",
                target_version, count, eligible_count, count
            ),
            eligible_nodes: eligible_count,
            in_flight_upgrades: count,
        })
    }

    /// Reconciles active rollout state from durable storage and registered nodes upon orchestrator startup.
    /// Recomputes ground-truth canary cohort sizes, in-flight upgrades, and completed nodes.
    /// Prevents split-brain by pausing/halting rollouts if any canary failed, and holding promotion
    /// until the active canary cohort has completed re-registration.
    ///
    /// Traces to: ADR-010, [REQ-OP-001], [REQ-OP-002], [NFR-REL-001]
    pub fn reconcile_rollouts_from_store(&self) -> Result<usize, SchedulingError> {
        let loaded = self
            .rollout_store
            .load_rollouts()
            .map_err(|e| SchedulingError::StorageError(e.to_string()))?;

        let mut inner = self.inner.write().expect("RwLock write lock poisoned");
        let now_epoch_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut reconciled_count = 0;
        for mut rollout in loaded {
            let key = rollout.rollout_id.clone();

            // Reconcile against current registered workers
            for nid in &rollout.eligible_node_ids {
                if let Some(w) = inner.workers.get_mut(nid) {
                    if w.client_version == rollout.target_version {
                        rollout.completed_node_ids.insert(nid.clone());
                        rollout.in_flight_node_ids.remove(nid);
                        w.desired_client_version = None;
                        w.upgrade_directive = None;
                        w.upgrade_lease_deadline_ms = 0;
                        if w.drained_for_upgrade {
                            w.draining = false;
                            w.drained_for_upgrade = false;
                        }
                    } else if rollout.in_flight_node_ids.contains(nid) {
                        w.desired_client_version = Some(rollout.target_version.clone());
                        w.upgrade_directive = Some(rollout.directive_template.clone());
                        w.upgrade_lease_deadline_ms =
                            now_epoch_ms + (rollout.lease_timeout_seconds as u64) * 1000;
                        if rollout.drain_before_upgrade && !w.draining {
                            w.draining = true;
                            w.drained_for_upgrade = true;
                        }
                    }
                }
            }

            if !rollout.failed_node_ids.is_empty() {
                rollout.is_halted = true;
            }

            self.rollout_store.save_rollout(&rollout).ok();
            inner.active_rollouts.insert(key, rollout);
            reconciled_count += 1;
        }

        Ok(reconciled_count)
    }
}

fn record_node_upgrade_failure(
    inner: &mut SchedulerInner,
    node_id: &str,
    target_version: &str,
    error_code: &str,
    error_message: &str,
    is_terminal: bool,
    rollout_store: &crate::scheduler::rollout_store::RolloutStore,
) {
    if is_terminal {
        if let Some(w) = inner.workers.get_mut(node_id) {
            if w.desired_client_version.as_deref() == Some(target_version) {
                w.desired_client_version = None;
                w.upgrade_directive = None;
                w.upgrade_lease_deadline_ms = 0;
                if w.drained_for_upgrade {
                    w.draining = false;
                    w.drained_for_upgrade = false;
                }
            }
        }

        for rollout in inner.active_rollouts.values_mut() {
            if rollout.target_version == target_version
                && (rollout.in_flight_node_ids.contains(node_id)
                    || rollout.staged_node_ids.contains(&node_id.to_string())
                    || rollout.eligible_node_ids.contains(&node_id.to_string()))
            {
                rollout.in_flight_node_ids.remove(node_id);
                rollout.failed_node_ids.insert(node_id.to_string());
                rollout.is_halted = true;
                rollout.halt_reason = Some(format!(
                    "Node '{}' failed upgrade with {}: {}",
                    node_id, error_code, error_message
                ));
                rollout_store.save_rollout(rollout).ok();
            }
        }
    } else {
        // Transient failure: retain in_flight_node_ids and worker directive to allow
        // the client to retry with exponential backoff or the lease sweeper to govern timeout.
        debug!(
            node_id = %node_id,
            target_version = %target_version,
            error_code = %error_code,
            error_message = %error_message,
            "Transient upgrade failure reported; retaining in-flight canary state for retry"
        );
    }
}

fn promote_next_canary_if_ready(
    inner: &mut SchedulerInner,
    completed_node_id: &str,
    now_epoch_ms: u64,
    rollout_store: &crate::scheduler::rollout_store::RolloutStore,
) {
    let mut touched_rollouts = Vec::new();
    for (rollout_id, rollout) in inner.active_rollouts.iter_mut() {
        if rollout.is_halted {
            continue;
        }
        if rollout.in_flight_node_ids.remove(completed_node_id) {
            rollout
                .completed_node_ids
                .insert(completed_node_id.to_string());
            touched_rollouts.push(rollout_id.clone());
        }
    }

    for rollout_id in touched_rollouts {
        if let Some(rollout) = inner.active_rollouts.get_mut(&rollout_id) {
            if rollout.is_halted {
                continue;
            }
            while let Some(next_nid) = rollout.staged_node_ids.pop_front() {
                if let Some(w) = inner.workers.get_mut(&next_nid) {
                    if w.client_version == rollout.target_version {
                        rollout.completed_node_ids.insert(next_nid);
                        continue;
                    }
                    w.desired_client_version = Some(rollout.target_version.clone());
                    w.upgrade_directive = Some(rollout.directive_template.clone());
                    w.upgrade_lease_deadline_ms =
                        now_epoch_ms + (rollout.lease_timeout_seconds as u64) * 1000;
                    if rollout.drain_before_upgrade && !w.draining {
                        w.draining = true;
                        w.drained_for_upgrade = true;
                    }
                    rollout.in_flight_node_ids.insert(next_nid);
                    break;
                }
            }
            rollout_store.save_rollout(rollout).ok();
        }
    }
}

fn is_terminal_task_state(state: TaskState) -> bool {
    matches!(
        state,
        TaskState::Completed | TaskState::Failed | TaskState::TimedOut | TaskState::Cancelled
    )
}

fn validate_group_id(group_id: &str) -> Result<(), SchedulingError> {
    if group_id.is_empty()
        || group_id.len() > 64
        || !group_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(SchedulingError::InvalidGroupId(group_id.to_string()));
    }
    Ok(())
}

fn validate_partitions(partitions: &[TaskPartitionSpec]) -> Result<(), SchedulingError> {
    if partitions.is_empty() {
        return Err(SchedulingError::InvalidGroupPartitions(
            "partitions must not be empty".to_string(),
        ));
    }
    if partitions.len() > MAX_GROUP_PARTITIONS {
        return Err(SchedulingError::InvalidGroupPartitions(format!(
            "partitions count {} exceeds MAX_GROUP_PARTITIONS ({})",
            partitions.len(),
            MAX_GROUP_PARTITIONS
        )));
    }
    Ok(())
}

fn validate_task_template(template: &TaskTemplate) -> Result<(), SchedulingError> {
    let engine = ExecutionEngine::try_from(template.engine).map_err(|_| {
        SchedulingError::InvalidTaskTemplate(format!(
            "unknown execution engine {}",
            template.engine
        ))
    })?;
    match engine {
        ExecutionEngine::WasmWasi => {}
        ExecutionEngine::ToyboxUser | ExecutionEngine::RootShell => {
            if template.shell_command.trim().is_empty() {
                return Err(SchedulingError::InvalidTaskTemplate(
                    "shell_command must not be empty for shell execution engines".to_string(),
                ));
            }
        }
        ExecutionEngine::Unspecified => {
            return Err(SchedulingError::InvalidTaskTemplate(
                "execution engine must be WasmWasi, ToyboxUser, or RootShell".to_string(),
            ));
        }
    }
    if template.timeout_seconds == 0 {
        return Err(SchedulingError::InvalidTaskTemplate(
            "timeout_seconds must be greater than 0".to_string(),
        ));
    }
    validate_network_egress_policy_params(
        template.engine,
        template.egress_policy,
        &template.allowed_hostnames,
        template.max_egress_bytes,
    )?;
    Ok(())
}

fn is_reserved_group_task_id(task_id: &str) -> bool {
    let mut parts = task_id.rsplitn(3, ':');
    let (Some(p_part), Some(e_part), Some(g_part)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !g_part.is_empty()
        && e_part.starts_with('e')
        && e_part.len() > 1
        && e_part[1..].bytes().all(|b| b.is_ascii_digit())
        && p_part.starts_with('p')
        && p_part.len() > 1
        && p_part[1..].bytes().all(|b| b.is_ascii_digit())
}

#[allow(deprecated)]
fn build_partition_task_record(
    group_id: &str,
    epoch: u64,
    index: usize,
    template: &TaskTemplate,
    partition: &TaskPartitionSpec,
) -> TaskRecord {
    let mut env_vars = template.env_vars.clone();
    for (k, v) in &partition.env_overrides {
        env_vars.insert(k.clone(), v.clone());
    }
    let task_id = format!("{}:e{}:p{}", group_id, epoch, index);
    TaskRecord::new(TaskSpec {
        task_id,
        run_attempt: 0,
        engine: template.engine,
        timeout_seconds: template.timeout_seconds,
        entrypoint: template.entrypoint.clone(),
        env_vars,
        wasm_bytecode: Vec::new(),
        shell_command: template.shell_command.clone(),
        artifact_sha256: template.artifact_sha256.clone(),
        requires_unmetered: template.requires_unmetered,
        artifact_url: String::new(),
        group_id: group_id.to_string(),
        group_epoch: epoch,
        node_group_affinity: template.node_group_affinity.clone(),
        egress_policy: template.egress_policy,
        allowed_hostnames: template.allowed_hostnames.clone(),
        max_egress_bytes: template.max_egress_bytes,
    })
}

fn queue_wifi_cancel(inner: &mut SchedulerInner, task: &TaskRecord) {
    for node_id in [&task.assigned_node_id, &task.speculative_node_id]
        .into_iter()
        .flatten()
    {
        let queue = inner
            .pending_cancellations
            .entry(node_id.clone())
            .or_default();
        if !queue.contains(&task.spec.task_id) {
            queue.push(task.spec.task_id.clone());
        }
    }
}

fn reconcile_group_state(inner: &mut SchedulerInner, group_id: &str, now_epoch_ms: u64) {
    let Some(group) = inner.groups.get(group_id) else {
        return;
    };
    if group.state == TaskGroupState::Cancelled {
        return;
    }

    let current_ids = group.current_task_ids.clone();
    let mut draining_ids = group.draining_task_ids.clone();
    draining_ids.retain(|tid| {
        inner
            .tasks
            .get(tid)
            .map(|t| !is_terminal_task_state(t.state))
            .unwrap_or(false)
    });

    let mut all_terminal = true;
    let mut any_failed = false;
    let mut all_cancelled = !current_ids.is_empty();

    for tid in &current_ids {
        if let Some(t) = inner.tasks.get(tid) {
            if !is_terminal_task_state(t.state) {
                all_terminal = false;
                all_cancelled = false;
                break;
            }
            if t.state == TaskState::Failed || t.state == TaskState::TimedOut {
                any_failed = true;
                all_cancelled = false;
            } else if t.state != TaskState::Cancelled {
                all_cancelled = false;
            }
        }
    }

    let next_state = if all_terminal && draining_ids.is_empty() {
        if any_failed {
            TaskGroupState::Failed
        } else if all_cancelled {
            TaskGroupState::Cancelled
        } else {
            TaskGroupState::Completed
        }
    } else if !draining_ids.is_empty() {
        TaskGroupState::Draining
    } else {
        TaskGroupState::Active
    };

    if let Some(group_mut) = inner.groups.get_mut(group_id) {
        group_mut.draining_task_ids = draining_ids;
        group_mut.state = next_state;
        if now_epoch_ms > 0 {
            group_mut.updated_at_epoch_ms = now_epoch_ms;
        }
    }
}

fn task_record_to_info(record: &TaskRecord) -> crate::TaskInfo {
    let (exit_code, duration_ms, error_message) = match &record.result {
        Some(res) => (
            res.exit_code,
            res.execution_duration_ms,
            res.error_message.clone(),
        ),
        None => (0, 0, String::new()),
    };
    crate::TaskInfo {
        task_id: record.spec.task_id.clone(),
        state: record.state as i32,
        engine: record.spec.engine,
        run_attempt: record.active_attempt,
        assigned_node_id: record.assigned_node_id.clone().unwrap_or_default(),
        timeout_seconds: record.spec.timeout_seconds,
        requires_unmetered: record.spec.requires_unmetered,
        exit_code,
        execution_duration_ms: duration_ms,
        error_message,
        speculative_node_id: record.speculative_node_id.clone().unwrap_or_default(),
        node_group_affinity: record.spec.node_group_affinity.clone(),
    }
}

fn validate_labels(
    labels: &HashMap<String, String>,
    allow_reserved_prefix: bool,
) -> Result<BTreeMap<String, String>, SchedulingError> {
    if labels.len() > MAX_GROUP_LABELS {
        return Err(SchedulingError::InvalidNodeLabels(format!(
            "label count {} exceeds MAX_GROUP_LABELS ({})",
            labels.len(),
            MAX_GROUP_LABELS
        )));
    }
    let mut out = BTreeMap::new();
    for (k, v) in labels {
        if k.is_empty()
            || k.len() > 128
            || !k
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-'))
        {
            return Err(SchedulingError::InvalidNodeLabels(format!(
                "invalid label key '{}': must match ^[a-zA-Z0-9_./-]{{1,128}}$",
                k
            )));
        }
        if !allow_reserved_prefix && k.starts_with("androgrid.io/") {
            return Err(SchedulingError::InvalidNodeLabels(format!(
                "label key '{}' uses reserved 'androgrid.io/' prefix",
                k
            )));
        }
        if v.is_empty() || v.len() > 128 || !v.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
            return Err(SchedulingError::InvalidNodeLabels(format!(
                "invalid label value for key '{}': must be 1..=128 printable non-whitespace ASCII chars",
                k
            )));
        }
        out.insert(k.clone(), v.clone());
    }
    Ok(out)
}

fn validate_node_id_batch(
    node_ids: &[String],
    allow_empty: bool,
) -> Result<Vec<String>, SchedulingError> {
    if !allow_empty && node_ids.is_empty() {
        return Err(SchedulingError::InvalidNodeGroupRequest(
            "node_ids must not be empty".to_string(),
        ));
    }
    if node_ids.len() > MAX_ASSIGN_NODES_BATCH {
        return Err(SchedulingError::InvalidNodeGroupRequest(format!(
            "node_ids count {} exceeds MAX_ASSIGN_NODES_BATCH ({})",
            node_ids.len(),
            MAX_ASSIGN_NODES_BATCH
        )));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(node_ids.len());
    for nid in node_ids {
        if nid.is_empty() || nid.len() > 128 || !nid.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
            return Err(SchedulingError::InvalidNodeGroupRequest(
                "node_ids elements must be 1..=128 printable non-whitespace ASCII chars"
                    .to_string(),
            ));
        }
        if seen.insert(nid.clone()) {
            out.push(nid.clone());
        }
    }
    Ok(out)
}

fn pending_desired_version(worker: &WorkerRecord) -> String {
    match worker.desired_client_version.as_deref() {
        Some(target) if target != worker.client_version => target.to_string(),
        _ => String::new(),
    }
}

/// Validates network egress policy fields in a TaskSpec.
///
/// Validates the network egress specification of a compute task against security invariants.
///
/// Traces to: [INV-006], [ANTI-003], [NFR-SEC-001], ADR-011
pub fn validate_network_egress_policy(spec: &TaskSpec) -> Result<(), SchedulingError> {
    validate_network_egress_policy_params(
        spec.engine,
        spec.egress_policy,
        &spec.allowed_hostnames,
        spec.max_egress_bytes,
    )
}

/// Validates network egress parameters against cluster security invariants.
///
/// Traces to: [INV-006], [ANTI-003], [NFR-SEC-001], ADR-011
pub fn validate_network_egress_policy_params(
    engine: i32,
    egress_policy: i32,
    allowed_hostnames: &[String],
    max_egress_bytes: u64,
) -> Result<(), SchedulingError> {
    match egress_policy {
        0 | 1 => {
            // Unspecified or Blocked
            if !allowed_hostnames.is_empty() || max_egress_bytes > 0 {
                return Err(SchedulingError::InvalidNetworkEgress(
                    "allowed_hostnames and max_egress_bytes must be empty/zero when egress_policy is BLOCKED or unspecified"
                        .to_string(),
                ));
            }
            Ok(())
        }
        2 => {
            // NetworkEgressPolicyAllowlist
            if engine != ExecutionEngine::WasmWasi as i32 {
                return Err(SchedulingError::InvalidNetworkEgress(
                    "Network egress policy ALLOWLIST is only supported for WasmWasi workloads"
                        .to_string(),
                ));
            }
            if max_egress_bytes == 0 {
                return Err(SchedulingError::InvalidNetworkEgress(
                    "max_egress_bytes must be greater than zero when egress_policy is NETWORK_EGRESS_POLICY_ALLOWLIST (fail-closed default)".to_string(),
                ));
            }
            if max_egress_bytes > 64 * 1024 * 1024 {
                return Err(SchedulingError::InvalidNetworkEgress(
                    "max_egress_bytes exceeds maximum allowable bound of 64 MB".to_string(),
                ));
            }
            if allowed_hostnames.is_empty() {
                return Err(SchedulingError::InvalidNetworkEgress(
                    "allowed_hostnames must not be empty when egress_policy is NETWORK_EGRESS_POLICY_ALLOWLIST".to_string(),
                ));
            }
            if allowed_hostnames.len() > 64 {
                return Err(SchedulingError::InvalidNetworkEgress(
                    "allowed_hostnames count exceeds maximum limit of 64".to_string(),
                ));
            }
            for host in allowed_hostnames {
                let trimmed = host.trim();
                if trimmed.is_empty() {
                    return Err(SchedulingError::InvalidNetworkEgress(
                        "allowed_hostnames cannot contain empty hostnames".to_string(),
                    ));
                }
                if trimmed == "*" || trimmed == "*.*" {
                    return Err(SchedulingError::InvalidNetworkEgress(
                        "Bare wildcard '*' is strictly forbidden in allowed_hostnames".to_string(),
                    ));
                }
                if trimmed.len() > 253 {
                    return Err(SchedulingError::InvalidNetworkEgress(format!(
                        "Hostname '{trimmed}' exceeds maximum RFC 1035 length limit of 253 octets"
                    )));
                }
                if !trimmed
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'*')
                {
                    return Err(SchedulingError::InvalidNetworkEgress(format!(
                        "Invalid characters in hostname '{trimmed}': allowed characters are ASCII a-z, 0-9, hyphen, period, and leading wildcard '*.'"
                    )));
                }
                if trimmed.contains("://")
                    || trimmed.contains('/')
                    || trimmed.contains(':')
                    || trimmed.contains(' ')
                {
                    return Err(SchedulingError::InvalidNetworkEgress(format!(
                        "Invalid hostname in allowed_hostnames: '{trimmed}'. Must be a FQDN or wildcard without scheme, port, or path."
                    )));
                }
                if trimmed.ends_with('.') || trimmed.starts_with('.') || trimmed.contains("..") {
                    return Err(SchedulingError::InvalidNetworkEgress(format!(
                        "Invalid hostname format in allowed_hostnames: '{trimmed}'. Leading, trailing, or consecutive dots are forbidden."
                    )));
                }
                let rest = trimmed.strip_prefix("*.").unwrap_or(trimmed);
                if rest.contains('*') {
                    return Err(SchedulingError::InvalidNetworkEgress(format!(
                        "Invalid wildcard placement in allowed_hostnames: '{trimmed}'. Wildcard '*' is only permitted as a leading '*.' prefix."
                    )));
                }
                let labels: Vec<&str> = rest.split('.').collect();
                if labels.len() < 2 {
                    return Err(SchedulingError::InvalidNetworkEgress(format!(
                        "Invalid hostname in allowed_hostnames: '{trimmed}'. Must contain at least two dot-separated labels (e.g., 'example.com')."
                    )));
                }
                let tld = labels.last().unwrap();
                let is_valid_tld = tld.len() >= 2
                    && (tld.chars().all(|c| c.is_ascii_alphabetic())
                        || (tld.starts_with("xn--")
                            && tld.len() > 4
                            && tld[4..]
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '-')));
                if !is_valid_tld {
                    return Err(SchedulingError::InvalidNetworkEgress(format!(
                        "Invalid hostname in allowed_hostnames: '{trimmed}'. Top-level domain must be valid ASCII alphabetic or punycode."
                    )));
                }
                let lower = trimmed.to_ascii_lowercase();
                if lower.parse::<std::net::IpAddr>().is_ok() {
                    return Err(SchedulingError::InvalidNetworkEgress(format!(
                        "Host '{trimmed}' in allowed_hostnames is an IP literal; must be a domain name or wildcard"
                    )));
                }
                if lower == "localhost" || lower.ends_with(".localhost") {
                    return Err(SchedulingError::InvalidNetworkEgress(format!(
                        "Host '{trimmed}' in allowed_hostnames targets a forbidden localhost address"
                    )));
                }
                if let Some(domain_part) = lower.strip_prefix("*.") {
                    let parts: Vec<&str> = domain_part.split('.').collect();
                    if parts.len() < 2 {
                        return Err(SchedulingError::InvalidNetworkEgress(format!(
                            "Wildcard '{trimmed}' must have at least three dot-separated components (e.g. '*.api.example.com')"
                        )));
                    }
                    const FORBIDDEN_SUFFIXES: &[&str] = &[
                        "com",
                        "org",
                        "net",
                        "edu",
                        "gov",
                        "mil",
                        "io",
                        "co.uk",
                        "org.uk",
                        "gov.uk",
                        "com.au",
                        "net.au",
                        "co.jp",
                        "com.br",
                        "co.nz",
                        "com.sg",
                        "co.za",
                        "de",
                        "fr",
                        "nl",
                        "ru",
                        "cn",
                        "in",
                        "uk",
                        "au",
                        "ca",
                        "jp",
                        "eu",
                        "ai",
                        "app",
                        "dev",
                        "xyz",
                        "cloud",
                        "workers.dev",
                        "amazonaws.com",
                        "github.io",
                        "vercel.app",
                        "netlify.app",
                        "pages.dev",
                        "appspot.com",
                    ];
                    if FORBIDDEN_SUFFIXES.contains(&domain_part) {
                        return Err(SchedulingError::InvalidNetworkEgress(format!(
                            "Wildcard '{trimmed}' targets a public suffix or top-level domain"
                        )));
                    }
                }
            }
            Ok(())
        }
        other => Err(SchedulingError::InvalidNetworkEgress(format!(
            "Unknown egress_policy value: {other}"
        ))),
    }
}

fn validate_node_group_affinity(
    node_groups: &HashMap<String, NodeGroupRecord>,
    affinity: &str,
) -> Result<(), SchedulingError> {
    if affinity.is_empty() {
        return Ok(());
    }
    validate_group_id(affinity)?;
    if !node_groups.contains_key(affinity) {
        return Err(SchedulingError::NodeGroupNotFound(affinity.to_string()));
    }
    Ok(())
}

fn is_task_eligible_for_worker(
    spec: &TaskSpec,
    is_rooted: bool,
    allow_root: bool,
    node_groups: &HashMap<String, NodeGroupRecord>,
    worker: &WorkerRecord,
    cached_effective_labels: Option<&BTreeMap<String, String>>,
) -> bool {
    if spec.engine == ExecutionEngine::RootShell as i32 && (!is_rooted || !allow_root) {
        return false;
    }
    if !spec.node_group_affinity.is_empty()
        && !is_worker_in_node_group(
            node_groups,
            worker,
            cached_effective_labels,
            &spec.node_group_affinity,
        )
    {
        return false;
    }
    true
}

fn selector_matches_labels(
    selector: &BTreeMap<String, String>,
    effective_labels: &BTreeMap<String, String>,
) -> bool {
    !selector.is_empty()
        && selector
            .iter()
            .all(|(k, v)| effective_labels.get(k) == Some(v))
}

fn is_worker_in_node_group(
    node_groups: &HashMap<String, NodeGroupRecord>,
    worker: &WorkerRecord,
    cached_effective_labels: Option<&BTreeMap<String, String>>,
    group_id: &str,
) -> bool {
    if let Some(ref explicit) = worker.explicit_node_group {
        return explicit == group_id;
    }
    let Some(group) = node_groups.get(group_id) else {
        return false;
    };
    if group.label_selector.is_empty() {
        return false;
    }
    let owned_labels;
    let effective = match cached_effective_labels {
        Some(labels) => labels,
        None => {
            owned_labels = worker.effective_labels();
            &owned_labels
        }
    };
    selector_matches_labels(&group.label_selector, effective)
}

fn resolve_effective_node_group(
    node_groups: &HashMap<String, NodeGroupRecord>,
    worker: &WorkerRecord,
    effective_labels: &BTreeMap<String, String>,
) -> Option<String> {
    if let Some(ref explicit) = worker.explicit_node_group {
        return Some(explicit.clone());
    }
    let mut matches: Vec<&str> = node_groups
        .values()
        .filter(|g| selector_matches_labels(&g.label_selector, effective_labels))
        .map(|g| g.group_id.as_str())
        .collect();
    matches.sort_unstable();
    matches.first().map(|s| (*s).to_string())
}

fn build_node_group_proto(
    record: &NodeGroupRecord,
    workers: &HashMap<String, WorkerRecord>,
) -> NodeGroup {
    let cached: Vec<(&WorkerRecord, Option<BTreeMap<String, String>>)> = workers
        .values()
        .map(|w| {
            let labels = if w.explicit_node_group.is_none() && !record.label_selector.is_empty() {
                Some(w.effective_labels())
            } else {
                None
            };
            (w, labels)
        })
        .collect();
    build_node_group_proto_cached(record, &cached)
}

fn build_node_group_proto_cached(
    record: &NodeGroupRecord,
    workers: &[(&WorkerRecord, Option<BTreeMap<String, String>>)],
) -> NodeGroup {
    let active_node_count = workers
        .iter()
        .filter(|(w, cached_labels)| {
            if let Some(ref explicit) = w.explicit_node_group {
                explicit == &record.group_id
            } else if let Some(ref effective) = cached_labels {
                selector_matches_labels(&record.label_selector, effective)
            } else {
                false
            }
        })
        .count() as u32;
    NodeGroup {
        group_id: record.group_id.clone(),
        description: record.description.clone(),
        label_selector: record
            .label_selector
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        member_node_ids: record.member_node_ids.iter().cloned().collect(),
        active_node_count,
        created_at_epoch_ms: record.created_at_epoch_ms,
        updated_at_epoch_ms: record.updated_at_epoch_ms,
    }
}

fn resolve_target_node_ids(
    inner: &SchedulerInner,
    node_group: &str,
    node_ids: &[String],
) -> Result<Vec<String>, SchedulingError> {
    let has_group = !node_group.is_empty();
    let has_nodes = !node_ids.is_empty();
    if has_group == has_nodes {
        return Err(SchedulingError::InvalidNodeGroupRequest(
            "exactly one of node_group or node_ids must be provided".to_string(),
        ));
    }

    if has_group {
        validate_group_id(node_group)?;
        if !inner.node_groups.contains_key(node_group) {
            return Err(SchedulingError::NodeGroupNotFound(node_group.to_string()));
        }
        let mut matched: Vec<String> = inner
            .workers
            .iter()
            .filter(|(_, w)| is_worker_in_node_group(&inner.node_groups, w, None, node_group))
            .map(|(nid, _)| nid.clone())
            .collect();
        matched.sort();
        Ok(matched)
    } else {
        let deduped = validate_node_id_batch(node_ids, false)?;
        for nid in &deduped {
            if !inner.workers.contains_key(nid) {
                return Err(SchedulingError::NodeNotFound(nid.clone()));
            }
        }
        Ok(deduped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LastUpgradeOutcome, UpgradeInstallStatus};
    use std::collections::HashMap;

    fn make_test_capabilities(is_rooted: bool, is_metered: bool) -> NodeCapabilities {
        NodeCapabilities {
            is_rooted,
            supported_engines: vec![
                ExecutionEngine::WasmWasi as i32,
                ExecutionEngine::RootShell as i32,
            ],
            cpu_cores: 8,
            total_ram_bytes: 8 * 1024 * 1024 * 1024,
            os_version: "14".to_string(),
            abi: "arm64-v8a".to_string(),
            is_metered,
            current_transport: if is_metered {
                NetworkTransportType::NetworkTransportCellularWan as i32
            } else {
                NetworkTransportType::NetworkTransportWifiLan as i32
            },
            max_cellular_task_duration_seconds: 180,
            battery_temperature_celsius: 0,
            thermal_status: 0,
        }
    }

    #[allow(deprecated)]
    fn make_test_task(
        task_id: &str,
        timeout_seconds: u32,
        requires_unmetered: bool,
        engine: ExecutionEngine,
    ) -> TaskSpec {
        let wasm_bytecode = if engine == ExecutionEngine::WasmWasi {
            vec![
                0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
                0x07, 0x0a, 0x01, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00,
                0x00, // export _start
            ]
        } else {
            Vec::new()
        };
        TaskSpec {
            task_id: task_id.to_string(),
            run_attempt: 0,
            engine: engine as i32,
            timeout_seconds,
            entrypoint: "_start".to_string(),
            env_vars: HashMap::new(),
            wasm_bytecode,
            shell_command: String::new(),
            artifact_sha256: "dummy-sha256".to_string(),
            requires_unmetered,
            artifact_url: String::new(),
            group_id: String::new(),
            group_epoch: 0,
            node_group_affinity: String::new(),
            egress_policy: 0,
            allowed_hostnames: Vec::new(),
            max_egress_bytes: 0,
        }
    }

    #[test]
    fn test_network_egress_policy_validation() {
        let scheduler = ClusterScheduler::new();

        // 1. ALLOWLIST with empty allowed_hostnames is rejected
        let mut task_empty_allowlist =
            make_test_task("task-egress-01", 30, false, ExecutionEngine::WasmWasi);
        task_empty_allowlist.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_empty_allowlist.allowed_hostnames = vec![];
        let err = scheduler.submit_task(task_empty_allowlist).unwrap_err();
        assert!(matches!(err, SchedulingError::InvalidNetworkEgress(_)));

        // 2. ALLOWLIST with scheme or path in hostname is rejected
        let mut task_scheme =
            make_test_task("task-egress-02", 30, false, ExecutionEngine::WasmWasi);
        task_scheme.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_scheme.allowed_hostnames = vec!["https://api.example.com".to_string()];
        let err2 = scheduler.submit_task(task_scheme).unwrap_err();
        assert!(matches!(err2, SchedulingError::InvalidNetworkEgress(_)));

        // 3. ALLOWLIST with private/loopback address is rejected
        let mut task_private =
            make_test_task("task-egress-03", 30, false, ExecutionEngine::WasmWasi);
        task_private.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_private.allowed_hostnames = vec!["127.0.0.1".to_string()];
        let err3 = scheduler.submit_task(task_private).unwrap_err();
        assert!(matches!(err3, SchedulingError::InvalidNetworkEgress(_)));

        // 4. Valid FQDN and wildcard succeeds (requires max_egress_bytes > 0)
        let mut task_valid = make_test_task("task-egress-04", 30, false, ExecutionEngine::WasmWasi);
        task_valid.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_valid.max_egress_bytes = 1024 * 1024;
        task_valid.allowed_hostnames = vec![
            "api.example.com".to_string(),
            "*.api.trusted.org".to_string(),
        ];
        assert!(scheduler.submit_task(task_valid).is_ok());

        // 5. ALLOWLIST with max_egress_bytes == 0 is rejected (fail-closed)
        let mut task_zero_quota =
            make_test_task("task-egress-05", 30, false, ExecutionEngine::WasmWasi);
        task_zero_quota.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_zero_quota.max_egress_bytes = 0;
        task_zero_quota.allowed_hostnames = vec!["api.example.com".to_string()];
        let err_zero = scheduler.submit_task(task_zero_quota).unwrap_err();
        assert!(matches!(err_zero, SchedulingError::InvalidNetworkEgress(_)));

        // 6. Bare wildcard '*' is rejected
        let mut task_bare_wildcard =
            make_test_task("task-egress-06", 30, false, ExecutionEngine::WasmWasi);
        task_bare_wildcard.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_bare_wildcard.max_egress_bytes = 1024;
        task_bare_wildcard.allowed_hostnames = vec!["*".to_string()];
        let err_bare = scheduler.submit_task(task_bare_wildcard).unwrap_err();
        assert!(matches!(err_bare, SchedulingError::InvalidNetworkEgress(_)));

        // 7. Public suffix wildcard '*.com' or '*.co.uk' is rejected
        let mut task_ps_wildcard =
            make_test_task("task-egress-07", 30, false, ExecutionEngine::WasmWasi);
        task_ps_wildcard.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_ps_wildcard.max_egress_bytes = 1024;
        task_ps_wildcard.allowed_hostnames = vec!["*.co.uk".to_string()];
        let err_ps = scheduler.submit_task(task_ps_wildcard).unwrap_err();
        assert!(matches!(err_ps, SchedulingError::InvalidNetworkEgress(_)));

        // 8. BLOCKED policy succeeds
        let mut task_blocked =
            make_test_task("task-egress-08", 30, false, ExecutionEngine::WasmWasi);
        task_blocked.egress_policy = NetworkEgressPolicy::Blocked as i32;
        assert!(scheduler.submit_task(task_blocked).is_ok());

        // 9. fcm.googleapis.com and fda.gov succeed without false positive rejection
        let mut task_fda = make_test_task("task-egress-09", 30, false, ExecutionEngine::WasmWasi);
        task_fda.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_fda.max_egress_bytes = 1024 * 1024;
        task_fda.allowed_hostnames = vec!["fcm.googleapis.com".to_string(), "fda.gov".to_string()];
        assert!(scheduler.submit_task(task_fda).is_ok());

        // 10. ALLOWLIST with non-WasmWasi engine is rejected
        let mut task_shell_egress =
            make_test_task("task-egress-10", 30, false, ExecutionEngine::ToyboxUser);
        task_shell_egress.shell_command = "echo hi".to_string();
        task_shell_egress.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_shell_egress.max_egress_bytes = 1024;
        task_shell_egress.allowed_hostnames = vec!["api.example.com".to_string()];
        let err_engine = scheduler.submit_task(task_shell_egress).unwrap_err();
        assert!(matches!(
            err_engine,
            SchedulingError::InvalidNetworkEgress(_)
        ));

        // 11. ALLOWLIST with > 64 allowed hostnames is rejected
        let mut task_too_many_hosts =
            make_test_task("task-egress-11", 30, false, ExecutionEngine::WasmWasi);
        task_too_many_hosts.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_too_many_hosts.max_egress_bytes = 1024;
        task_too_many_hosts.allowed_hostnames =
            (0..65).map(|i| format!("host{i}.example.com")).collect();
        let err_too_many = scheduler.submit_task(task_too_many_hosts).unwrap_err();
        assert!(matches!(
            err_too_many,
            SchedulingError::InvalidNetworkEgress(_)
        ));

        // 12. ALLOWLIST with max_egress_bytes > 64MB is rejected
        let mut task_over_bound =
            make_test_task("task-egress-12", 30, false, ExecutionEngine::WasmWasi);
        task_over_bound.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_over_bound.max_egress_bytes = 65 * 1024 * 1024;
        task_over_bound.allowed_hostnames = vec!["api.example.com".to_string()];
        let err_bound = scheduler.submit_task(task_over_bound).unwrap_err();
        assert!(matches!(
            err_bound,
            SchedulingError::InvalidNetworkEgress(_)
        ));

        // 13. IP literal in allowed_hostnames is rejected
        let mut task_cgnat = make_test_task("task-egress-13", 30, false, ExecutionEngine::WasmWasi);
        task_cgnat.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_cgnat.max_egress_bytes = 1024;
        task_cgnat.allowed_hostnames = vec!["100.65.0.1".to_string()];
        let err_cgnat = scheduler.submit_task(task_cgnat).unwrap_err();
        assert!(matches!(
            err_cgnat,
            SchedulingError::InvalidNetworkEgress(_)
        ));

        // 14. Modern TLD / cloud suffix wildcard (*.dev, *.workers.dev) is rejected
        let mut task_cloud = make_test_task("task-egress-14", 30, false, ExecutionEngine::WasmWasi);
        task_cloud.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_cloud.max_egress_bytes = 1024;
        task_cloud.allowed_hostnames = vec!["*.workers.dev".to_string()];
        let err_cloud = scheduler.submit_task(task_cloud).unwrap_err();
        assert!(matches!(
            err_cloud,
            SchedulingError::InvalidNetworkEgress(_)
        ));

        // 15. Trailing dot or mid-string wildcard is rejected
        let mut task_dot = make_test_task("task-egress-15", 30, false, ExecutionEngine::WasmWasi);
        task_dot.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_dot.max_egress_bytes = 1024;
        task_dot.allowed_hostnames = vec!["api.example.com.".to_string()];
        let err_dot = scheduler.submit_task(task_dot).unwrap_err();
        assert!(matches!(err_dot, SchedulingError::InvalidNetworkEgress(_)));

        // 16. Non-ASCII multi-byte UTF-8 hostname does not panic and is rejected
        let mut task_utf8 = make_test_task("task-egress-16", 30, false, ExecutionEngine::WasmWasi);
        task_utf8.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_utf8.max_egress_bytes = 1024;
        task_utf8.allowed_hostnames = vec!["a\u{00e9}.com".to_string()];
        let err_utf8 = scheduler.submit_task(task_utf8).unwrap_err();
        assert!(matches!(err_utf8, SchedulingError::InvalidNetworkEgress(_)));

        // 17. Invalid wildcards (*a. or a*.) are rejected
        let mut task_bad_wc =
            make_test_task("task-egress-17", 30, false, ExecutionEngine::WasmWasi);
        task_bad_wc.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_bad_wc.max_egress_bytes = 1024;
        task_bad_wc.allowed_hostnames = vec!["*a.example.com".to_string()];
        let err_bad_wc = scheduler.submit_task(task_bad_wc).unwrap_err();
        assert!(matches!(
            err_bad_wc,
            SchedulingError::InvalidNetworkEgress(_)
        ));

        // 18. Subdomain of localhost (*.localhost / evil.localhost) is rejected
        let mut task_sub_lh =
            make_test_task("task-egress-18", 30, false, ExecutionEngine::WasmWasi);
        task_sub_lh.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_sub_lh.max_egress_bytes = 1024;
        task_sub_lh.allowed_hostnames = vec!["evil.localhost".to_string()];
        let err_sub_lh = scheduler.submit_task(task_sub_lh).unwrap_err();
        assert!(matches!(
            err_sub_lh,
            SchedulingError::InvalidNetworkEgress(_)
        ));

        // 19. Additional cloud suffixes (*.vercel.app, *.pages.dev) are rejected
        let mut task_cloud2 =
            make_test_task("task-egress-19", 30, false, ExecutionEngine::WasmWasi);
        task_cloud2.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_cloud2.max_egress_bytes = 1024;
        task_cloud2.allowed_hostnames = vec!["*.vercel.app".to_string()];
        let err_cloud2 = scheduler.submit_task(task_cloud2).unwrap_err();
        assert!(matches!(
            err_cloud2,
            SchedulingError::InvalidNetworkEgress(_)
        ));
    }

    #[test]
    fn test_cellular_worker_skips_task_with_network_egress() {
        let scheduler = ClusterScheduler::new();
        let caps = make_test_capabilities(false, false);
        scheduler
            .register_node(
                "cell-egress-node".to_string(),
                caps,
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();

        // Task has egress policy set to ALLOWLIST
        let mut task_egress =
            make_test_task("task-egress-cell", 60, false, ExecutionEngine::WasmWasi);
        task_egress.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        task_egress.allowed_hostnames = vec!["api.example.com".to_string()];
        task_egress.max_egress_bytes = 1024 * 1024;
        scheduler.submit_task(task_egress).unwrap();

        // Cellular worker attempts to claim task -> must be skipped per [ANTI-003], [INV-003], [NFR-POW-001]
        let claim = scheduler
            .claim_cellular_task("cell-egress-node", 90, true, 25, 0, 1000)
            .unwrap();
        assert!(
            !claim.task_available,
            "Cellular worker must not be leased tasks with network egress"
        );
    }

    #[test]
    fn test_egress_task_disables_speculative_dual_assignment() {
        let scheduler = ClusterScheduler::new();
        let wifi_caps = make_test_capabilities(false, false);
        let reg = scheduler
            .register_node(
                "wifi-worker-1".to_string(),
                wifi_caps,
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();

        let mut egress_task =
            make_test_task("task-egress-no-dual", 60, false, ExecutionEngine::WasmWasi);
        egress_task.egress_policy = NetworkEgressPolicy::Allowlist as i32;
        egress_task.allowed_hostnames = vec!["api.example.com".to_string()];
        egress_task.max_egress_bytes = 1024 * 1024;
        scheduler.submit_task(egress_task).unwrap();

        // First worker claims the task
        let sync1 = scheduler
            .sync_node_state("wifi-worker-1", &reg.session_token, &[], 1000)
            .unwrap();
        assert_eq!(sync1.desired_tasks.len(), 1);

        // Register second Wi-Fi worker
        let wifi_caps2 = make_test_capabilities(false, false);
        let reg2 = scheduler
            .register_node(
                "wifi-worker-2".to_string(),
                wifi_caps2,
                "1.0.0".to_string(),
                1001,
            )
            .unwrap();

        // Second worker syncs; speculative dual-assignment MUST NOT preempt the active egress task
        let sync2 = scheduler
            .sync_node_state("wifi-worker-2", &reg2.session_token, &[], 1002)
            .unwrap();
        assert!(
            sync2.desired_tasks.is_empty(),
            "Speculative dual-assignment must be disabled for tasks with egress_policy == ALLOWLIST"
        );
    }

    #[test]
    fn test_static_wasi_validator_rejects_disallowed_egress_imports() {
        let scheduler = ClusterScheduler::new();

        // Construct minimal valid WebAssembly module importing androgrid_net::http_fetch
        let mut wasm_bytes = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        // Import section (ID 2)
        // Module: "androgrid_net", Field: "http_fetch", Kind: 0 (Func), TypeIdx: 0
        let mut import_payload = Vec::new();
        import_payload.push(1); // 1 import
        import_payload.push(13); // mod length
        import_payload.extend_from_slice(b"androgrid_net");
        import_payload.push(10); // field length
        import_payload.extend_from_slice(b"http_fetch");
        import_payload.push(0); // func import
        import_payload.push(0); // type index 0

        wasm_bytes.push(2); // section id 2
        wasm_bytes.push(import_payload.len() as u8); // section length
        wasm_bytes.extend_from_slice(&import_payload);

        // Export section (ID 7) exporting "_start"
        let mut export_payload = Vec::new();
        export_payload.push(1); // 1 export
        export_payload.push(6); // export name length
        export_payload.extend_from_slice(b"_start");
        export_payload.push(0); // func export
        export_payload.push(0); // func index 0

        wasm_bytes.push(7); // section id 7
        wasm_bytes.push(export_payload.len() as u8);
        wasm_bytes.extend_from_slice(&export_payload);

        let mut task = make_test_task("task-import-test", 30, false, ExecutionEngine::WasmWasi);
        task.wasm_bytecode = wasm_bytes;
        task.egress_policy = NetworkEgressPolicy::Blocked as i32;

        // Submitting with BLOCKED policy must be rejected because module imports androgrid_net
        let err = scheduler.submit_task(task).unwrap_err();
        assert!(
            matches!(err, SchedulingError::InvalidNetworkEgress(_)),
            "Scheduler must reject task importing androgrid_net when egress_policy is BLOCKED"
        );
    }

    #[test]
    fn test_node_registration_unrooted_sanitizes_engines() {
        let scheduler = ClusterScheduler::new();
        let caps = make_test_capabilities(false, false);

        let res = scheduler
            .register_node(
                "node-unrooted-1".to_string(),
                caps,
                "1.0.0".to_string(),
                1000,
            )
            .expect("Registration must succeed");

        assert!(!res.session_token.is_empty());

        let inner = scheduler.inner.read().unwrap();
        let worker = inner.workers.get("node-unrooted-1").unwrap();
        assert!(!worker.capabilities.is_rooted);
        // RootShell must have been removed per [INV-006]
        assert!(!worker
            .capabilities
            .supported_engines
            .contains(&(ExecutionEngine::RootShell as i32)));
        assert!(worker
            .capabilities
            .supported_engines
            .contains(&(ExecutionEngine::WasmWasi as i32)));
    }

    #[test]
    fn test_cellular_spot_claim_and_anti_requirement_enforcement() {
        let scheduler = ClusterScheduler::new();
        let caps = make_test_capabilities(false, true);
        scheduler
            .register_node("cell-01".to_string(), caps, "1.0.0".to_string(), 1000)
            .unwrap();

        // Task 1: requires_unmetered = true -> Must NOT be claimed by cellular worker per [ANTI-003]
        let task_unmetered = make_test_task("task-wifi-only", 60, true, ExecutionEngine::WasmWasi);
        scheduler.submit_task(task_unmetered).unwrap();

        // Task 2: timeout > 180s -> Must NOT be claimed by cellular worker per [ANTI-003], [INV-005]
        let task_too_long = make_test_task("task-long", 200, false, ExecutionEngine::WasmWasi);
        scheduler.submit_task(task_too_long).unwrap();

        // Task 3: Root shell task on unrooted worker -> Must NOT be claimed per [INV-006]
        let task_root = make_test_task("task-root", 60, false, ExecutionEngine::RootShell);
        scheduler.submit_task(task_root).unwrap();

        let claim_res1 = scheduler
            .claim_cellular_task_nominal("cell-01", 80, false, 2000)
            .unwrap();
        assert!(
            !claim_res1.task_available,
            "None of the above tasks should be claimable"
        );

        // Task 4: Eligible cellular spot task (WASM, <= 180s, unmetered=false)
        let task_eligible = make_test_task("task-spot-501", 120, false, ExecutionEngine::WasmWasi);
        scheduler.submit_task(task_eligible).unwrap();

        let claim_res2 = scheduler
            .claim_cellular_task_nominal("cell-01", 80, false, 2000)
            .unwrap();
        assert!(claim_res2.task_available);
        let task = claim_res2.task.expect("Task must be returned");
        assert_eq!(task.task_id, "task-spot-501");
        assert_eq!(task.run_attempt, 1);
        assert_eq!(claim_res2.deadline_epoch_seconds, 2120);

        assert_eq!(
            scheduler.get_task_state("task-spot-501"),
            Some(TaskState::Leased)
        );
        assert_eq!(scheduler.get_active_attempt("task-spot-501"), Some(1));
    }

    #[test]
    fn test_cellular_spot_dual_assignment_and_monotonic_fencing() {
        // Direct implementation of Acceptance Criteria: Section 8, Scenario 2
        let scheduler = ClusterScheduler::new();

        // Register cell_01 (cellular node) and wifi_01 (Wi-Fi node)
        let cell_caps = make_test_capabilities(false, true);
        scheduler
            .register_node("cell_01".to_string(), cell_caps, "1.0.0".to_string(), 1000)
            .unwrap();

        let wifi_caps = make_test_capabilities(false, false);
        let wifi_reg = scheduler
            .register_node("wifi_01".to_string(), wifi_caps, "1.0.0".to_string(), 1000)
            .unwrap();

        // Task 601 submitted
        let task_601 = make_test_task("task_601", 120, false, ExecutionEngine::WasmWasi);
        scheduler.submit_task(task_601).unwrap();

        // Step 1: Claimed by cellular worker cell_01 with run_attempt 1
        let claim = scheduler
            .claim_cellular_task_nominal("cell_01", 85, false, 1000)
            .unwrap();
        assert!(claim.task_available);
        assert_eq!(
            scheduler.get_task_state("task_601"),
            Some(TaskState::Leased)
        );
        assert_eq!(scheduler.get_active_attempt("task_601"), Some(1));

        // Step 2: 60s elapse, wifi_01 becomes idle and synchronizes state
        // Orchestrator speculatively dual-assigns task_601 to wifi_01 with run_attempt 2
        let sync_res = scheduler
            .sync_node_state("wifi_01", &wifi_reg.session_token, &[], 1060000)
            .unwrap();
        assert_eq!(sync_res.desired_tasks.len(), 1);
        let preempted_task = &sync_res.desired_tasks[0];
        assert_eq!(preempted_task.task_id, "task_601");
        assert_eq!(preempted_task.run_attempt, 2);

        assert_eq!(
            scheduler.get_task_state("task_601"),
            Some(TaskState::Preempted)
        );
        assert_eq!(scheduler.get_active_attempt("task_601"), Some(2));

        // Step 3: wifi_01 completes and submits result with run_attempt 2
        let wifi_report = TaskExecutionReport {
            task_id: "task_601".to_string(),
            run_attempt: 2,
            state: TaskState::Completed as i32,
            exit_code: 0,
            stdout_bytes: b"Result from Wi-Fi worker".to_vec(),
            stderr_bytes: Vec::new(),
            error_code: String::new(),
            execution_time_ms: 1500,
        };
        let sync_res2 = scheduler
            .sync_node_state("wifi_01", &wifi_reg.session_token, &[wifi_report], 1070000)
            .unwrap();
        assert_eq!(sync_res2.acknowledged_task_ids, vec!["task_601"]);

        // Task is now COMPLETED
        assert_eq!(
            scheduler.get_task_state("task_601"),
            Some(TaskState::Completed)
        );
        let committed_res = scheduler
            .get_task_result("task_601")
            .expect("Result must exist");
        assert_eq!(committed_res.committed_attempt, 2);
        assert_eq!(committed_res.committed_by_node_id, "wifi_01");

        // Step 4: cell_01 subsequently submits task_601 with run_attempt 1
        // Orchestrator MUST reject with AttemptStale (TASK_ATTEMPT_STALE) per [INV-004]
        let cell_req = crate::SubmitCellularResultRequest {
            node_id: "cell_01".to_string(),
            task_id: "task_601".to_string(),
            run_attempt: 1, // Stale attempt 1 vs committed attempt 2
            exit_code: 0,
            stdout_bytes: b"Result from slow cellular worker".to_vec(),
            stderr_bytes: Vec::new(),
            error_code: String::new(),
            error_message: String::new(),
            execution_duration_ms: 45000,
        };
        let cell_submit_res = scheduler.submit_cellular_result(&cell_req);

        assert_eq!(
            cell_submit_res,
            Err(SchedulingError::AlreadyFinalized("task_601".to_string()))
        );
    }

    #[test]
    fn test_monotonic_attempt_fencing_rejects_stale_before_finalization() {
        let scheduler = ClusterScheduler::new();
        let cell_caps = make_test_capabilities(false, true);
        scheduler
            .register_node("cell_01".to_string(), cell_caps, "1.0.0".to_string(), 1000)
            .unwrap();

        let wifi_caps = make_test_capabilities(false, false);
        let wifi_reg = scheduler
            .register_node("wifi_01".to_string(), wifi_caps, "1.0.0".to_string(), 1000)
            .unwrap();

        let task = make_test_task("task_fence", 120, false, ExecutionEngine::WasmWasi);
        scheduler.submit_task(task).unwrap();

        // Claimed on cellular -> attempt 1
        scheduler
            .claim_cellular_task_nominal("cell_01", 90, false, 1000)
            .unwrap();

        // Preempted on Wi-Fi -> attempt 2
        scheduler
            .sync_node_state("wifi_01", &wifi_reg.session_token, &[], 2000)
            .unwrap();
        assert_eq!(scheduler.get_active_attempt("task_fence"), Some(2));
        assert_eq!(
            scheduler.get_task_state("task_fence"),
            Some(TaskState::Preempted)
        );

        // Cellular worker submits attempt 1 WHILE task is still PREEMPTED (not yet finalized)
        let stale_req = crate::SubmitCellularResultRequest {
            node_id: "cell_01".to_string(),
            task_id: "task_fence".to_string(),
            run_attempt: 1, // Submitted 1, active is 2
            exit_code: 0,
            stdout_bytes: b"stdout".to_vec(),
            stderr_bytes: Vec::new(),
            error_code: String::new(),
            error_message: String::new(),
            execution_duration_ms: 3000,
        };
        let stale_res = scheduler.submit_cellular_result(&stale_req);

        assert_eq!(
            stale_res,
            Err(SchedulingError::AttemptStale {
                task_id: "task_fence".to_string(),
                submitted: 1,
                active: 2,
            })
        );

        // State remains PREEMPTED; not corrupted
        assert_eq!(
            scheduler.get_task_state("task_fence"),
            Some(TaskState::Preempted)
        );
    }

    /// Verifies thermal deferral when battery temperature exceeds 38 deg C or thermal status >= 3.
    ///
    /// Traces to: [REQ-OP-003], [NFR-POW-001]
    #[test]
    fn test_thermal_policy_cellular_claim_deferral() {
        let scheduler = ClusterScheduler::new();
        let cell_caps = make_test_capabilities(false, true);
        scheduler
            .register_node("cell_hot".to_string(), cell_caps, "1.0.0".to_string(), 1000)
            .unwrap();

        let task = make_test_task("task_spot_thermal", 120, false, ExecutionEngine::WasmWasi);
        scheduler.submit_task(task).unwrap();

        // 1. Temperature is 42 deg C (> 38 deg C threshold) -> Task claim must be deferred
        let res_temp = scheduler
            .claim_cellular_task("cell_hot", 85, false, 42, 0, 1000)
            .expect("Claim RPC must succeed");
        assert!(
            !res_temp.task_available,
            "Claim must be deferred when battery temperature exceeds 38 deg C"
        );
        assert_eq!(
            scheduler.get_task_state("task_spot_thermal"),
            Some(TaskState::Pending)
        );

        // 2. Temperature is nominal (35 deg C), but thermal status is 3 (SEVERE) -> Must be deferred
        let res_status = scheduler
            .claim_cellular_task("cell_hot", 85, false, 35, 3, 1010)
            .expect("Claim RPC must succeed");
        assert!(
            !res_status.task_available,
            "Claim must be deferred when thermal status is >= 3"
        );
        assert_eq!(
            scheduler.get_task_state("task_spot_thermal"),
            Some(TaskState::Pending)
        );

        // 3. Node cools down: temperature is 32 deg C, thermal status is 1 (LIGHT) -> Lease succeeds
        let res_nominal = scheduler
            .claim_cellular_task("cell_hot", 85, false, 32, 1, 1020)
            .expect("Claim RPC must succeed");
        assert!(
            res_nominal.task_available,
            "Claim must succeed once node cools below threshold"
        );
        assert_eq!(
            scheduler.get_task_state("task_spot_thermal"),
            Some(TaskState::Leased)
        );
    }

    /// Verifies uncalibrated or zero battery temperature does not trigger false throttling.
    ///
    /// Traces to: [REQ-OP-003], [NFR-POW-001]
    #[test]
    fn test_thermal_policy_unreported_telemetry_tolerated() {
        let scheduler = ClusterScheduler::new();
        let cell_caps = make_test_capabilities(false, true);
        scheduler
            .register_node(
                "cell_uncal".to_string(),
                cell_caps,
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();

        let task = make_test_task("task_uncal", 120, false, ExecutionEngine::WasmWasi);
        scheduler.submit_task(task).unwrap();

        // Temperature 0 and status 0 (nominal / unreported telemetry) -> Must be claimable
        let res = scheduler
            .claim_cellular_task("cell_uncal", 80, false, 0, 0, 1000)
            .unwrap();
        assert!(
            res.task_available,
            "Unreported temperature (0) must not cause false deferral"
        );
    }

    /// Verifies thermal policy rejection action emits ThermalThrottled error.
    ///
    /// Traces to: [REQ-OP-003], [NFR-POW-001]
    #[test]
    fn test_thermal_policy_rejection_action() {
        let scheduler =
            ClusterScheduler::with_options(false, ThermalPolicy::new(38, 3, ThermalAction::Reject));
        let cell_caps = make_test_capabilities(false, true);
        scheduler
            .register_node(
                "cell_reject".to_string(),
                cell_caps,
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();

        let task = make_test_task("task_reject", 120, false, ExecutionEngine::WasmWasi);
        scheduler.submit_task(task).unwrap();

        let err = scheduler
            .claim_cellular_task("cell_reject", 80, false, 44, 0, 1000)
            .unwrap_err();

        assert_eq!(
            err,
            SchedulingError::ThermalThrottled {
                node_id: "cell_reject".to_string(),
                temperature_celsius: 44,
                thermal_status: 0,
            }
        );
    }

    /// Verifies root shell tasks are refused without explicit cluster flag even on rooted nodes.
    ///
    /// Traces to: [INV-006]
    #[test]
    fn test_root_task_refused_without_cli_flag() {
        let scheduler = ClusterScheduler::new(); // allow_insecure_root_tasks is false by default
        assert!(!scheduler.allow_insecure_root_tasks());

        let rooted_caps = make_test_capabilities(true, false);
        let reg = scheduler
            .register_node(
                "rooted_node_01".to_string(),
                rooted_caps,
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();

        let root_task = make_test_task("root_task_01", 60, false, ExecutionEngine::RootShell);
        scheduler.submit_task(root_task).unwrap();

        // Wi-Fi sync should NOT dispatch the root task
        let sync_res = scheduler
            .sync_node_state("rooted_node_01", &reg.session_token, &[], 2000)
            .unwrap();
        assert!(
            sync_res.desired_tasks.is_empty(),
            "Root shell task must be refused when allow_insecure_root_tasks is false"
        );
    }

    /// Verifies root shell tasks are allowed on rooted nodes when explicit cluster flag is set.
    ///
    /// Traces to: [INV-006]
    #[test]
    fn test_root_task_allowed_with_explicit_flag() {
        let scheduler = ClusterScheduler::with_options(true, ThermalPolicy::default());
        assert!(scheduler.allow_insecure_root_tasks());

        let rooted_caps = make_test_capabilities(true, false);
        let reg = scheduler
            .register_node(
                "rooted_node_02".to_string(),
                rooted_caps,
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();

        let root_task = make_test_task("root_task_02", 60, false, ExecutionEngine::RootShell);
        scheduler.submit_task(root_task).unwrap();

        // Wi-Fi sync SHOULD dispatch the root task to the rooted node
        let sync_res = scheduler
            .sync_node_state("rooted_node_02", &reg.session_token, &[], 2000)
            .unwrap();
        assert_eq!(
            sync_res.desired_tasks.len(),
            1,
            "Root shell task must be dispatched when allow_insecure_root_tasks is true on rooted node"
        );
        assert_eq!(sync_res.desired_tasks[0].task_id, "root_task_02");
    }

    fn make_group_template(sha: &str) -> TaskTemplate {
        TaskTemplate {
            engine: ExecutionEngine::WasmWasi as i32,
            timeout_seconds: 120,
            entrypoint: "_start".to_string(),
            env_vars: HashMap::from([("MODE".to_string(), "prod".to_string())]),
            artifact_sha256: sha.to_string(),
            shell_command: String::new(),
            requires_unmetered: false,
            node_group_affinity: String::new(),
            egress_policy: 0,
            allowed_hostnames: Vec::new(),
            max_egress_bytes: 0,
        }
    }

    #[test]
    fn test_task_group_submit_and_status_rollup() {
        let scheduler = ClusterScheduler::new();
        let wifi = scheduler
            .register_node(
                "wifi_g1".to_string(),
                make_test_capabilities(false, false),
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();

        let sub = scheduler
            .submit_task_group(
                TaskGroupSpec {
                    group_id: "img-batch".to_string(),
                    template: Some(make_group_template(&"a".repeat(64))),
                    partitions: vec![
                        TaskPartitionSpec {
                            env_overrides: HashMap::from([("PART".to_string(), "0".to_string())]),
                        },
                        TaskPartitionSpec {
                            env_overrides: HashMap::from([("PART".to_string(), "1".to_string())]),
                        },
                    ],
                },
                1000,
            )
            .unwrap();
        assert_eq!(sub.group_epoch, 1);
        assert_eq!(sub.total_tasks, 2);

        let sync1 = scheduler
            .sync_node_state("wifi_g1", &wifi.session_token, &[], 2000)
            .unwrap();
        assert_eq!(sync1.desired_tasks.len(), 1);
        let t1 = sync1.desired_tasks[0].clone();

        let sync2 = scheduler
            .sync_node_state(
                "wifi_g1",
                &wifi.session_token,
                &[TaskExecutionReport {
                    task_id: t1.task_id,
                    run_attempt: t1.run_attempt,
                    state: TaskState::Completed as i32,
                    exit_code: 0,
                    stdout_bytes: b"ok".to_vec(),
                    stderr_bytes: Vec::new(),
                    error_code: String::new(),
                    execution_time_ms: 10,
                }],
                3000,
            )
            .unwrap();
        let t2 = sync2.desired_tasks[0].clone();

        scheduler
            .sync_node_state(
                "wifi_g1",
                &wifi.session_token,
                &[TaskExecutionReport {
                    task_id: t2.task_id,
                    run_attempt: t2.run_attempt,
                    state: TaskState::Completed as i32,
                    exit_code: 0,
                    stdout_bytes: b"ok".to_vec(),
                    stderr_bytes: Vec::new(),
                    error_code: String::new(),
                    execution_time_ms: 12,
                }],
                4000,
            )
            .unwrap();

        let status = scheduler.get_task_group_status("img-batch", true).unwrap();
        assert_eq!(status.state, TaskGroupState::Completed as i32);
        assert_eq!(status.completed_tasks, 2);
        assert_eq!(status.tasks.len(), 2);
    }

    #[test]
    fn test_task_group_replace_immediate_fences_cellular_and_queues_wifi_cancel() {
        let scheduler = ClusterScheduler::new();
        let wifi = scheduler
            .register_node(
                "wifi_g2".to_string(),
                make_test_capabilities(false, false),
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();

        scheduler
            .submit_task_group(
                TaskGroupSpec {
                    group_id: "fence-grp".to_string(),
                    template: Some(make_group_template(&"a".repeat(64))),
                    partitions: vec![TaskPartitionSpec::default(), TaskPartitionSpec::default()],
                },
                1000,
            )
            .unwrap();

        // Lease one partition on cellular and one on Wi-Fi
        scheduler
            .register_node(
                "cell_g2".to_string(),
                make_test_capabilities(false, true),
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();
        let cell_claim = scheduler
            .claim_cellular_task_nominal("cell_g2", 90, false, 10)
            .unwrap();
        let cell_task = cell_claim.task.unwrap();
        let wifi_sync = scheduler
            .sync_node_state("wifi_g2", &wifi.session_token, &[], 2000)
            .unwrap();
        let wifi_task = wifi_sync.desired_tasks[0].clone();

        let rep = scheduler
            .replace_task_group(
                ReplaceTaskGroupRequest {
                    group_id: "fence-grp".to_string(),
                    expected_epoch: Some(1),
                    template: Some(make_group_template(&"b".repeat(64))),
                    partitions: vec![TaskPartitionSpec::default()],
                    strategy: ReplaceStrategy::Immediate as i32,
                },
                3000,
            )
            .unwrap();
        assert_eq!(rep.new_epoch, 2);
        assert_eq!(rep.cancelled_tasks, 2);
        assert_eq!(rep.created_tasks, 1);

        // Cellular submission for epoch 1 MUST fail with GroupSuperseded
        let err = scheduler
            .submit_cellular_result(&crate::SubmitCellularResultRequest {
                node_id: "cell_g2".to_string(),
                task_id: cell_task.task_id,
                run_attempt: cell_task.run_attempt,
                exit_code: 0,
                stdout_bytes: Vec::new(),
                stderr_bytes: Vec::new(),
                error_code: String::new(),
                error_message: String::new(),
                execution_duration_ms: 5,
            })
            .unwrap_err();
        assert!(matches!(err, SchedulingError::GroupSuperseded { .. }));

        // Wi-Fi sync receives cancel_task_ids once and acks stale completed report
        let next_sync = scheduler
            .sync_node_state(
                "wifi_g2",
                &wifi.session_token,
                &[TaskExecutionReport {
                    task_id: wifi_task.task_id.clone(),
                    run_attempt: wifi_task.run_attempt,
                    state: TaskState::Completed as i32,
                    exit_code: 0,
                    stdout_bytes: Vec::new(),
                    stderr_bytes: Vec::new(),
                    error_code: String::new(),
                    execution_time_ms: 5,
                }],
                4000,
            )
            .unwrap();
        assert_eq!(next_sync.cancel_task_ids, vec![wifi_task.task_id.clone()]);
        assert!(next_sync.acknowledged_task_ids.contains(&wifi_task.task_id));

        // Subsequent sync has drained cancel_task_ids
        let drain_sync = scheduler
            .sync_node_state("wifi_g2", &wifi.session_token, &[], 5000)
            .unwrap();
        assert!(drain_sync.cancel_task_ids.is_empty());
    }

    #[test]
    fn test_task_group_replace_drain_and_cas_conflict() {
        let scheduler = ClusterScheduler::new();
        scheduler
            .submit_task_group(
                TaskGroupSpec {
                    group_id: "drain-grp".to_string(),
                    template: Some(make_group_template(&"a".repeat(64))),
                    partitions: vec![TaskPartitionSpec::default(), TaskPartitionSpec::default()],
                },
                1000,
            )
            .unwrap();

        scheduler
            .register_node(
                "cell_d1".to_string(),
                make_test_capabilities(false, true),
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();
        let cell_claim = scheduler
            .claim_cellular_task_nominal("cell_d1", 90, false, 10)
            .unwrap();
        let leased_e1 = cell_claim.task.unwrap();

        // CAS mismatch fails with GroupEpochConflict
        let cas_err = scheduler
            .replace_task_group(
                ReplaceTaskGroupRequest {
                    group_id: "drain-grp".to_string(),
                    expected_epoch: Some(99),
                    template: Some(make_group_template(&"b".repeat(64))),
                    partitions: vec![TaskPartitionSpec::default()],
                    strategy: ReplaceStrategy::Drain as i32,
                },
                2000,
            )
            .unwrap_err();
        assert!(matches!(
            cas_err,
            SchedulingError::GroupEpochConflict { .. }
        ));

        // DRAIN leaves leased epoch 1 task alive and cancels pending epoch 1 task
        let rep = scheduler
            .replace_task_group(
                ReplaceTaskGroupRequest {
                    group_id: "drain-grp".to_string(),
                    expected_epoch: Some(1),
                    template: Some(make_group_template(&"b".repeat(64))),
                    partitions: vec![TaskPartitionSpec::default()],
                    strategy: ReplaceStrategy::Drain as i32,
                },
                2000,
            )
            .unwrap();
        assert_eq!(rep.state, TaskGroupState::Draining as i32);
        assert_eq!(rep.draining_tasks, 1);
        assert_eq!(rep.cancelled_tasks, 1);

        // Draining epoch 1 task CAN still commit within its lease
        let commit = scheduler
            .submit_cellular_result(&crate::SubmitCellularResultRequest {
                node_id: "cell_d1".to_string(),
                task_id: leased_e1.task_id,
                run_attempt: leased_e1.run_attempt,
                exit_code: 0,
                stdout_bytes: b"done".to_vec(),
                stderr_bytes: Vec::new(),
                error_code: String::new(),
                error_message: String::new(),
                execution_duration_ms: 5,
            })
            .unwrap();
        assert!(commit.accepted);

        // Once drained, group transitions from DRAINING -> ACTIVE
        let st = scheduler.get_task_group_status("drain-grp", false).unwrap();
        assert_eq!(st.state, TaskGroupState::Active as i32);
        assert_eq!(st.previous_epoch_draining_tasks, 0);
    }

    #[test]
    fn test_task_group_cancel_and_bounds_validation() {
        let scheduler = ClusterScheduler::new();
        assert!(matches!(
            scheduler.submit_task_group(
                TaskGroupSpec {
                    group_id: "bad:id".to_string(),
                    template: Some(make_group_template(&"a".repeat(64))),
                    partitions: vec![TaskPartitionSpec::default()],
                },
                1000,
            ),
            Err(SchedulingError::InvalidGroupId(_))
        ));
        assert!(matches!(
            scheduler.submit_task_group(
                TaskGroupSpec {
                    group_id: "valid-id".to_string(),
                    template: Some(make_group_template(&"a".repeat(64))),
                    partitions: vec![],
                },
                1000,
            ),
            Err(SchedulingError::InvalidGroupPartitions(_))
        ));

        scheduler
            .submit_task_group(
                TaskGroupSpec {
                    group_id: "valid-id".to_string(),
                    template: Some(make_group_template(&"a".repeat(64))),
                    partitions: vec![TaskPartitionSpec::default()],
                },
                1000,
            )
            .unwrap();
        let cancel = scheduler
            .cancel_task_group("valid-id", Some(1), 2000)
            .unwrap();
        assert!(cancel.cancelled);
        assert_eq!(cancel.cancelled_tasks, 1);

        let st = scheduler.get_task_group_status("valid-id", false).unwrap();
        assert_eq!(st.state, TaskGroupState::Cancelled as i32);
        assert_eq!(st.cancelled_tasks, 1);
    }

    #[test]
    fn test_task_group_drain_stays_draining_until_epoch1_finishes() {
        let scheduler = ClusterScheduler::new();
        let wifi = scheduler
            .register_node(
                "wifi-1".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                1000,
            )
            .unwrap();

        scheduler
            .submit_task_group(
                TaskGroupSpec {
                    group_id: "drain-order".to_string(),
                    template: Some(make_group_template(&"a".repeat(64))),
                    partitions: vec![TaskPartitionSpec::default()],
                },
                1000,
            )
            .unwrap();

        let sync1 = scheduler
            .sync_node_state("wifi-1", &wifi.session_token, &[], 1000)
            .unwrap();
        assert_eq!(sync1.desired_tasks[0].task_id, "drain-order:e1:p0");

        let rep = scheduler
            .replace_task_group(
                ReplaceTaskGroupRequest {
                    group_id: "drain-order".to_string(),
                    expected_epoch: Some(1),
                    template: Some(make_group_template(&"b".repeat(64))),
                    partitions: vec![TaskPartitionSpec::default()],
                    strategy: ReplaceStrategy::Drain as i32,
                },
                2000,
            )
            .unwrap();
        assert_eq!(rep.state, TaskGroupState::Draining as i32);

        // Wi-Fi worker claims and completes epoch 2 while epoch 1 is still LEASED.
        let sync2 = scheduler
            .sync_node_state("wifi-1", &wifi.session_token, &[], 2000)
            .unwrap();
        assert_eq!(sync2.desired_tasks[0].task_id, "drain-order:e2:p0");
        scheduler
            .sync_node_state(
                "wifi-1",
                &wifi.session_token,
                &[TaskExecutionReport {
                    task_id: "drain-order:e2:p0".to_string(),
                    run_attempt: sync2.desired_tasks[0].run_attempt,
                    state: TaskState::Completed as i32,
                    exit_code: 0,
                    stdout_bytes: b"ok".to_vec(),
                    stderr_bytes: Vec::new(),
                    error_code: String::new(),
                    execution_time_ms: 10,
                }],
                3000,
            )
            .unwrap();

        // Must remain Draining while epoch 1 task is still non-terminal.
        let mid = scheduler
            .get_task_group_status("drain-order", false)
            .unwrap();
        assert_eq!(mid.state, TaskGroupState::Draining as i32);
        assert_eq!(mid.previous_epoch_draining_tasks, 1);

        // Once epoch 1 finishes, group transitions to Completed.
        scheduler
            .sync_node_state(
                "wifi-1",
                &wifi.session_token,
                &[TaskExecutionReport {
                    task_id: "drain-order:e1:p0".to_string(),
                    run_attempt: sync1.desired_tasks[0].run_attempt,
                    state: TaskState::Completed as i32,
                    exit_code: 0,
                    stdout_bytes: b"ok".to_vec(),
                    stderr_bytes: Vec::new(),
                    error_code: String::new(),
                    execution_time_ms: 10,
                }],
                4000,
            )
            .unwrap();
        let done = scheduler
            .get_task_group_status("drain-order", false)
            .unwrap();
        assert_eq!(done.state, TaskGroupState::Completed as i32);
        assert_eq!(done.previous_epoch_draining_tasks, 0);
    }

    #[test]
    fn test_task_group_validation_guards_and_error_parity() {
        let scheduler = ClusterScheduler::new();

        // Invalid TaskTemplate: engine=Unspecified, timeout=0, empty shell_command
        let mut bad_engine = make_group_template(&"a".repeat(64));
        bad_engine.engine = ExecutionEngine::Unspecified as i32;
        assert!(matches!(
            scheduler.submit_task_group(
                TaskGroupSpec {
                    group_id: "bad-tpl".to_string(),
                    template: Some(bad_engine),
                    partitions: vec![TaskPartitionSpec::default()],
                },
                1000,
            ),
            Err(SchedulingError::InvalidTaskTemplate(_))
        ));

        let mut bad_timeout = make_group_template(&"a".repeat(64));
        bad_timeout.timeout_seconds = 0;
        assert!(matches!(
            scheduler.submit_task_group(
                TaskGroupSpec {
                    group_id: "bad-to".to_string(),
                    template: Some(bad_timeout),
                    partitions: vec![TaskPartitionSpec::default()],
                },
                1000,
            ),
            Err(SchedulingError::InvalidTaskTemplate(_))
        ));

        assert!(matches!(
            scheduler.submit_task_group(
                TaskGroupSpec {
                    group_id: "bad-shell".to_string(),
                    template: Some(TaskTemplate {
                        engine: ExecutionEngine::ToyboxUser as i32,
                        timeout_seconds: 30,
                        shell_command: "   ".to_string(),
                        ..Default::default()
                    }),
                    partitions: vec![TaskPartitionSpec::default()],
                },
                1000,
            ),
            Err(SchedulingError::InvalidTaskTemplate(_))
        ));

        // Standalone submit_task rejects reserved <group>:e<epoch>:p<index> IDs.
        assert!(matches!(
            scheduler.submit_task(TaskSpec {
                task_id: "grp:e1:p0".to_string(),
                engine: ExecutionEngine::WasmWasi as i32,
                timeout_seconds: 30,
                ..Default::default()
            }),
            Err(SchedulingError::TaskIdCollision(_))
        ));

        // Group-owned tasks reject individual cancel_task and return TaskCancelled on late cellular submit.
        scheduler
            .submit_task_group(
                TaskGroupSpec {
                    group_id: "grp-guard".to_string(),
                    template: Some(make_group_template(&"a".repeat(64))),
                    partitions: vec![TaskPartitionSpec::default()],
                },
                1000,
            )
            .unwrap();
        assert!(matches!(
            scheduler.cancel_task("grp-guard:e1:p0"),
            Err(SchedulingError::InvalidStateTransition { .. })
        ));

        scheduler
            .cancel_task_group("grp-guard", Some(1), 2000)
            .unwrap();
        assert!(matches!(
            scheduler.submit_cellular_result(&crate::SubmitCellularResultRequest {
                node_id: "cell-1".to_string(),
                task_id: "grp-guard:e1:p0".to_string(),
                run_attempt: 1,
                exit_code: 0,
                ..Default::default()
            }),
            Err(SchedulingError::TaskCancelled(_))
        ));

        let snap = scheduler.get_snapshot();
        assert_eq!(snap.metrics.cancelled_tasks, 1);
        assert_eq!(snap.tasks[0].state, "Cancelled");

        // Replace on Completed group is rejected consistently with GroupTerminal.
        let wifi = scheduler
            .register_node(
                "wifi-1".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                1000,
            )
            .unwrap();
        scheduler
            .submit_task_group(
                TaskGroupSpec {
                    group_id: "grp-done".to_string(),
                    template: Some(make_group_template(&"c".repeat(64))),
                    partitions: vec![TaskPartitionSpec::default()],
                },
                1000,
            )
            .unwrap();
        let sync_done = scheduler
            .sync_node_state("wifi-1", &wifi.session_token, &[], 1000)
            .unwrap();
        scheduler
            .sync_node_state(
                "wifi-1",
                &wifi.session_token,
                &[TaskExecutionReport {
                    task_id: "grp-done:e1:p0".to_string(),
                    run_attempt: sync_done.desired_tasks[0].run_attempt,
                    state: TaskState::Completed as i32,
                    exit_code: 0,
                    stdout_bytes: Vec::new(),
                    stderr_bytes: Vec::new(),
                    error_code: String::new(),
                    execution_time_ms: 5,
                }],
                2000,
            )
            .unwrap();
        assert!(matches!(
            scheduler.replace_task_group(
                ReplaceTaskGroupRequest {
                    group_id: "grp-done".to_string(),
                    expected_epoch: Some(1),
                    template: Some(make_group_template(&"d".repeat(64))),
                    partitions: vec![TaskPartitionSpec::default()],
                    strategy: ReplaceStrategy::Immediate as i32,
                },
                3000,
            ),
            Err(SchedulingError::GroupTerminal(_))
        ));
    }

    #[test]
    fn test_node_group_create_update_list_and_validation() {
        let scheduler = ClusterScheduler::new();

        // Invalid group_id
        assert!(matches!(
            scheduler.create_node_group(
                CreateNodeGroupRequest {
                    group_id: "bad group!".to_string(),
                    description: String::new(),
                    label_selector: HashMap::new(),
                    initial_node_ids: Vec::new(),
                },
                1000,
            ),
            Err(SchedulingError::InvalidGroupId(_))
        ));

        // Reserved prefix rejected on RegisterNode, allowed in NodeGroup selector
        assert!(matches!(
            scheduler.register_node_with_labels(
                "n1".to_string(),
                make_test_capabilities(false, false),
                "1.0.0".to_string(),
                HashMap::from([("androgrid.io/rooted".to_string(), "true".to_string())]),
                1000,
            ),
            Err(SchedulingError::InvalidNodeLabels(_))
        ));

        let created = scheduler
            .create_node_group(
                CreateNodeGroupRequest {
                    group_id: "rack-01".to_string(),
                    description: "Rack 1".to_string(),
                    label_selector: HashMap::from([
                        ("rack".to_string(), "rig-01".to_string()),
                        ("androgrid.io/rooted".to_string(), "true".to_string()),
                    ]),
                    initial_node_ids: Vec::new(),
                },
                1000,
            )
            .unwrap();
        assert!(created.created);
        assert_eq!(created.group.as_ref().unwrap().group_id, "rack-01");

        // Duplicate group_id
        assert!(matches!(
            scheduler.create_node_group(
                CreateNodeGroupRequest {
                    group_id: "rack-01".to_string(),
                    description: String::new(),
                    label_selector: HashMap::new(),
                    initial_node_ids: Vec::new(),
                },
                1100,
            ),
            Err(SchedulingError::NodeGroupAlreadyExists(_))
        ));

        // Update with replace_label_selector == false and non-empty selector fails
        assert!(matches!(
            scheduler.update_node_group(
                UpdateNodeGroupRequest {
                    group_id: "rack-01".to_string(),
                    description: None,
                    label_selector: HashMap::from([("rack".to_string(), "rig-02".to_string())]),
                    replace_label_selector: false,
                },
                1200,
            ),
            Err(SchedulingError::InvalidNodeGroupRequest(_))
        ));

        // Update with replace_label_selector == true succeeds
        let updated = scheduler
            .update_node_group(
                UpdateNodeGroupRequest {
                    group_id: "rack-01".to_string(),
                    description: Some("Updated Rack 1".to_string()),
                    label_selector: HashMap::from([("rack".to_string(), "rig-02".to_string())]),
                    replace_label_selector: true,
                },
                1300,
            )
            .unwrap();
        let grp = updated.group.unwrap();
        assert_eq!(grp.description, "Updated Rack 1");
        assert_eq!(
            grp.label_selector.get("rack").map(String::as_str),
            Some("rig-02")
        );
        assert_eq!(grp.updated_at_epoch_ms, 1300);
        assert_eq!(scheduler.list_node_groups().len(), 1);
    }

    #[test]
    fn test_node_group_explicit_partitioning_and_reregistration_preservation() {
        let scheduler = ClusterScheduler::new();

        // Pre-register node-1 in group-a before it connects
        scheduler
            .create_node_group(
                CreateNodeGroupRequest {
                    group_id: "group-a".to_string(),
                    description: String::new(),
                    label_selector: HashMap::new(),
                    initial_node_ids: vec!["node-1".to_string()],
                },
                1000,
            )
            .unwrap();
        scheduler
            .create_node_group(
                CreateNodeGroupRequest {
                    group_id: "group-b".to_string(),
                    description: String::new(),
                    label_selector: HashMap::new(),
                    initial_node_ids: Vec::new(),
                },
                1000,
            )
            .unwrap();

        scheduler
            .register_node(
                "node-1".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                1100,
            )
            .unwrap();

        let nodes = scheduler.list_worker_nodes();
        assert_eq!(nodes[0].node_group, "group-a");

        // Drain and signal upgrade on node-1
        scheduler
            .upgrade_nodes(UpgradeNodesRequest {
                node_group: "group-a".to_string(),
                node_ids: Vec::new(),
                target_version: "0.2.0".to_string(),
                drain_before_upgrade: true,
                ..Default::default()
            })
            .unwrap();

        // Move node-1 from group-a to group-b atomically
        let assign_res = scheduler
            .assign_nodes_to_group(
                AssignNodesToGroupRequest {
                    group_id: "group-b".to_string(),
                    node_ids: vec!["node-1".to_string()],
                    unassign: false,
                },
                1200,
            )
            .unwrap();
        assert_eq!(assign_res.affected_nodes, 1);

        let groups = scheduler.list_node_groups();
        assert!(groups[0].member_node_ids.is_empty());
        assert_eq!(groups[0].updated_at_epoch_ms, 1200);
        assert_eq!(groups[1].member_node_ids, vec!["node-1"]);

        // Re-register with old version: preserves explicit_node_group, draining, and desired_client_version
        scheduler
            .register_node(
                "node-1".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                1300,
            )
            .unwrap();
        let n1 = &scheduler.list_worker_nodes()[0];
        assert_eq!(n1.node_group, "group-b");
        assert!(n1.draining);
        assert_eq!(n1.desired_client_version, "0.2.0");

        // Re-register with target version 0.2.0: clears desired_client_version and upgrade drain, preserves group
        scheduler
            .register_node(
                "node-1".to_string(),
                make_test_capabilities(false, false),
                "0.2.0".to_string(),
                1400,
            )
            .unwrap();
        let n1_upgraded = &scheduler.list_worker_nodes()[0];
        assert_eq!(n1_upgraded.node_group, "group-b");
        assert!(!n1_upgraded.draining);
        assert_eq!(n1_upgraded.desired_client_version, "");

        // Unassign idempotency
        let unassign_res = scheduler
            .assign_nodes_to_group(
                AssignNodesToGroupRequest {
                    group_id: "group-b".to_string(),
                    node_ids: vec!["node-1".to_string(), "node-1".to_string()],
                    unassign: true,
                },
                1500,
            )
            .unwrap();
        assert_eq!(unassign_res.affected_nodes, 1);
        let unassign_noop = scheduler
            .assign_nodes_to_group(
                AssignNodesToGroupRequest {
                    group_id: "group-b".to_string(),
                    node_ids: vec!["node-1".to_string()],
                    unassign: true,
                },
                1600,
            )
            .unwrap();
        assert_eq!(unassign_noop.affected_nodes, 0);
    }

    #[test]
    fn test_node_group_affinity_and_preemption_isolation() {
        let scheduler = ClusterScheduler::new();

        scheduler
            .create_node_group(
                CreateNodeGroupRequest {
                    group_id: "pool-a".to_string(),
                    description: "Pool A".to_string(),
                    label_selector: HashMap::from([
                        ("pool".to_string(), "alpha".to_string()),
                        ("androgrid.io/transport".to_string(), "cellular".to_string()),
                    ]),
                    initial_node_ids: Vec::new(),
                },
                1000,
            )
            .unwrap();
        scheduler
            .create_node_group(
                CreateNodeGroupRequest {
                    group_id: "pool-wifi-a".to_string(),
                    description: "Wi-Fi Pool A".to_string(),
                    label_selector: HashMap::from([("pool".to_string(), "alpha".to_string())]),
                    initial_node_ids: Vec::new(),
                },
                1000,
            )
            .unwrap();
        scheduler
            .create_node_group(
                CreateNodeGroupRequest {
                    group_id: "pool-b".to_string(),
                    description: "Pool B".to_string(),
                    label_selector: HashMap::from([("pool".to_string(), "beta".to_string())]),
                    initial_node_ids: Vec::new(),
                },
                1000,
            )
            .unwrap();

        // Unknown affinity fails fast
        let mut bad_task = make_test_task("t-bad", 60, false, ExecutionEngine::WasmWasi);
        bad_task.node_group_affinity = "missing-pool".to_string();
        assert!(matches!(
            scheduler.submit_task(bad_task),
            Err(SchedulingError::NodeGroupNotFound(_))
        ));

        // Register cellular node in alpha (starts as Wi-Fi in RegisterNode, switches to cellular on Claim)
        let cell_reg = scheduler
            .register_node_with_labels(
                "cell-alpha".to_string(),
                make_test_capabilities(false, false),
                "1.0.0".to_string(),
                HashMap::from([("pool".to_string(), "alpha".to_string())]),
                1000,
            )
            .unwrap();
        let _ = cell_reg;

        let wifi_beta = scheduler
            .register_node_with_labels(
                "wifi-beta".to_string(),
                make_test_capabilities(false, false),
                "1.0.0".to_string(),
                HashMap::from([("pool".to_string(), "beta".to_string())]),
                1000,
            )
            .unwrap();
        let wifi_alpha = scheduler
            .register_node_with_labels(
                "wifi-alpha".to_string(),
                make_test_capabilities(false, false),
                "1.0.0".to_string(),
                HashMap::from([("pool".to_string(), "alpha".to_string())]),
                1000,
            )
            .unwrap();

        // Submit task pinned to pool-a (requires cellular + pool=alpha)
        let mut t1 = make_test_task("t-alpha", 60, false, ExecutionEngine::WasmWasi);
        t1.node_group_affinity = "pool-a".to_string();
        scheduler.submit_task(t1).unwrap();

        // wifi-beta cannot claim t-alpha
        let beta_sync = scheduler
            .sync_node_state("wifi-beta", &wifi_beta.session_token, &[], 1100)
            .unwrap();
        assert!(beta_sync.desired_tasks.is_empty());

        // cell-alpha updates transport -> cellular on claim and claims t-alpha
        let cell_claim = scheduler
            .claim_cellular_task_nominal("cell-alpha", 90, false, 1200)
            .unwrap();
        assert!(cell_claim.task_available);
        assert_eq!(cell_claim.task.unwrap().task_id, "t-alpha");

        // Now submit a task pinned to pool-wifi-a, and lease it to cell-alpha? No, test preemption!
        let mut t2 = make_test_task("t-preempt-a", 60, false, ExecutionEngine::WasmWasi);
        t2.node_group_affinity = "pool-wifi-a".to_string();
        scheduler.submit_task(t2).unwrap();
        let cell_claim2 = scheduler
            .claim_cellular_task_nominal("cell-alpha", 90, false, 1250)
            .unwrap();
        assert!(cell_claim2.task_available);

        // wifi-beta MUST NOT speculatively preempt t-preempt-a because of pool-wifi-a affinity
        let beta_sync2 = scheduler
            .sync_node_state("wifi-beta", &wifi_beta.session_token, &[], 1300)
            .unwrap();
        assert!(beta_sync2.desired_tasks.is_empty());

        // wifi-alpha CAN speculatively preempt t-preempt-a
        let alpha_sync = scheduler
            .sync_node_state("wifi-alpha", &wifi_alpha.session_token, &[], 1350)
            .unwrap();
        assert_eq!(alpha_sync.desired_tasks.len(), 1);
        assert_eq!(alpha_sync.desired_tasks[0].task_id, "t-preempt-a");
        assert_eq!(alpha_sync.desired_tasks[0].run_attempt, 2);
    }

    #[test]
    fn test_drain_and_upgrade_nodes_lifecycle() {
        let scheduler = ClusterScheduler::new();
        scheduler
            .create_node_group(
                CreateNodeGroupRequest {
                    group_id: "beta".to_string(),
                    description: String::new(),
                    label_selector: HashMap::new(),
                    initial_node_ids: vec!["w1".to_string(), "w2".to_string()],
                },
                1000,
            )
            .unwrap();
        let w1 = scheduler
            .register_node(
                "w1".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                1000,
            )
            .unwrap();
        let w2 = scheduler
            .register_node(
                "w2".to_string(),
                make_test_capabilities(false, false),
                "0.2.0".to_string(),
                1000,
            )
            .unwrap();

        // UpgradeNodes skips w2 (already on 0.2.0) and drains only w1
        let upg = scheduler
            .upgrade_nodes(UpgradeNodesRequest {
                node_group: "beta".to_string(),
                node_ids: Vec::new(),
                target_version: "0.2.0".to_string(),
                drain_before_upgrade: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(upg.targeted_nodes, 1);
        assert_eq!(upg.targeted_node_ids, vec!["w1"]);

        scheduler
            .submit_task(make_test_task(
                "t-drain",
                60,
                false,
                ExecutionEngine::WasmWasi,
            ))
            .unwrap();

        // w1 is draining: receives desired_client_version=0.2.0 and NO task
        let s1 = scheduler
            .sync_node_state("w1", &w1.session_token, &[], 1100)
            .unwrap();
        assert!(s1.desired_tasks.is_empty());
        assert_eq!(s1.desired_client_version, "0.2.0");

        // w2 was NOT drained and is at 0.2.0: receives task and empty desired_client_version
        let s2 = scheduler
            .sync_node_state("w2", &w2.session_token, &[], 1100)
            .unwrap();
        assert_eq!(s2.desired_tasks.len(), 1);
        assert_eq!(s2.desired_client_version, "");

        // Undrain w1
        let undrain = scheduler
            .drain_nodes(DrainNodesRequest {
                node_group: String::new(),
                node_ids: vec!["w1".to_string()],
                drain: false,
            })
            .unwrap();
        assert_eq!(undrain.affected_nodes, 1);
        assert!(
            !scheduler
                .list_worker_nodes()
                .into_iter()
                .find(|n| n.node_id == "w1")
                .unwrap()
                .draining
        );
    }

    #[test]
    fn test_sync_node_state_metered_cellular_hides_desired_client_version() {
        let scheduler = ClusterScheduler::new();
        let reg = scheduler
            .register_node(
                "dual-1".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                1000,
            )
            .unwrap();

        scheduler
            .upgrade_nodes(UpgradeNodesRequest {
                node_group: String::new(),
                node_ids: vec!["dual-1".to_string()],
                target_version: "0.2.0".to_string(),
                drain_before_upgrade: false,
                ..Default::default()
            })
            .unwrap();

        let wifi_sync = scheduler
            .sync_node_state("dual-1", &reg.session_token, &[], 1100)
            .unwrap();
        assert_eq!(wifi_sync.desired_client_version, "0.2.0");

        let _ = scheduler
            .claim_cellular_task_nominal("dual-1", 90, false, 1200)
            .unwrap();

        let metered_sync = scheduler
            .sync_node_state("dual-1", &reg.session_token, &[], 1300)
            .unwrap();
        assert_eq!(metered_sync.desired_client_version, "");
    }

    #[test]
    fn test_upgrade_nodes_rollback_clears_stale_desired_version() {
        let scheduler = ClusterScheduler::new();

        // Empty or whitespace client_version is rejected symmetrically with target_version
        assert!(matches!(
            scheduler.register_node(
                "rb-bad".to_string(),
                make_test_capabilities(false, false),
                " ".to_string(),
                1000,
            ),
            Err(SchedulingError::InvalidNodeGroupRequest(_))
        ));

        let reg = scheduler
            .register_node(
                "rb-1".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                1000,
            )
            .unwrap();
        scheduler
            .register_node(
                "rb-2".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                1000,
            )
            .unwrap();

        // Manually drain rb-2 before upgrade
        scheduler
            .drain_nodes(DrainNodesRequest {
                node_group: String::new(),
                node_ids: vec!["rb-2".to_string()],
                drain: true,
            })
            .unwrap();

        scheduler
            .upgrade_nodes(UpgradeNodesRequest {
                node_group: String::new(),
                node_ids: vec!["rb-1".to_string(), "rb-2".to_string()],
                target_version: "0.2.0".to_string(),
                drain_before_upgrade: true,
                ..Default::default()
            })
            .unwrap();

        let rb = scheduler
            .upgrade_nodes(UpgradeNodesRequest {
                node_group: String::new(),
                node_ids: vec!["rb-1".to_string(), "rb-2".to_string()],
                target_version: "0.1.0".to_string(),
                drain_before_upgrade: false,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(rb.targeted_nodes, 0);

        let sync = scheduler
            .sync_node_state("rb-1", &reg.session_token, &[], 1100)
            .unwrap();
        assert_eq!(sync.desired_client_version, "");

        let nodes = scheduler.list_worker_nodes();
        let n1 = nodes.iter().find(|n| n.node_id == "rb-1").unwrap();
        let n2 = nodes.iter().find(|n| n.node_id == "rb-2").unwrap();
        assert_eq!(n1.desired_client_version, "");
        assert!(!n1.draining);
        assert!(n2.draining);
    }

    #[test]
    fn test_task_group_submit_and_replace_node_group_affinity() {
        let scheduler = ClusterScheduler::new();
        scheduler
            .create_node_group(
                CreateNodeGroupRequest {
                    group_id: "pool-a".to_string(),
                    description: String::new(),
                    label_selector: HashMap::new(),
                    initial_node_ids: vec!["w-a".to_string()],
                },
                1000,
            )
            .unwrap();
        scheduler
            .create_node_group(
                CreateNodeGroupRequest {
                    group_id: "pool-b".to_string(),
                    description: String::new(),
                    label_selector: HashMap::new(),
                    initial_node_ids: vec!["w-b".to_string()],
                },
                1000,
            )
            .unwrap();

        let wa = scheduler
            .register_node(
                "w-a".to_string(),
                make_test_capabilities(false, false),
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();
        let wb = scheduler
            .register_node(
                "w-b".to_string(),
                make_test_capabilities(false, false),
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();

        let mut bad_tpl = make_group_template(&"a".repeat(64));
        bad_tpl.node_group_affinity = "missing-pool".to_string();
        assert!(matches!(
            scheduler.submit_task_group(
                TaskGroupSpec {
                    group_id: "tg-aff".to_string(),
                    template: Some(bad_tpl),
                    partitions: vec![TaskPartitionSpec::default()],
                },
                1100,
            ),
            Err(SchedulingError::NodeGroupNotFound(_))
        ));

        let mut tpl_a = make_group_template(&"a".repeat(64));
        tpl_a.node_group_affinity = "pool-a".to_string();
        scheduler
            .submit_task_group(
                TaskGroupSpec {
                    group_id: "tg-aff".to_string(),
                    template: Some(tpl_a),
                    partitions: vec![TaskPartitionSpec::default()],
                },
                1200,
            )
            .unwrap();

        assert!(scheduler
            .sync_node_state("w-b", &wb.session_token, &[], 1250)
            .unwrap()
            .desired_tasks
            .is_empty());
        assert_eq!(
            scheduler
                .sync_node_state("w-a", &wa.session_token, &[], 1250)
                .unwrap()
                .desired_tasks
                .len(),
            1
        );

        let mut bad_rep = make_group_template(&"b".repeat(64));
        bad_rep.node_group_affinity = "missing-pool".to_string();
        assert!(matches!(
            scheduler.replace_task_group(
                ReplaceTaskGroupRequest {
                    group_id: "tg-aff".to_string(),
                    expected_epoch: Some(1),
                    template: Some(bad_rep),
                    partitions: vec![TaskPartitionSpec::default()],
                    strategy: ReplaceStrategy::Immediate as i32,
                },
                1300,
            ),
            Err(SchedulingError::NodeGroupNotFound(_))
        ));

        let mut tpl_b = make_group_template(&"b".repeat(64));
        tpl_b.node_group_affinity = "pool-b".to_string();
        scheduler
            .replace_task_group(
                ReplaceTaskGroupRequest {
                    group_id: "tg-aff".to_string(),
                    expected_epoch: Some(1),
                    template: Some(tpl_b),
                    partitions: vec![TaskPartitionSpec::default()],
                    strategy: ReplaceStrategy::Immediate as i32,
                },
                1400,
            )
            .unwrap();

        assert!(scheduler
            .sync_node_state("w-a", &wa.session_token, &[], 1450)
            .unwrap()
            .desired_tasks
            .is_empty());
        assert_eq!(
            scheduler
                .sync_node_state("w-b", &wb.session_token, &[], 1450)
                .unwrap()
                .desired_tasks
                .len(),
            1
        );
    }

    #[test]
    fn test_upgrade_drain_clears_on_target_version_reconnect_while_manual_drain_persists() {
        let scheduler = ClusterScheduler::new();
        scheduler
            .register_node(
                "u1".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                1000,
            )
            .unwrap();
        scheduler
            .register_node(
                "u2".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                1000,
            )
            .unwrap();

        // u2 is manually drained before upgrade
        scheduler
            .drain_nodes(DrainNodesRequest {
                node_group: String::new(),
                node_ids: vec!["u2".to_string()],
                drain: true,
            })
            .unwrap();

        // Upgrade both with drain_before_upgrade = true
        scheduler
            .upgrade_nodes(UpgradeNodesRequest {
                node_group: String::new(),
                node_ids: vec!["u1".to_string(), "u2".to_string()],
                target_version: "0.2.0".to_string(),
                drain_before_upgrade: true,
                ..Default::default()
            })
            .unwrap();

        // Both reconnect on 0.2.0: u1 auto-undrains; u2 stays drained (manual drain preserved)
        let r1 = scheduler
            .register_node(
                "u1".to_string(),
                make_test_capabilities(false, false),
                "0.2.0".to_string(),
                1100,
            )
            .unwrap();
        scheduler
            .register_node(
                "u2".to_string(),
                make_test_capabilities(false, false),
                "0.2.0".to_string(),
                1100,
            )
            .unwrap();

        let nodes = scheduler.list_worker_nodes();
        let n1 = nodes.iter().find(|n| n.node_id == "u1").unwrap();
        let n2 = nodes.iter().find(|n| n.node_id == "u2").unwrap();
        assert!(!n1.draining);
        assert!(n2.draining);

        // u1 can now receive tasks
        scheduler
            .submit_task(make_test_task(
                "t-post-upg",
                60,
                false,
                ExecutionEngine::WasmWasi,
            ))
            .unwrap();
        let s1 = scheduler
            .sync_node_state("u1", &r1.session_token, &[], 1200)
            .unwrap();
        assert_eq!(s1.desired_tasks.len(), 1);
    }

    #[test]
    fn test_multi_selector_match_tie_breaker_and_affinity() {
        let scheduler = ClusterScheduler::new();
        scheduler
            .create_node_group(
                CreateNodeGroupRequest {
                    group_id: "g-alpha".to_string(),
                    description: String::new(),
                    label_selector: HashMap::from([("tier".to_string(), "prod".to_string())]),
                    initial_node_ids: Vec::new(),
                },
                1000,
            )
            .unwrap();
        scheduler
            .create_node_group(
                CreateNodeGroupRequest {
                    group_id: "g-beta".to_string(),
                    description: String::new(),
                    label_selector: HashMap::from([(
                        "androgrid.io/transport".to_string(),
                        "wifi".to_string(),
                    )]),
                    initial_node_ids: Vec::new(),
                },
                1000,
            )
            .unwrap();

        let reg = scheduler
            .register_node_with_labels(
                "multi-1".to_string(),
                make_test_capabilities(false, false),
                "1.0.0".to_string(),
                HashMap::from([("tier".to_string(), "prod".to_string())]),
                1000,
            )
            .unwrap();

        // list_worker_nodes reports lexicographically smallest match ("g-alpha")
        let info = scheduler.list_worker_nodes();
        assert_eq!(info[0].node_group, "g-alpha");

        // Both groups count the matching unpinned worker
        let groups = scheduler.list_node_groups();
        assert_eq!(groups[0].active_node_count, 1);
        assert_eq!(groups[1].active_node_count, 1);

        // Task pinned to g-beta still schedules onto multi-1
        let mut t_beta = make_test_task("t-beta", 60, false, ExecutionEngine::WasmWasi);
        t_beta.node_group_affinity = "g-beta".to_string();
        scheduler.submit_task(t_beta).unwrap();
        let sync = scheduler
            .sync_node_state("multi-1", &reg.session_token, &[], 1100)
            .unwrap();
        assert_eq!(sync.desired_tasks.len(), 1);
        assert_eq!(sync.desired_tasks[0].task_id, "t-beta");
    }

    #[test]
    fn test_drain_group_with_prepinned_unregistered_nodes_vs_explicit_node_ids() {
        let scheduler = ClusterScheduler::new();
        scheduler
            .create_node_group(
                CreateNodeGroupRequest {
                    group_id: "pre-grp".to_string(),
                    description: String::new(),
                    label_selector: HashMap::new(),
                    initial_node_ids: vec!["ghost-1".to_string(), "live-1".to_string()],
                },
                1000,
            )
            .unwrap();
        scheduler
            .register_node(
                "live-1".to_string(),
                make_test_capabilities(false, false),
                "1.0.0".to_string(),
                1000,
            )
            .unwrap();

        // Group drain targets only currently registered members ("live-1")
        let grp_drain = scheduler
            .drain_nodes(DrainNodesRequest {
                node_group: "pre-grp".to_string(),
                node_ids: Vec::new(),
                drain: true,
            })
            .unwrap();
        assert_eq!(grp_drain.affected_nodes, 1);
        assert_eq!(grp_drain.affected_node_ids, vec!["live-1"]);

        // Explicit node_ids drain rejects unregistered "ghost-1" with NodeNotFound
        assert!(matches!(
            scheduler.drain_nodes(DrainNodesRequest {
                node_group: String::new(),
                node_ids: vec!["ghost-1".to_string()],
                drain: true,
            }),
            Err(SchedulingError::NodeNotFound(_))
        ));
    }

    #[test]
    fn test_upgrade_nodes_validates_apk_url_and_sha256() {
        let scheduler = ClusterScheduler::new();
        scheduler
            .register_node(
                "n1".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                1000,
            )
            .unwrap();

        // Invalid APK URL (ftp scheme)
        let res_bad_url = scheduler.upgrade_nodes(UpgradeNodesRequest {
            node_group: String::new(),
            node_ids: vec!["n1".to_string()],
            target_version: "0.2.0".to_string(),
            apk_url: "ftp://example.com/app.apk".to_string(),
            ..Default::default()
        });
        assert!(matches!(
            res_bad_url,
            Err(SchedulingError::InvalidNodeGroupRequest(_))
        ));

        // Invalid SHA-256 (too short)
        let res_bad_sha = scheduler.upgrade_nodes(UpgradeNodesRequest {
            node_group: String::new(),
            node_ids: vec!["n1".to_string()],
            target_version: "0.2.0".to_string(),
            apk_sha256: "abcd123".to_string(),
            ..Default::default()
        });
        assert!(matches!(
            res_bad_sha,
            Err(SchedulingError::InvalidNodeGroupRequest(_))
        ));

        // Valid APK URL and SHA-256
        let res_valid = scheduler.upgrade_nodes(UpgradeNodesRequest {
            node_group: String::new(),
            node_ids: vec!["n1".to_string()],
            target_version: "0.2.0".to_string(),
            apk_url: "https://dl.androgrid.net/apk/v0.2.0.apk".to_string(),
            apk_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            ..Default::default()
        });
        assert!(res_valid.is_ok());
    }

    #[test]
    fn test_upgrade_nodes_rolling_canary_rollout_and_automatic_promotion() {
        let scheduler = ClusterScheduler::new();
        for id in ["c1", "c2", "c3", "c4"] {
            scheduler
                .register_node(
                    id.to_string(),
                    make_test_capabilities(false, false),
                    "0.1.0".to_string(),
                    1000,
                )
                .unwrap();
        }

        // Rolling upgrade with 25% rollout percentage (1 of 4 nodes)
        let res = scheduler
            .upgrade_nodes(UpgradeNodesRequest {
                node_group: String::new(),
                node_ids: vec![
                    "c1".to_string(),
                    "c2".to_string(),
                    "c3".to_string(),
                    "c4".to_string(),
                ],
                target_version: "0.2.0".to_string(),
                apk_url:
                    "/v1/blobs/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .to_string(),
                apk_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                rollout_strategy: UpgradeRolloutStrategy::Rolling as i32,
                rollout_percentage: 25,
                drain_before_upgrade: true,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(res.eligible_nodes, 4);
        assert_eq!(res.targeted_nodes, 1);
        assert_eq!(res.targeted_node_ids, vec!["c1"]);

        // Verify c1 has directive and is drained; c2..c4 are not drained
        let nodes = scheduler.list_worker_nodes();
        let n1 = nodes.iter().find(|n| n.node_id == "c1").unwrap();
        let n2 = nodes.iter().find(|n| n.node_id == "c2").unwrap();
        assert!(n1.draining);
        assert!(!n2.draining);

        // c1 completes upgrade and reconnects with 0.2.0
        let r1 = scheduler
            .register_node(
                "c1".to_string(),
                make_test_capabilities(false, false),
                "0.2.0".to_string(),
                1100,
            )
            .unwrap();
        assert!(!r1.session_token.is_empty());

        // c1 is now auto-undrained, and c2 was automatically promoted!
        let nodes_after = scheduler.list_worker_nodes();
        let n1_after = nodes_after.iter().find(|n| n.node_id == "c1").unwrap();
        let n2_after = nodes_after.iter().find(|n| n.node_id == "c2").unwrap();
        assert!(!n1_after.draining);
        assert_eq!(n1_after.desired_client_version, "");
        assert!(n2_after.draining);
        assert_eq!(n2_after.desired_client_version, "0.2.0");
    }

    #[test]
    fn test_upgrade_nodes_cellular_network_policy_enforcement() {
        let scheduler = ClusterScheduler::new();
        let reg = scheduler
            .register_node(
                "cell-1".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                1000,
            )
            .unwrap();

        // 1. Default policy (wifi-only)
        scheduler
            .upgrade_nodes(UpgradeNodesRequest {
                node_group: String::new(),
                node_ids: vec!["cell-1".to_string()],
                target_version: "0.2.0".to_string(),
                apk_url: "https://dl.androgrid.net/apk/v0.2.0.apk".to_string(),
                apk_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                network_policy: UpgradeNetworkPolicy::WifiOnly as i32,
                ..Default::default()
            })
            .unwrap();

        // Over Wi-Fi: receives directive
        let wifi_sync = scheduler
            .sync_node_state("cell-1", &reg.session_token, &[], 1100)
            .unwrap();
        assert!(wifi_sync.upgrade_directive.is_some());
        assert_eq!(
            wifi_sync.upgrade_directive.as_ref().unwrap().target_version,
            "0.2.0"
        );

        // Over Cellular WAN: directive is suppressed per [ANTI-003] and [INV-003]
        let cell_claim = scheduler
            .claim_cellular_task_nominal("cell-1", 90, false, 1200)
            .unwrap();
        assert!(cell_claim.upgrade_directive.is_none());

        // 2. Allow cellular policy
        scheduler
            .upgrade_nodes(UpgradeNodesRequest {
                node_group: String::new(),
                node_ids: vec!["cell-1".to_string()],
                target_version: "0.3.0".to_string(),
                apk_url: "https://dl.androgrid.net/apk/v0.3.0.apk".to_string(),
                apk_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                network_policy: UpgradeNetworkPolicy::AllowCellular as i32,
                ..Default::default()
            })
            .unwrap();

        // Over Cellular WAN: directive IS delivered
        let cell_claim_allowed = scheduler
            .claim_cellular_task_nominal("cell-1", 90, false, 1300)
            .unwrap();
        assert!(cell_claim_allowed.upgrade_directive.is_some());
        assert_eq!(
            cell_claim_allowed
                .upgrade_directive
                .as_ref()
                .unwrap()
                .target_version,
            "0.3.0"
        );
    }

    #[test]
    fn test_upgrade_nodes_terminal_failure_halts_canary_and_clears_directive() {
        let scheduler = ClusterScheduler::new();
        for id in ["c1", "c2", "c3", "c4"] {
            scheduler
                .register_node(
                    id.to_string(),
                    make_test_capabilities(false, false),
                    "0.1.0".to_string(),
                    1000,
                )
                .unwrap();
        }

        // Rolling upgrade with 25% rollout percentage (targeting c1)
        let res = scheduler
            .upgrade_nodes(UpgradeNodesRequest {
                node_group: String::new(),
                node_ids: vec![
                    "c1".to_string(),
                    "c2".to_string(),
                    "c3".to_string(),
                    "c4".to_string(),
                ],
                target_version: "0.2.0".to_string(),
                apk_url: "https://dl.androgrid.net/apk/v0.2.0.apk".to_string(),
                apk_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                rollout_strategy: UpgradeRolloutStrategy::Rolling as i32,
                rollout_percentage: 25,
                drain_before_upgrade: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(res.targeted_node_ids, vec!["c1"]);

        // c1 receives upgrade directive on sync
        let sync1 = scheduler
            .sync_node_state("c1", "session-c1-1000", &[], 1050)
            .unwrap();
        assert!(sync1.upgrade_directive.is_some());

        // c1 fails terminally (e.g., INSTALL_FAILED_VERSION_DOWNGRADE) and reports outcome
        let outcome = LastUpgradeOutcome {
            target_version: "0.2.0".to_string(),
            apk_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            status: UpgradeInstallStatus::TerminallyRejected as i32,
            error_code: "INSTALL_FAILED_VERSION_DOWNGRADE".to_string(),
            error_message: "System rejected version downgrade".to_string(),
            attempt_count: 1,
        };

        let sync_fail = scheduler
            .sync_node_state_with_outcome("c1", "session-c1-1000", &[], Some(outcome), 1100)
            .unwrap();

        // 1. Directive is cleared for c1 (no infinite loop)
        assert!(sync_fail.upgrade_directive.is_none());

        // 2. c1 is un-drained
        let nodes = scheduler.list_worker_nodes();
        let n1 = nodes.iter().find(|n| n.node_id == "c1").unwrap();
        assert!(!n1.draining);
        assert_eq!(n1.desired_client_version, "");

        // 3. Canary cohort promotion is immediately HALTED: c2 is NOT promoted
        let n2 = nodes.iter().find(|n| n.node_id == "c2").unwrap();
        assert!(!n2.draining);
        assert_eq!(n2.desired_client_version, "");

        // Even if c1 subsequently reconnects or syncs again, canary remains halted
        let sync_c2 = scheduler
            .sync_node_state("c2", "session-c2-1000", &[], 1200)
            .unwrap();
        assert!(sync_c2.upgrade_directive.is_none());
    }

    #[test]
    fn test_upgrade_nodes_rollout_store_durability_and_restart_reconciliation() {
        let temp_dir = std::env::temp_dir().join(format!(
            "androgrid_rollout_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store1 =
            Arc::new(crate::scheduler::rollout_store::RolloutStore::with_directory(&temp_dir));
        let scheduler1 = ClusterScheduler::with_rollout_store(store1);

        for id in ["c1", "c2", "c3", "c4"] {
            scheduler1
                .register_node(
                    id.to_string(),
                    make_test_capabilities(false, false),
                    "0.1.0".to_string(),
                    1000,
                )
                .unwrap();
        }

        // Start 25% rolling rollout (targets c1)
        scheduler1
            .upgrade_nodes(UpgradeNodesRequest {
                node_group: String::new(),
                node_ids: vec![
                    "c1".to_string(),
                    "c2".to_string(),
                    "c3".to_string(),
                    "c4".to_string(),
                ],
                target_version: "0.2.0".to_string(),
                apk_url: "https://dl.androgrid.net/apk/v0.2.0.apk".to_string(),
                apk_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                rollout_strategy: UpgradeRolloutStrategy::Rolling as i32,
                rollout_percentage: 25,
                drain_before_upgrade: true,
                ..Default::default()
            })
            .unwrap();

        // Simulate Orchestrator restart: new scheduler instance with the same storage directory
        let store2 =
            Arc::new(crate::scheduler::rollout_store::RolloutStore::with_directory(&temp_dir));
        let scheduler2 = ClusterScheduler::with_rollout_store(store2);

        // Nodes reconnect to new orchestrator instance on version 0.1.0
        for id in ["c1", "c2", "c3", "c4"] {
            scheduler2
                .register_node(
                    id.to_string(),
                    make_test_capabilities(false, false),
                    "0.1.0".to_string(),
                    2000,
                )
                .unwrap();
        }

        // Reconcile rollouts from store on startup
        let reconciled = scheduler2.reconcile_rollouts_from_store().unwrap();
        assert_eq!(reconciled, 1);

        // Ground-truth check: c1 has not completed upgrade, so c2..c4 MUST NOT be promoted (no split-brain blast)
        let nodes = scheduler2.list_worker_nodes();
        let n1 = nodes.iter().find(|n| n.node_id == "c1").unwrap();
        let n2 = nodes.iter().find(|n| n.node_id == "c2").unwrap();
        assert!(n1.draining);
        assert_eq!(n1.desired_client_version, "0.2.0");
        assert!(!n2.draining);
        assert_eq!(n2.desired_client_version, "");

        // c1 completes upgrade and registers with version 0.2.0
        scheduler2
            .register_node(
                "c1".to_string(),
                make_test_capabilities(false, false),
                "0.2.0".to_string(),
                2100,
            )
            .unwrap();

        // Now c1 is upgraded and auto-undrained, and c2 is cleanly promoted to the next canary cohort
        let nodes_after = scheduler2.list_worker_nodes();
        let n1_after = nodes_after.iter().find(|n| n.node_id == "c1").unwrap();
        let n2_after = nodes_after.iter().find(|n| n.node_id == "c2").unwrap();
        assert!(!n1_after.draining);
        assert_eq!(n1_after.desired_client_version, "");
        assert!(n2_after.draining);
        assert_eq!(n2_after.desired_client_version, "0.2.0");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_upgrade_nodes_reconnect_empty_scheduler_preserves_canary_pacing_and_undrains() {
        let temp_dir = std::env::temp_dir().join(format!(
            "androgrid_empty_restart_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store1 =
            Arc::new(crate::scheduler::rollout_store::RolloutStore::with_directory(&temp_dir));
        let scheduler1 = ClusterScheduler::with_rollout_store(store1);

        for id in ["node-1", "node-2", "node-3", "node-4"] {
            scheduler1
                .register_node(
                    id.to_string(),
                    make_test_capabilities(false, false),
                    "0.1.0".to_string(),
                    1000,
                )
                .unwrap();
        }

        scheduler1
            .upgrade_nodes(UpgradeNodesRequest {
                node_group: String::new(),
                node_ids: vec![
                    "node-1".to_string(),
                    "node-2".to_string(),
                    "node-3".to_string(),
                    "node-4".to_string(),
                ],
                target_version: "0.2.0".to_string(),
                apk_url: "https://dl.androgrid.net/apk/v0.2.0.apk".to_string(),
                apk_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                rollout_strategy: UpgradeRolloutStrategy::Rolling as i32,
                rollout_percentage: 25,
                drain_before_upgrade: true,
                ..Default::default()
            })
            .unwrap();

        // Simulate real startup: orchestrator starts with NO connected workers, loads rollouts
        let store2 =
            Arc::new(crate::scheduler::rollout_store::RolloutStore::with_directory(&temp_dir));
        let scheduler2 = ClusterScheduler::with_rollout_store(store2);
        let reconciled = scheduler2.reconcile_rollouts_from_store().unwrap();
        assert_eq!(reconciled, 1);

        // Staged node-2 reconnects BEFORE in-flight node-1
        let reg2 = scheduler2
            .register_node(
                "node-2".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                2000,
            )
            .unwrap();
        // Regression check: node-2 MUST NOT receive upgrade directive or be drained
        let sync2 = scheduler2
            .sync_node_state("node-2", &reg2.session_token, &[], 2001)
            .unwrap();
        assert!(sync2.upgrade_directive.is_none());
        let node2_rec = scheduler2
            .list_worker_nodes()
            .into_iter()
            .find(|n| n.node_id == "node-2")
            .unwrap();
        assert!(!node2_rec.draining);
        assert_eq!(node2_rec.desired_client_version, "");

        // In-flight node-1 reconnects
        let reg1 = scheduler2
            .register_node(
                "node-1".to_string(),
                make_test_capabilities(false, false),
                "0.1.0".to_string(),
                2001,
            )
            .unwrap();
        let sync1 = scheduler2
            .sync_node_state("node-1", &reg1.session_token, &[], 2002)
            .unwrap();
        assert!(sync1.upgrade_directive.is_some());
        let node1_rec = scheduler2
            .list_worker_nodes()
            .into_iter()
            .find(|n| n.node_id == "node-1")
            .unwrap();
        assert!(node1_rec.draining);
        assert_eq!(node1_rec.desired_client_version, "0.2.0");

        // node-1 reports FAILED_TRANSIENT: rollout MUST NOT halt and node-1 MUST NOT be evicted
        let sync_resp = scheduler2
            .sync_node_state_with_outcome(
                "node-1",
                &reg1.session_token,
                &[],
                Some(crate::LastUpgradeOutcome {
                    target_version: "0.2.0".to_string(),
                    apk_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .to_string(),
                    status: crate::UpgradeInstallStatus::FailedTransient as i32,
                    error_code: "DOWNLOAD_TIMEOUT".to_string(),
                    error_message: "Network dropped".to_string(),
                    attempt_count: 1,
                }),
                2003,
            )
            .unwrap();
        // Directive remains assigned for retry
        assert!(sync_resp.upgrade_directive.is_some());

        // node-1 successfully completes upgrade and re-registers on 0.2.0
        let reg1_upgraded = scheduler2
            .register_node(
                "node-1".to_string(),
                make_test_capabilities(false, false),
                "0.2.0".to_string(),
                2100,
            )
            .unwrap();
        let sync1_upgraded = scheduler2
            .sync_node_state("node-1", &reg1_upgraded.session_token, &[], 2101)
            .unwrap();
        assert!(sync1_upgraded.upgrade_directive.is_none());

        // node-1 must be auto-undrained, and node-2 must now be promoted
        let node1_done = scheduler2
            .list_worker_nodes()
            .into_iter()
            .find(|n| n.node_id == "node-1")
            .unwrap();
        let node2_promoted = scheduler2
            .list_worker_nodes()
            .into_iter()
            .find(|n| n.node_id == "node-2")
            .unwrap();
        assert!(!node1_done.draining);
        assert_eq!(node1_done.desired_client_version, "");
        assert!(node2_promoted.draining);
        assert_eq!(node2_promoted.desired_client_version, "0.2.0");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Verifies version string comparison across pre-release and general release identifiers.
    ///
    /// Traces to: [REQ-VER-001], Gate L-02
    #[test]
    fn test_compare_client_versions() {
        assert_eq!(
            compare_client_versions("0.0.1-alpha.5", "0.0.1-alpha.6").unwrap(),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_client_versions("0.0.1-alpha.6", "0.0.1-alpha.6").unwrap(),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            compare_client_versions("0.0.1-alpha.7", "0.0.1-alpha.6").unwrap(),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_client_versions("0.1.0", "0.0.1-alpha.6").unwrap(),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_client_versions("1.0.0", "0.0.1-alpha.6").unwrap(),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_client_versions("v0.0.1-alpha.6", "0.0.1-alpha.6").unwrap(),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            compare_client_versions("0.0.1-alpha.6+build.100", "0.0.1-alpha.6+build.200").unwrap(),
            std::cmp::Ordering::Equal
        );
        // Numeric prerelease has lower precedence than alphanumeric prerelease (0 < alpha)
        assert_eq!(
            compare_client_versions("0.0.1-0", "0.0.1-alpha.6").unwrap(),
            std::cmp::Ordering::Less
        );
        // Prerelease precedence: alpha < beta < rc
        assert_eq!(
            compare_client_versions("0.0.1-alpha.1", "0.0.1-beta.1").unwrap(),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_client_versions("0.0.1-beta.1", "0.0.1-rc.1").unwrap(),
            std::cmp::Ordering::Less
        );
        // Malformed versions return Err
        assert!(compare_client_versions("0.bad.0.1-alpha.6", "0.0.1-alpha.6").is_err());
        assert!(parse_client_version("not-a-version").is_err());
    }

    /// Verifies newly joining workers reporting client version below baseline are rejected.
    ///
    /// Traces to: [REQ-VER-001], [REQ-OP-001], Gate L-02
    #[test]
    fn test_register_node_rejects_new_worker_below_onboarding_baseline() {
        let scheduler = ClusterScheduler::new();
        let caps = make_test_capabilities(false, false);

        // First attempt with 0.0.1-alpha.5 must fail admission
        let err = scheduler
            .register_node(
                "new-node-alpha5".to_string(),
                caps.clone(),
                "0.0.1-alpha.5".to_string(),
                1000,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            SchedulingError::OnboardingVersionBelowBaseline {
                client_version,
                min_version,
            } if client_version == "0.0.1-alpha.5" && min_version == "0.0.1-alpha.6"
        ));

        // Attempt with baseline version 0.0.1-alpha.6 must succeed
        let reg = scheduler
            .register_node(
                "new-node-alpha6".to_string(),
                caps,
                "0.0.1-alpha.6".to_string(),
                1001,
            )
            .unwrap();
        assert!(reg.session_token.contains("new-node-alpha6"));
    }

    /// Verifies existing admitted workers are permitted to reconnect even below baseline.
    ///
    /// Traces to: [REQ-VER-001], [REQ-OP-001], Gate L-02
    #[test]
    fn test_register_node_permits_existing_worker_below_onboarding_baseline() {
        let scheduler = ClusterScheduler::new();
        let caps = make_test_capabilities(false, false);

        // Pre-mark node as admitted (simulating prior admission before gate was raised)
        scheduler.mark_node_admitted("legacy-worker");
        assert!(scheduler.is_node_admitted("legacy-worker"));

        // Legacy worker reconnects with 0.0.1-alpha.5; must succeed without rejection or eviction
        let reg = scheduler
            .register_node(
                "legacy-worker".to_string(),
                caps,
                "0.0.1-alpha.5".to_string(),
                1000,
            )
            .unwrap();
        assert!(reg.session_token.contains("legacy-worker"));
    }

    /// Verifies admitted node membership persists across scheduler instance restarts.
    ///
    /// Traces to: [REQ-VER-001], [REQ-OP-001], Gate L-02
    #[test]
    fn test_admitted_nodes_persists_across_restart() {
        let temp_dir = std::env::temp_dir().join(format!("androgrid-admit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let db_path = temp_dir.join("admission.redb");
        let store = Arc::new(
            crate::scheduler::admission_store::DurableAdmissionStore::open(&db_path).unwrap(),
        );
        let rollout_store = Arc::new(crate::scheduler::rollout_store::RolloutStore::new());

        let scheduler1 = ClusterScheduler::with_options_and_stores(
            false,
            ThermalPolicy::default(),
            rollout_store.clone(),
            store.clone(),
        );
        let caps = make_test_capabilities(false, false);

        // Register node with 0.0.1-alpha.6
        scheduler1
            .register_node(
                "persisted-worker".to_string(),
                caps.clone(),
                "0.0.1-alpha.6".to_string(),
                1000,
            )
            .unwrap();
        assert!(scheduler1.is_node_admitted("persisted-worker"));

        drop(scheduler1);
        drop(store);

        // Create new scheduler instance with the same storage database
        let store2 = Arc::new(
            crate::scheduler::admission_store::DurableAdmissionStore::open(&db_path).unwrap(),
        );
        let scheduler2 = ClusterScheduler::with_options_and_stores(
            false,
            ThermalPolicy::default(),
            rollout_store,
            store2,
        );
        assert!(scheduler2.is_node_admitted("persisted-worker"));

        // Persisted worker reconnects with 0.0.1-alpha.5; recognized as admitted
        let reg = scheduler2
            .register_node(
                "persisted-worker".to_string(),
                caps,
                "0.0.1-alpha.5".to_string(),
                2000,
            )
            .unwrap();
        assert!(reg.session_token.contains("persisted-worker"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
