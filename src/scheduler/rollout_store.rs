//! Durable persistence and state reconciliation for OTA upgrade rollouts.
//!
//! Traces to: ADR-010, [REQ-OP-001], [REQ-OP-002], [NFR-REL-001]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::proto::androgrid::v1::{NodeUpgradeDirective, UpgradeRolloutStrategy};
use crate::scheduler::state::UpgradeRolloutRecord;

/// Serializable DTO for persisting rollout descriptors to durable disk storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedRolloutDescriptor {
    pub rollout_id: String,
    pub target_version: String,
    pub apk_url: String,
    pub apk_sha256: String,
    pub network_policy: i32,
    pub rollout_strategy: i32,
    pub rollout_percentage: u32,
    pub eligible_node_ids: Vec<String>,
    pub in_flight_node_ids: Vec<String>,
    pub completed_node_ids: Vec<String>,
    pub failed_node_ids: Vec<String>,
    pub staged_node_ids: Vec<String>,
    pub lease_timeout_seconds: u32,
    pub drain_before_upgrade: bool,
    pub is_halted: bool,
    pub halt_reason: Option<String>,
    pub created_at_epoch_ms: u64,
}

impl From<&UpgradeRolloutRecord> for PersistedRolloutDescriptor {
    fn from(rec: &UpgradeRolloutRecord) -> Self {
        Self {
            rollout_id: rec.rollout_id.clone(),
            target_version: rec.target_version.clone(),
            apk_url: rec.directive_template.apk_url.clone(),
            apk_sha256: rec.directive_template.apk_sha256.clone(),
            network_policy: rec.directive_template.network_policy,
            rollout_strategy: rec.rollout_strategy as i32,
            rollout_percentage: rec.rollout_percentage,
            eligible_node_ids: rec.eligible_node_ids.clone(),
            in_flight_node_ids: rec.in_flight_node_ids.iter().cloned().collect(),
            completed_node_ids: rec.completed_node_ids.iter().cloned().collect(),
            failed_node_ids: rec.failed_node_ids.iter().cloned().collect(),
            staged_node_ids: rec.staged_node_ids.iter().cloned().collect(),
            lease_timeout_seconds: rec.lease_timeout_seconds,
            drain_before_upgrade: rec.drain_before_upgrade,
            is_halted: rec.is_halted,
            halt_reason: rec.halt_reason.clone(),
            created_at_epoch_ms: rec.created_at_epoch_ms,
        }
    }
}

impl PersistedRolloutDescriptor {
    pub fn to_rollout_record(&self) -> UpgradeRolloutRecord {
        let directive_template = NodeUpgradeDirective {
            target_version: self.target_version.clone(),
            apk_url: self.apk_url.clone(),
            apk_sha256: self.apk_sha256.clone(),
            network_policy: self.network_policy,
            rollout_strategy: self.rollout_strategy,
            upgrade_lease_timeout_seconds: self.lease_timeout_seconds,
            drain_before_upgrade: self.drain_before_upgrade,
        };
        UpgradeRolloutRecord {
            rollout_id: self.rollout_id.clone(),
            target_version: self.target_version.clone(),
            directive_template,
            rollout_strategy: if self.rollout_strategy == UpgradeRolloutStrategy::Rolling as i32 {
                UpgradeRolloutStrategy::Rolling
            } else {
                UpgradeRolloutStrategy::Immediate
            },
            rollout_percentage: self.rollout_percentage,
            eligible_node_ids: self.eligible_node_ids.clone(),
            in_flight_node_ids: self.in_flight_node_ids.iter().cloned().collect(),
            completed_node_ids: self.completed_node_ids.iter().cloned().collect(),
            failed_node_ids: self.failed_node_ids.iter().cloned().collect(),
            staged_node_ids: self.staged_node_ids.iter().cloned().collect(),
            lease_timeout_seconds: self.lease_timeout_seconds,
            drain_before_upgrade: self.drain_before_upgrade,
            is_halted: self.is_halted,
            halt_reason: self.halt_reason.clone(),
            created_at_epoch_ms: self.created_at_epoch_ms,
        }
    }
}

/// Durable rollout store writing descriptor files to disk and caching in memory.
#[derive(Debug)]
pub struct RolloutStore {
    storage_dir: Option<PathBuf>,
    in_memory: RwLock<HashMap<String, PersistedRolloutDescriptor>>,
}

impl Default for RolloutStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RolloutStore {
    /// Creates an in-memory rollout store.
    pub fn new() -> Self {
        Self {
            storage_dir: None,
            in_memory: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a disk-backed rollout store rooted at `storage_dir`.
    pub fn with_directory<P: AsRef<Path>>(dir: P) -> Self {
        let path = dir.as_ref().to_path_buf();
        if let Err(e) = fs::create_dir_all(&path) {
            tracing::warn!(path = ?path, error = %e, "Failed to create rollout storage directory");
        }
        Self {
            storage_dir: Some(path),
            in_memory: RwLock::new(HashMap::new()),
        }
    }

    /// Saves a rollout record to memory and durable disk storage.
    pub fn save_rollout(&self, record: &UpgradeRolloutRecord) -> Result<(), std::io::Error> {
        let descriptor = PersistedRolloutDescriptor::from(record);
        let key = record.target_version.clone();

        {
            let mut mem = self.in_memory.write().unwrap();
            mem.insert(key.clone(), descriptor.clone());
        }

        if let Some(ref dir) = self.storage_dir {
            fs::create_dir_all(dir)?;
            let file_path = dir.join(format!("rollout_{}.json", sanitize_filename(&key)));
            let json = serde_json::to_string_pretty(&descriptor).map_err(std::io::Error::other)?;
            fs::write(file_path, json)?;
        }

        Ok(())
    }

    /// Loads all active rollout records from disk and memory cache.
    pub fn load_rollouts(&self) -> Result<Vec<UpgradeRolloutRecord>, std::io::Error> {
        if let Some(ref dir) = self.storage_dir {
            if dir.exists() {
                for entry in fs::read_dir(dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("json") {
                        if let Ok(content) = fs::read_to_string(&path) {
                            if let Ok(desc) =
                                serde_json::from_str::<PersistedRolloutDescriptor>(&content)
                            {
                                let mut mem = self.in_memory.write().unwrap();
                                mem.insert(desc.target_version.clone(), desc);
                            }
                        }
                    }
                }
            }
        }

        let mem = self.in_memory.read().unwrap();
        let records = mem.values().map(|d| d.to_rollout_record()).collect();
        Ok(records)
    }

    /// Deletes a persisted rollout descriptor by target version.
    pub fn delete_rollout(&self, target_version: &str) -> Result<(), std::io::Error> {
        {
            let mut mem = self.in_memory.write().unwrap();
            mem.remove(target_version);
        }

        if let Some(ref dir) = self.storage_dir {
            let file_path = dir.join(format!(
                "rollout_{}.json",
                sanitize_filename(target_version)
            ));
            if file_path.exists() {
                fs::remove_file(file_path)?;
            }
        }

        Ok(())
    }
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
