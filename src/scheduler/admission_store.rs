//! Durable embedded transactional admission store backed by `redb` and Protobuf.
//!
//! Maintains a durable, crash-resilient ledger of admitted worker nodes
//! and an in-memory index for O(1) admission checks without lock contention.
//!
//! Traces to: [REQ-OP-001], [REQ-VER-001], [INV-002], Gate L-02

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use prost::Message;
use redb::{Database, ReadableTable, TableDefinition};
use tracing::info;

use crate::scheduler::errors::SchedulingError;

const ADMISSION_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("admitted_workers");

/// Protobuf-encoded admission record stored in `redb`.
///
/// Traces to: [REQ-OP-001], [REQ-VER-001]
#[derive(Clone, PartialEq, prost::Message)]
pub struct AdmissionRecordProto {
    /// Canonical mobile worker node identifier.
    #[prost(string, tag = "1")]
    pub node_id: String,

    /// Client version reported at initial admission.
    #[prost(string, tag = "2")]
    pub initial_client_version: String,

    /// Epoch millisecond timestamp of admission.
    #[prost(uint64, tag = "3")]
    pub admitted_epoch_ms: u64,

    /// Last seen epoch millisecond timestamp.
    #[prost(uint64, tag = "4")]
    pub last_seen_epoch_ms: u64,

    /// Provenance source (0: FreshOnboarded, 1: LegacyMigrated, 2: AdminSeeded).
    #[prost(int32, tag = "5")]
    pub admission_source: i32,
}

/// Provenance of an admitted worker node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionSource {
    FreshOnboarded = 0,
    LegacyMigrated = 1,
    AdminSeeded = 2,
}

/// Durable embedded transactional admission store.
#[derive(Clone)]
pub struct DurableAdmissionStore {
    db: Option<Arc<Database>>,
    in_memory_index: Arc<RwLock<HashSet<String>>>,
    db_path: Option<PathBuf>,
}

impl std::fmt::Debug for DurableAdmissionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableAdmissionStore")
            .field("db_path", &self.db_path)
            .field(
                "admitted_count",
                &self.in_memory_index.read().map(|i| i.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl Default for DurableAdmissionStore {
    fn default() -> Self {
        Self::new_in_memory()
    }
}

impl DurableAdmissionStore {
    /// Creates an ephemeral in-memory admission store (used in tests and standalone ephemeral mode).
    pub fn new_in_memory() -> Self {
        Self {
            db: None,
            in_memory_index: Arc::new(RwLock::new(HashSet::new())),
            db_path: None,
        }
    }

    /// Opens an embedded transactional database at the specified path.
    ///
    /// Requires an existing database unless authorized via `open_or_create`.
    /// Traces to: [REQ-OP-001], [REQ-VER-001], Gate L-02
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SchedulingError> {
        Self::open_or_create(path, false)
    }

    /// Opens or explicitly creates an embedded transactional database at the specified path.
    ///
    /// When `allow_create` is false, returns an error if the database file does not already exist,
    /// preventing ordinary startup from silently creating an empty database when established state is expected.
    /// Traces to: [REQ-OP-001], [REQ-VER-001], Gate L-02
    pub fn open_or_create<P: AsRef<Path>>(path: P, allow_create: bool) -> Result<Self, SchedulingError> {
        let db_path = path.as_ref().to_path_buf();
        if !allow_create && !db_path.exists() {
            return Err(SchedulingError::StorageError(format!(
                "Admission database not found at '{}'. Refusing to silently create an empty database during ordinary startup; pass --init-admission-db or set ANDROGRID_INIT_ADMISSION_DB=1 to initialize a new database.",
                db_path.display()
            )));
        }
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                SchedulingError::StorageError(format!(
                    "Failed to create admission DB directory: {e}"
                ))
            })?;
        }

        let db = Database::create(&db_path).map_err(|e| {
            SchedulingError::StorageError(format!(
                "Failed to open/create redb admission database: {e}"
            ))
        })?;

        // Ensure table exists via short write transaction before hydration
        {
            let write_txn = db.begin_write().map_err(|e| {
                SchedulingError::StorageError(format!(
                    "Failed to begin init write transaction: {e}"
                ))
            })?;
            {
                let _ = write_txn.open_table(ADMISSION_TABLE).map_err(|e| {
                    SchedulingError::StorageError(format!("Failed to open admission table: {e}"))
                })?;
            }
            write_txn.commit().map_err(|e| {
                SchedulingError::StorageError(format!(
                    "Failed to commit init write transaction: {e}"
                ))
            })?;
        }

        let mut index = HashSet::new();

        // Hydrate in-memory index from existing committed records, validating and propagating errors
        {
            let read_txn = db.begin_read().map_err(|e| {
                SchedulingError::StorageError(format!(
                    "Failed to begin read transaction for hydration: {e}"
                ))
            })?;
            let table = read_txn.open_table(ADMISSION_TABLE).map_err(|e| {
                SchedulingError::StorageError(format!(
                    "Failed to open admission table for hydration: {e}"
                ))
            })?;
            let iter = table.iter().map_err(|e| {
                SchedulingError::StorageError(format!(
                    "Failed to iterate admission table during hydration: {e}"
                ))
            })?;
            for item in iter {
                let (key, value) = item.map_err(|e| {
                    SchedulingError::StorageError(format!(
                        "Failed to read hydration item from admission table: {e}"
                    ))
                })?;
                let record = AdmissionRecordProto::decode(value.value()).map_err(|e| {
                    SchedulingError::StorageError(format!(
                        "Corrupted or invalid protobuf payload in admission table entry for key '{}': {e}",
                        key.value()
                    ))
                })?;
                if record.node_id != key.value() {
                    return Err(SchedulingError::StorageError(format!(
                        "Admission record identity mismatch: table key '{}' does not match record.node_id '{}'",
                        key.value(),
                        record.node_id
                    )));
                }
                index.insert(key.value().to_string());
            }
        }

        info!(
            path = %db_path.display(),
            admitted_workers = index.len(),
            "Durable embedded admission store initialized"
        );

        Ok(Self {
            db: Some(Arc::new(db)),
            in_memory_index: Arc::new(RwLock::new(index)),
            db_path: Some(db_path),
        })
    }

    /// Returns the database path if backed by disk.
    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }

    /// Checks if a worker node is already admitted using the in-memory index.
    ///
    /// Traces to: [REQ-OP-001], [REQ-VER-001]
    pub fn is_admitted(&self, node_id: &str) -> bool {
        self.in_memory_index
            .read()
            .expect("in_memory_index read lock poisoned")
            .contains(node_id)
    }

    /// Transactionally commits a new admission record to disk and updates the in-memory index.
    ///
    /// Traces to: [REQ-OP-001], [REQ-VER-001], Gate L-02
    pub fn commit_admission(
        &self,
        node_id: &str,
        client_version: &str,
        epoch_ms: u64,
        source: AdmissionSource,
    ) -> Result<(), SchedulingError> {
        let record = AdmissionRecordProto {
            node_id: node_id.to_string(),
            initial_client_version: client_version.to_string(),
            admitted_epoch_ms: epoch_ms,
            last_seen_epoch_ms: epoch_ms,
            admission_source: source as i32,
        };

        let mut buf = Vec::with_capacity(record.encoded_len());
        record.encode(&mut buf).map_err(|e| {
            SchedulingError::StorageError(format!("Failed to encode admission record: {e}"))
        })?;

        // 1. Transactional commit to redb (if disk-backed)
        if let Some(ref db) = self.db {
            let write_txn = db.begin_write().map_err(|e| {
                SchedulingError::StorageError(format!(
                    "Failed to begin admission write transaction: {e}"
                ))
            })?;
            {
                let mut table = write_txn.open_table(ADMISSION_TABLE).map_err(|e| {
                    SchedulingError::StorageError(format!("Failed to open admission table: {e}"))
                })?;
                table.insert(node_id, buf.as_slice()).map_err(|e| {
                    SchedulingError::StorageError(format!("Failed to insert admission record: {e}"))
                })?;
            }
            write_txn.commit().map_err(|e| {
                SchedulingError::StorageError(format!(
                    "Failed to commit admission transaction: {e}"
                ))
            })?;
        }

        // 2. Update memory index only after durable commit succeeds
        self.in_memory_index
            .write()
            .expect("in_memory_index write lock poisoned")
            .insert(node_id.to_string());

        Ok(())
    }

    /// Batch migration/seeding for administrator-confirmed historical membership.
    ///
    /// Traces to: [REQ-OP-001], Gate L-02
    pub fn seed_migration_batch(
        &self,
        node_ids: &[String],
        default_version: &str,
        epoch_ms: u64,
    ) -> Result<usize, SchedulingError> {
        let mut count = 0;
        if let Some(ref db) = self.db {
            let write_txn = db.begin_write().map_err(|e| {
                SchedulingError::StorageError(format!(
                    "Failed to begin migration write transaction: {e}"
                ))
            })?;
            {
                let mut table = write_txn.open_table(ADMISSION_TABLE).map_err(|e| {
                    SchedulingError::StorageError(format!("Failed to open admission table: {e}"))
                })?;
                for node_id in node_ids {
                    let trimmed = node_id.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if table
                        .get(trimmed)
                        .map_err(|e| {
                            SchedulingError::StorageError(format!(
                                "Failed to check existing admission record during migration: {e}"
                            ))
                        })?
                        .is_some()
                    {
                        // Node is already admitted; preserve existing record and timestamp
                        continue;
                    }
                    let record = AdmissionRecordProto {
                        node_id: trimmed.to_string(),
                        initial_client_version: default_version.to_string(),
                        admitted_epoch_ms: epoch_ms,
                        last_seen_epoch_ms: epoch_ms,
                        admission_source: AdmissionSource::LegacyMigrated as i32,
                    };
                    let mut buf = Vec::with_capacity(record.encoded_len());
                    record.encode(&mut buf).map_err(|e| {
                        SchedulingError::StorageError(format!(
                            "Failed to encode migration record: {e}"
                        ))
                    })?;
                    table.insert(trimmed, buf.as_slice()).map_err(|e| {
                        SchedulingError::StorageError(format!(
                            "Failed to insert migration record: {e}"
                        ))
                    })?;
                    count += 1;
                }
            }
            write_txn.commit().map_err(|e| {
                SchedulingError::StorageError(format!(
                    "Failed to commit migration transaction: {e}"
                ))
            })?;
        } else {
            count = node_ids.len();
        }

        // Update in-memory index
        let mut index = self
            .in_memory_index
            .write()
            .expect("in_memory_index write lock");
        for node_id in node_ids {
            let trimmed = node_id.trim();
            if !trimmed.is_empty() {
                index.insert(trimmed.to_string());
            }
        }

        info!(
            count = count,
            default_version = %default_version,
            "Seeded administrator-confirmed historical membership batch"
        );

        Ok(count)
    }

    /// Loads an administrator-confirmed migration inventory file from disk.
    ///
    /// Accepts newline-delimited or comma-separated node identifiers.
    /// Traces to: [REQ-OP-001], Gate L-02
    pub fn load_inventory_file<P: AsRef<Path>>(
        &self,
        path: P,
        default_version: &str,
        epoch_ms: u64,
    ) -> Result<usize, SchedulingError> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            SchedulingError::StorageError(format!("Failed to read migration inventory file: {e}"))
        })?;

        let mut node_ids = Vec::new();
        for line in content.lines() {
            let trimmed: &str = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            for part in trimmed.split(',') {
                let part_trimmed: &str = part.trim();
                if !part_trimmed.is_empty() {
                    node_ids.push(part_trimmed.to_string());
                }
            }
        }

        self.seed_migration_batch(&node_ids, default_version, epoch_ms)
    }

    /// Exports all admission records for operator inspection and diagnostics.
    pub fn export_records(&self) -> Result<Vec<AdmissionRecordProto>, SchedulingError> {
        if let Some(ref db) = self.db {
            let read_txn = db.begin_read().map_err(|e| {
                SchedulingError::StorageError(format!("Failed to begin read transaction: {e}"))
            })?;
            let table = read_txn.open_table(ADMISSION_TABLE).map_err(|e| {
                SchedulingError::StorageError(format!("Failed to open admission table: {e}"))
            })?;
            let mut records = Vec::new();
            let iter = table.iter().map_err(|e| {
                SchedulingError::StorageError(format!("Failed to iterate admission table: {e}"))
            })?;
            for item in iter {
                let (key, value) = item.map_err(|e| {
                    SchedulingError::StorageError(format!(
                        "Failed to read admission table entry: {e}"
                    ))
                })?;
                let record = AdmissionRecordProto::decode(value.value()).map_err(|e| {
                    SchedulingError::StorageError(format!(
                        "Corrupted or invalid protobuf payload in admission table entry for key '{}': {e}",
                        key.value()
                    ))
                })?;
                records.push(record);
            }
            Ok(records)
        } else {
            let index = self.in_memory_index.read().expect("index read lock");
            Ok(index
                .iter()
                .map(|id| AdmissionRecordProto {
                    node_id: id.clone(),
                    initial_client_version: "in-memory".to_string(),
                    admitted_epoch_ms: 0,
                    last_seen_epoch_ms: 0,
                    admission_source: AdmissionSource::FreshOnboarded as i32,
                })
                .collect())
        }
    }
}
