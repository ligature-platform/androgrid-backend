//! Feasibility and density spike: Embedded transactional key-value store (`redb`)
//! with Protobuf record encoding for durable cluster worker admission.
//!
//! Traces to: Issue #30, Goal [G-25], [REQ-OP-001], [REQ-VER-001], [INV-002], Gate L-02

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use prost::Message;
use redb::{Database, ReadableTable, TableDefinition};

const ADMISSION_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("admitted_workers");

/// Protobuf-encoded admission record.
/// Traces to: [REQ-OP-001], [REQ-VER-001]
#[derive(Clone, PartialEq, prost::Message)]
pub struct AdmissionRecordProto {
    #[prost(string, tag = "1")]
    pub node_id: String,
    #[prost(string, tag = "2")]
    pub initial_client_version: String,
    #[prost(uint64, tag = "3")]
    pub admitted_epoch_ms: u64,
    #[prost(uint64, tag = "4")]
    pub last_seen_epoch_ms: u64,
    #[prost(int32, tag = "5")]
    pub admission_source: i32, // 0 = FreshOnboarded, 1 = LegacyMigrated, 2 = AdminSeeded
}

pub enum AdmissionSource {
    FreshOnboarded = 0,
    LegacyMigrated = 1,
    AdminSeeded = 2,
}

/// Durable embedded KV admission store backed by `redb`.
pub struct DurableAdmissionStore {
    db: Arc<Database>,
    in_memory_index: Arc<RwLock<HashSet<String>>>,
    db_path: PathBuf,
}

impl DurableAdmissionStore {
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let db_path = path.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::create(&db_path)?;
        let mut index = HashSet::new();

        // Initialize table and populate in-memory index from committed records
        {
            let read_txn = db.begin_read()?;
            if let Ok(table) = read_txn.open_table(ADMISSION_TABLE) {
                for entry in table.iter()? {
                    let (key, _) = entry?;
                    index.insert(key.value().to_string());
                }
            }
        }

        // If table doesn't exist yet, create it in a short write transaction
        {
            let write_txn = db.begin_write()?;
            {
                let _ = write_txn.open_table(ADMISSION_TABLE)?;
            }
            write_txn.commit()?;
        }

        Ok(Self {
            db: Arc::new(db),
            in_memory_index: Arc::new(RwLock::new(index)),
            db_path,
        })
    }

    /// Checks whether a node is admitted using the zero-lock/read-locked in-memory index.
    pub fn is_admitted(&self, node_id: &str) -> bool {
        self.in_memory_index
            .read()
            .expect("index read lock poisoned")
            .contains(node_id)
    }

    /// Transactionally commits a new admission record to disk and updates the in-memory index.
    /// This runs outside the scheduler's central state write lock.
    pub fn commit_admission(
        &self,
        node_id: &str,
        client_version: &str,
        epoch_ms: u64,
        source: AdmissionSource,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let record = AdmissionRecordProto {
            node_id: node_id.to_string(),
            initial_client_version: client_version.to_string(),
            admitted_epoch_ms: epoch_ms,
            last_seen_epoch_ms: epoch_ms,
            admission_source: source as i32,
        };

        let mut buf = Vec::with_capacity(record.encoded_len());
        record.encode(&mut buf)?;

        // 1. Transactional write to redb
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(ADMISSION_TABLE)?;
            table.insert(node_id, buf.as_slice())?;
        }
        write_txn.commit()?;

        // 2. Update memory index only after durable commit succeeds
        self.in_memory_index
            .write()
            .expect("index write lock poisoned")
            .insert(node_id.to_string());

        Ok(())
    }

    /// Batch migration/seeding for administrator-confirmed historical membership.
    pub fn seed_migration_batch(
        &self,
        node_ids: &[String],
        default_version: &str,
        epoch_ms: u64,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let write_txn = self.db.begin_write()?;
        let mut count = 0;
        {
            let mut table = write_txn.open_table(ADMISSION_TABLE)?;
            for node_id in node_ids {
                let trimmed = node_id.trim();
                if trimmed.is_empty() {
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
                record.encode(&mut buf)?;
                table.insert(trimmed, buf.as_slice())?;
                count += 1;
            }
        }
        write_txn.commit()?;

        // Rebuild in-memory index
        let mut index = self.in_memory_index.write().expect("index write lock");
        for node_id in node_ids {
            let trimmed = node_id.trim();
            if !trimmed.is_empty() {
                index.insert(trimmed.to_string());
            }
        }

        Ok(count)
    }

    /// Exports all admission records for operator inspection.
    pub fn export_records(&self) -> Result<Vec<AdmissionRecordProto>, Box<dyn std::error::Error>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ADMISSION_TABLE)?;
        let mut records = Vec::new();
        for entry in table.iter()? {
            let (_, value) = entry?;
            let record = AdmissionRecordProto::decode(value.value())?;
            records.push(record);
        }
        Ok(records)
    }
}

#[test]
fn test_spike_durability_and_restart_recovery() {
    let temp_dir = std::env::temp_dir().join(format!("androgrid-spike-kv-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    let db_path = temp_dir.join("admissions.redb");

    // Phase 1: Open store and commit 100 worker admissions
    {
        let store = DurableAdmissionStore::open(&db_path).expect("open redb store");
        for i in 0..100 {
            let node_id = format!("worker-node-{:04}", i);
            store
                .commit_admission(
                    &node_id,
                    "0.0.1-alpha.6",
                    1000 + i as u64,
                    AdmissionSource::FreshOnboarded,
                )
                .expect("commit admission");
            assert!(store.is_admitted(&node_id));
        }
    }

    // Phase 2: Reopen database from disk and verify 100% recovery
    {
        let store2 = DurableAdmissionStore::open(&db_path).expect("reopen redb store");
        for i in 0..100 {
            let node_id = format!("worker-node-{:04}", i);
            assert!(
                store2.is_admitted(&node_id),
                "Recovered index must contain {node_id}"
            );
        }
        assert!(!store2.is_admitted("worker-node-9999"));

        let records = store2.export_records().expect("export records");
        assert_eq!(records.len(), 100);
        assert_eq!(records[0].initial_client_version, "0.0.1-alpha.6");
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_spike_interrupted_transaction_rollback() {
    let temp_dir =
        std::env::temp_dir().join(format!("androgrid-spike-rollback-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    let db_path = temp_dir.join("admissions.redb");

    let store = DurableAdmissionStore::open(&db_path).expect("open redb store");

    // Commit baseline node
    store
        .commit_admission(
            "baseline-node",
            "0.0.1-alpha.6",
            1000,
            AdmissionSource::FreshOnboarded,
        )
        .expect("commit baseline");
    assert!(store.is_admitted("baseline-node"));

    // Simulate an aborted/interrupted write transaction (e.g. process crash or panic)
    {
        let write_txn = store.db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(ADMISSION_TABLE).unwrap();
            let record = AdmissionRecordProto {
                node_id: "ghost-node".to_string(),
                initial_client_version: "0.0.1-alpha.6".to_string(),
                admitted_epoch_ms: 2000,
                last_seen_epoch_ms: 2000,
                admission_source: AdmissionSource::FreshOnboarded as i32,
            };
            let mut buf = Vec::new();
            record.encode(&mut buf).unwrap();
            table.insert("ghost-node", buf.as_slice()).unwrap();
        }
        // Drop write_txn without calling .commit()
        drop(write_txn);
    }

    // Drop original store to release redb file lock before reopening
    drop(store);

    // Ghost node must NOT exist in the database
    let store_reloaded = DurableAdmissionStore::open(&db_path).expect("reload store");
    assert!(store_reloaded.is_admitted("baseline-node"));
    assert!(!store_reloaded.is_admitted("ghost-node"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_spike_migration_batch_seeding() {
    let temp_dir =
        std::env::temp_dir().join(format!("androgrid-spike-migration-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    let db_path = temp_dir.join("admissions.redb");

    let store = DurableAdmissionStore::open(&db_path).expect("open redb store");

    // Administrator confirmed migration inventory of legacy Alpha.5 devices
    let legacy_nodes = vec![
        "pixel-8-shiba-alpha5".to_string(),
        "pixel-7-panther-alpha5".to_string(),
        "samsung-s23-alpha5".to_string(),
    ];

    let seeded = store
        .seed_migration_batch(&legacy_nodes, "0.0.1-alpha.5", 500)
        .expect("batch seed");
    assert_eq!(seeded, 3);

    for node in &legacy_nodes {
        assert!(store.is_admitted(node));
    }

    // Drop original store before reopening
    drop(store);

    // Reopen store to verify persistence
    let store2 = DurableAdmissionStore::open(&db_path).expect("reopen store");
    for node in &legacy_nodes {
        assert!(store2.is_admitted(node));
    }

    let records = store2.export_records().expect("export");
    assert_eq!(records.len(), 3);
    assert_eq!(
        records[0].admission_source,
        AdmissionSource::LegacyMigrated as i32
    );
    assert_eq!(records[0].initial_client_version, "0.0.1-alpha.5");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_spike_density_and_concurrent_sync_throughput() {
    let temp_dir =
        std::env::temp_dir().join(format!("androgrid-spike-density-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    let db_path = temp_dir.join("admissions.redb");

    let store = Arc::new(DurableAdmissionStore::open(&db_path).expect("open redb store"));

    // Pre-populate 1,000 workers
    let batch_nodes: Vec<String> = (0..1000).map(|i| format!("worker-{:05}", i)).collect();
    let seed_start = Instant::now();
    store
        .seed_migration_batch(&batch_nodes, "0.0.1-alpha.5", 1000)
        .unwrap();
    let seed_duration = seed_start.elapsed();
    println!("Seeded 1,000 legacy workers in {:?}", seed_duration);

    // Measure concurrent in-memory sync lookup latency while a burst of new admissions commits to disk
    let concurrent_sync_count = Arc::new(AtomicUsize::new(0));
    let stop_sync = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let store_clone = Arc::clone(&store);
    let count_clone = Arc::clone(&concurrent_sync_count);
    let stop_clone = Arc::clone(&stop_sync);

    let sync_thread = std::thread::spawn(move || {
        let mut rng_idx = 0;
        while !stop_clone.load(Ordering::Relaxed) {
            let key = format!("worker-{:05}", rng_idx % 1000);
            assert!(store_clone.is_admitted(&key));
            count_clone.fetch_add(1, Ordering::Relaxed);
            rng_idx += 1;
        }
    });

    // Simulate join burst of 50 new workers joining concurrently, writing to disk
    let burst_start = Instant::now();
    for i in 1000..1050 {
        let new_node = format!("new-worker-{:05}", i);
        store
            .commit_admission(
                &new_node,
                "0.0.1-alpha.6",
                2000,
                AdmissionSource::FreshOnboarded,
            )
            .unwrap();
    }
    let burst_duration = burst_start.elapsed();
    println!(
        "Committed join burst of 50 new workers to disk in {:?} (avg {:?} per durable commit)",
        burst_duration,
        burst_duration / 50
    );

    stop_sync.store(true, Ordering::Relaxed);
    sync_thread.join().unwrap();

    let total_syncs = concurrent_sync_count.load(Ordering::Relaxed);
    println!(
        "Concurrent in-memory worker sync queries completed during join burst: {}",
        total_syncs
    );
    assert!(
        total_syncs > 1000,
        "In-memory sync lookups must stay blisteringly fast during disk writes"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}
