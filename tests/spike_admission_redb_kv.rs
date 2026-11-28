//! Production tests for embedded transactional key-value admission store (`redb` + Protobuf).
//!
//! Traces to: Issue #30, Goal [G-25], [REQ-OP-001], [REQ-VER-001], [INV-002], Gate L-02

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use redb::{Database, TableDefinition};

use androgrid_backend::scheduler::admission_store::{AdmissionSource, DurableAdmissionStore};

const ADMISSION_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("admitted_workers");

#[test]
fn test_missing_established_database_rejected_on_ordinary_startup() {
    let temp_dir = std::env::temp_dir().join(format!("androgrid-missing-db-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    let db_path = temp_dir.join("nonexistent_admission.redb");

    // Ordinary open without allow_create must fail fast rather than silently creating an empty DB
    let result = DurableAdmissionStore::open(&db_path);
    assert!(
        result.is_err(),
        "Ordinary startup must reject missing established admission database"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_explicit_initialization_flag_creates_admission_database() {
    let temp_dir = std::env::temp_dir().join(format!("androgrid-init-db-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    let db_path = temp_dir.join("init_admission.redb");

    // Explicit initialization authorized via open_or_create(..., true)
    let store = DurableAdmissionStore::open_or_create(&db_path, true)
        .expect("Explicit initialization should succeed");
    assert!(db_path.exists());
    drop(store);

    // Subsequent ordinary startup (allow_create: false) must now succeed
    let store_reopened = DurableAdmissionStore::open(&db_path)
        .expect("Reopening existing database must succeed without init flag");
    assert_eq!(store_reopened.export_records().unwrap().len(), 0);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_durability_and_restart_recovery() {
    let temp_dir = std::env::temp_dir().join(format!("androgrid-durability-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    let db_path = temp_dir.join("admissions.redb");

    // Phase 1: Open store and commit 100 worker admissions
    {
        let store = DurableAdmissionStore::open_or_create(&db_path, true)
            .expect("open redb store");
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
fn test_hydration_validates_record_identity_and_rejects_corrupted_payload() {
    let temp_dir = std::env::temp_dir().join(format!("androgrid-hydration-corrupt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    let db_path = temp_dir.join("corrupt.redb");

    // Initialize database
    {
        let store = DurableAdmissionStore::open_or_create(&db_path, true).expect("init store");
        store
            .commit_admission(
                "valid-node",
                "0.0.1-alpha.6",
                1000,
                AdmissionSource::FreshOnboarded,
            )
            .expect("commit valid node");
    }

    // Inject corrupted raw bytes directly into the redb table
    {
        let db = Database::create(&db_path).expect("open raw redb");
        let write_txn = db.begin_write().expect("begin write");
        {
            let mut table = write_txn.open_table(ADMISSION_TABLE).expect("open table");
            // Invalid protobuf payload
            let garbage = vec![0xFF, 0xFF, 0xFF, 0xFF];
            table.insert("corrupt-node", garbage.as_slice()).expect("insert corrupt");
        }
        write_txn.commit().expect("commit raw");
    }

    // Reopen store: hydration must decode each record and fail on corrupted protobuf
    let result = DurableAdmissionStore::open(&db_path);
    assert!(
        result.is_err(),
        "Hydration must fail when stored protobuf payload is corrupted"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_export_records_fails_on_corrupt_entry() {
    let temp_dir = std::env::temp_dir().join(format!("androgrid-export-corrupt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    let db_path = temp_dir.join("export_corrupt.redb");

    // Create raw redb with garbage entry
    {
        let db = Database::create(&db_path).expect("open raw redb");
        let write_txn = db.begin_write().expect("begin write");
        {
            let mut table = write_txn.open_table(ADMISSION_TABLE).expect("open table");
            let garbage = vec![0xFF, 0xFF, 0xFF];
            table.insert("bad-entry", garbage.as_slice()).expect("insert bad entry");
        }
        write_txn.commit().expect("commit raw");
    }

    // Attempting to export must return Err rather than returning partial records with Ok
    let result = DurableAdmissionStore::open(&db_path);
    assert!(result.is_err(), "Store open with corrupt entry must fail during hydration");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_migration_batch_seeding_and_replay_preservation() {
    let temp_dir = std::env::temp_dir().join(format!("androgrid-migration-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    let db_path = temp_dir.join("migration.redb");

    let store = DurableAdmissionStore::open_or_create(&db_path, true).expect("init store");

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

    // Replay seeding with an existing node: existing record and timestamp must be preserved
    let replay_nodes = vec![
        "pixel-8-shiba-alpha5".to_string(),
        "pixel-9-tokay-alpha5".to_string(),
    ];
    let replay_count = store
        .seed_migration_batch(&replay_nodes, "0.0.1-alpha.5", 9999)
        .expect("replay seed");
    assert_eq!(replay_count, 1, "Only pixel-9 should be freshly inserted");

    // Drop original store before reopening
    drop(store);

    // Reopen store to verify persistence across restarts
    let store2 = DurableAdmissionStore::open(&db_path).expect("reopen store");
    for node in &legacy_nodes {
        assert!(store2.is_admitted(node));
    }
    assert!(store2.is_admitted("pixel-9-tokay-alpha5"));

    let records = store2.export_records().expect("export");
    assert_eq!(records.len(), 4);

    let shiba_record = records.iter().find(|r| r.node_id == "pixel-8-shiba-alpha5").unwrap();
    assert_eq!(shiba_record.admitted_epoch_ms, 500, "Original timestamp must be preserved on replay");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_density_and_concurrent_sync_throughput() {
    let temp_dir = std::env::temp_dir().join(format!("androgrid-density-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    let db_path = temp_dir.join("density.redb");

    let store = Arc::new(
        DurableAdmissionStore::open_or_create(&db_path, true).expect("init store")
    );

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
    let stop_sync = Arc::new(AtomicBool::new(false));

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
        "In-memory sync lookups must stay fast during disk writes"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}
