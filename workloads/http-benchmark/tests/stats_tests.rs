//! Unit tests for statistical percentiles, distributions, and metrics reporting.
//!
//! Traces to: [NFR-PERF-001], [REQ-OP-002]

use http_benchmark::metrics::MetricsCollector;
use http_benchmark::transport::TransportError;

#[test]
fn test_metrics_collector_empty() {
    let collector = MetricsCollector::new();
    let report = collector.finalize(
        "task_1".to_string(),
        "https://example.com/api".to_string(),
        "GET".to_string(),
        4,
        1_000_000,
        0,
    );

    assert_eq!(report.total_requests, 0);
    assert_eq!(report.successful_requests, 0);
    assert_eq!(report.requests_per_sec, 0.0);
    assert_eq!(report.latency_percentiles.min_ms, 0.0);
    assert_eq!(report.latency_percentiles.max_ms, 0.0);
}

#[test]
fn test_metrics_collector_percentiles_calculation() {
    let mut collector = MetricsCollector::new();

    // Insert 100 samples from 1ms (1000us) to 100ms (100000us)
    for i in 1..=100 {
        collector.record_response(200, 100, i * 1000);
    }

    let report = collector.finalize(
        "task_100".to_string(),
        "https://example.com/api".to_string(),
        "GET".to_string(),
        4,
        1_000_000, // 1 second
        5000,
    );

    assert_eq!(report.total_requests, 100);
    assert_eq!(report.successful_requests, 100);
    assert_eq!(report.status_codes.get("200"), Some(&100));

    let p = &report.latency_percentiles;
    assert!((p.min_ms - 1.0).abs() < 0.01, "min_ms was {}", p.min_ms);
    assert!((p.p50_ms - 50.5).abs() < 0.5, "p50_ms was {}", p.p50_ms);
    assert!((p.p90_ms - 90.1).abs() < 0.5, "p90_ms was {}", p.p90_ms);
    assert!((p.p95_ms - 95.05).abs() < 0.5, "p95_ms was {}", p.p95_ms);
    assert!((p.p99_ms - 99.01).abs() < 0.5, "p99_ms was {}", p.p99_ms);
    assert!((p.max_ms - 100.0).abs() < 0.01, "max_ms was {}", p.max_ms);
    assert!((p.mean_ms - 50.5).abs() < 0.5, "mean_ms was {}", p.mean_ms);

    // Throughput: 100 requests in 1 sec = 100 req/sec
    assert!((report.requests_per_sec - 100.0).abs() < 1.0);
    // Bytes: 5000 sent + (100 * 100) received = 15000 bytes
    assert_eq!(report.total_bytes_transferred, 15000);
}

#[test]
fn test_metrics_collector_error_breakdown() {
    let mut collector = MetricsCollector::new();

    collector.record_response(200, 200, 10_000);
    collector.record_response(404, 50, 12_000);
    collector.record_response(500, 120, 15_000);

    collector.record_error(&TransportError::IoFailure, 20_000);
    collector.record_error(&TransportError::SecurityViolation, 5_000);
    collector.record_error(&TransportError::BufferTooSmall, 8_000);
    collector.record_error(&TransportError::QuotaExceeded, 10_000);
    collector.record_error(&TransportError::Unknown(-999), 11_000);

    let report = collector.finalize(
        "task_errors".to_string(),
        "https://example.com/api".to_string(),
        "GET".to_string(),
        2,
        2_000_000,
        1000,
    );

    assert_eq!(report.total_requests, 8);
    assert_eq!(report.successful_requests, 1);
    assert_eq!(report.status_codes.get("200"), Some(&1));
    assert_eq!(report.status_codes.get("404"), Some(&1));
    assert_eq!(report.status_codes.get("500"), Some(&1));

    assert_eq!(report.errors.io_failure, 1);
    assert_eq!(report.errors.security_violation, 1);
    assert_eq!(report.errors.buffer_too_small, 1);
    assert_eq!(report.errors.quota_exceeded, 1);
    assert_eq!(report.errors.other_errors, 1);
    assert_eq!(report.errors.total(), 5);
}

#[test]
fn test_json_and_tabular_formatting() {
    let mut collector = MetricsCollector::new();
    collector.record_response(200, 512, 15_000);

    let report = collector.finalize(
        "task_fmt".to_string(),
        "https://example.com/api".to_string(),
        "GET".to_string(),
        4,
        1_000_000,
        256,
    );

    let tabular = report.format_tabular();
    assert!(tabular.contains("AndroGrid Distributed HTTP Benchmark"));
    assert!(tabular.contains("Task ID:             task_fmt"));
    assert!(tabular.contains("Target URL:          https://example.com/api"));
    assert!(tabular.contains("Successful (2xx):    1"));

    let json = report.to_json().expect("Serialization succeeds");
    assert!(json.contains("\"task_id\": \"task_fmt\""));
    assert!(json.contains("\"target_url\": \"https://example.com/api\""));
    assert!(json.contains("\"total_requests\": 1"));
    assert!(json.contains("\"latency_percentiles\": {"));

    // Verify roundtrip deserialization
    let deserialized: http_benchmark::BenchmarkReport =
        serde_json::from_str(&json).expect("Deserialization succeeds");
    assert_eq!(deserialized.task_id, report.task_id);
    assert_eq!(deserialized.total_requests, report.total_requests);
}
