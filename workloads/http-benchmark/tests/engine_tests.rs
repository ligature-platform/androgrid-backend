//! Unit tests for benchmark execution engine using mock transport.
//!
//! Traces to: [REQ-OP-002], [REQ-OP-003], [INV-001], [INV-006], ADR-011

use http_benchmark::config::BenchmarkConfig;
use http_benchmark::engine::BenchmarkEngine;
use http_benchmark::transport::{MockHttpTransport, TransportError};
use std::collections::HashMap;

#[test]
fn test_engine_executes_max_requests() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "https://httpbin.org/get".to_string(),
    );
    vars.insert("MAX_REQUESTS".to_string(), "5".to_string());
    vars.insert("DURATION_SECS".to_string(), "60".to_string());

    let config = BenchmarkConfig::from_map(&vars).unwrap();

    let mut transport = MockHttpTransport::new();
    transport.set_default_success(200, b"{\"status\": \"ok\"}", 5_000);

    let mut engine = BenchmarkEngine::new(&config, &mut transport);
    let report = engine.run();

    assert_eq!(report.total_requests, 5);
    assert_eq!(report.successful_requests, 5);
    assert_eq!(transport.recorded_requests.len(), 5);
    assert_eq!(report.status_codes.get("200"), Some(&5));
}

#[test]
fn test_engine_idempotency_key_injection_for_mutating_verbs() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "https://httpbin.org/post".to_string(),
    );
    vars.insert("METHOD".to_string(), "POST".to_string());
    vars.insert("TASK_ID".to_string(), "task_alpha_42".to_string());
    vars.insert("BODY".to_string(), "{\"load\": 1}".to_string());
    vars.insert("MAX_REQUESTS".to_string(), "1".to_string());

    let config = BenchmarkConfig::from_map(&vars).unwrap();

    let mut transport = MockHttpTransport::new();
    let engine = BenchmarkEngine::new(&config, &mut transport);
    let req = engine.build_request();

    assert_eq!(req.method, "POST");
    assert!(req.headers.contains("Idempotency-Key: task_alpha_42"));
    assert!(req.headers.contains("Content-Type: application/json"));
    assert_eq!(req.body, b"{\"load\": 1}");
}

#[test]
fn test_engine_get_does_not_inject_idempotency_key() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "https://httpbin.org/get".to_string(),
    );
    vars.insert("METHOD".to_string(), "GET".to_string());
    vars.insert("TASK_ID".to_string(), "task_alpha_42".to_string());

    let config = BenchmarkConfig::from_map(&vars).unwrap();

    let mut transport = MockHttpTransport::new();
    let engine = BenchmarkEngine::new(&config, &mut transport);
    let req = engine.build_request();

    assert_eq!(req.method, "GET");
    assert!(!req.headers.contains("Idempotency-Key:"));
    assert!(req.body.is_empty());
}

#[test]
fn test_engine_handles_transport_errors_cleanly() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "https://httpbin.org/get".to_string(),
    );
    vars.insert("MAX_REQUESTS".to_string(), "4".to_string());

    let config = BenchmarkConfig::from_map(&vars).unwrap();

    let mut transport = MockHttpTransport::new();
    transport.queue_response(200, b"OK", 1000);
    transport.queue_error(TransportError::SecurityViolation);
    transport.queue_error(TransportError::BufferTooSmall);
    transport.queue_error(TransportError::QuotaExceeded);

    let mut engine = BenchmarkEngine::new(&config, &mut transport);
    let report = engine.run();

    assert_eq!(report.total_requests, 4);
    assert_eq!(report.successful_requests, 1);
    assert_eq!(report.errors.security_violation, 1);
    assert_eq!(report.errors.buffer_too_small, 1);
    assert_eq!(report.errors.quota_exceeded, 1);
}
