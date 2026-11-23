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
    transport.set_default_success(200, 100, 5_000);

    let mut engine = BenchmarkEngine::new(&config, &mut transport);
    let report = engine.run();

    assert_eq!(report.total_requests, 5);
    assert_eq!(report.successful_requests, 5);
    assert_eq!(transport.recorded_requests.len(), 5);
    assert_eq!(report.status_codes.get("200"), Some(&5));
}

#[test]
fn test_engine_idempotency_key_injection_for_mutating_verbs_with_sequence() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "https://httpbin.org/post".to_string(),
    );
    vars.insert("METHOD".to_string(), "POST".to_string());
    vars.insert("TASK_ID".to_string(), "task_alpha_42".to_string());
    vars.insert("BODY".to_string(), "{\"load\": 1}".to_string());
    vars.insert("MAX_REQUESTS".to_string(), "2".to_string());

    let config = BenchmarkConfig::from_map(&vars).unwrap();

    let mut transport = MockHttpTransport::new();
    transport.set_default_success(201, 50, 1000);

    let mut engine = BenchmarkEngine::new(&config, &mut transport);
    let report = engine.run();

    assert_eq!(report.total_requests, 2);
    assert_eq!(transport.recorded_requests.len(), 2);

    let req1 = &transport.recorded_requests[0];
    assert_eq!(req1.method, "POST");
    assert!(req1.headers.contains("Idempotency-Key: task_alpha_42:1"));
    assert!(req1.headers.contains("Content-Type: application/json"));
    assert_eq!(req1.body, b"{\"load\": 1}");

    let req2 = &transport.recorded_requests[1];
    assert!(req2.headers.contains("Idempotency-Key: task_alpha_42:2"));
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
    let req = engine.build_request(1);

    assert_eq!(req.method, "GET");
    assert!(!req.headers.contains("Idempotency-Key:"));
    assert!(req.body.is_empty());
}

#[test]
fn test_engine_aborts_immediately_on_fatal_quota_or_security_error() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "https://httpbin.org/get".to_string(),
    );
    vars.insert("MAX_REQUESTS".to_string(), "100".to_string());

    let config = BenchmarkConfig::from_map(&vars).unwrap();

    let mut transport = MockHttpTransport::new();
    transport.queue_response(200, 10, 1000);
    transport.queue_error(TransportError::QuotaExceeded);
    // Even though 100 requests were configured, it must break immediately on QuotaExceeded
    transport.queue_response(200, 10, 1000);

    let mut engine = BenchmarkEngine::new(&config, &mut transport);
    let report = engine.run();

    assert_eq!(report.total_requests, 2);
    assert_eq!(report.successful_requests, 1);
    assert_eq!(report.errors.quota_exceeded, 1);
}

#[test]
fn test_engine_aborts_on_ten_consecutive_io_errors() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "https://httpbin.org/get".to_string(),
    );
    vars.insert("MAX_REQUESTS".to_string(), "100".to_string());

    let config = BenchmarkConfig::from_map(&vars).unwrap();

    let mut transport = MockHttpTransport::new();
    for _ in 0..20 {
        transport.queue_error(TransportError::IoFailure);
    }

    let mut engine = BenchmarkEngine::new(&config, &mut transport);
    let report = engine.run();

    // Must break at 10 consecutive failures, not execute all 100
    assert_eq!(report.total_requests, 10);
    assert_eq!(report.errors.io_failure, 10);
}
