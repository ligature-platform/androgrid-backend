//! Unit tests for benchmark configuration parsing.
//!
//! Traces to: [REQ-OP-002], [INV-006]

use http_benchmark::config::{BenchmarkConfig, ConfigError};
use std::collections::HashMap;

#[test]
fn test_missing_target_url_fails() {
    let vars = HashMap::new();
    let err = BenchmarkConfig::from_map(&vars).unwrap_err();
    assert_eq!(err, ConfigError::MissingTargetUrl);
}

#[test]
fn test_invalid_target_url_scheme() {
    let mut vars = HashMap::new();
    vars.insert("TARGET_URL".to_string(), "ftp://example.com".to_string());
    let err = BenchmarkConfig::from_map(&vars).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidTargetUrlScheme(_)));
}

#[test]
fn test_default_configuration_values() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "https://httpbin.org/get".to_string(),
    );

    let cfg = BenchmarkConfig::from_map(&vars).expect("Valid configuration");
    assert_eq!(cfg.target_url, "https://httpbin.org/get");
    assert_eq!(cfg.method, "GET");
    assert_eq!(cfg.duration_secs, BenchmarkConfig::DEFAULT_DURATION_SECS);
    assert_eq!(cfg.max_requests, None);
    assert_eq!(cfg.request_body, None);
    assert_eq!(cfg.custom_headers, None);
    assert_eq!(cfg.buffer_size, BenchmarkConfig::DEFAULT_BUFFER_SIZE);
    assert_eq!(cfg.task_id, "task_local_bench");
}

#[test]
fn test_custom_parameters_parsing() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "http://api.staging.internal/post".to_string(),
    );
    vars.insert("METHOD".to_string(), "post".to_string());
    vars.insert("DURATION_SECS".to_string(), "30".to_string());
    vars.insert("MAX_REQUESTS".to_string(), "500".to_string());
    vars.insert("BODY".to_string(), "{\"test\": true}".to_string());
    vars.insert("HEADERS".to_string(), "X-Custom: 123".to_string());
    vars.insert("TASK_ID".to_string(), "task_777".to_string());
    vars.insert("BUFFER_SIZE".to_string(), "32768".to_string());

    let cfg = BenchmarkConfig::from_map(&vars).expect("Valid configuration");
    assert_eq!(cfg.target_url, "http://api.staging.internal/post");
    assert_eq!(cfg.method, "POST");
    assert_eq!(cfg.duration_secs, 30);
    assert_eq!(cfg.max_requests, Some(500));
    assert_eq!(cfg.request_body, Some("{\"test\": true}".to_string()));
    assert_eq!(cfg.custom_headers, Some("X-Custom: 123".to_string()));
    assert_eq!(cfg.task_id, "task_777");
    assert_eq!(cfg.buffer_size, 32768);
}

#[test]
fn test_invalid_method_rejected() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "https://httpbin.org/get".to_string(),
    );
    vars.insert("METHOD".to_string(), "INVALID_VERB".to_string());
    let err = BenchmarkConfig::from_map(&vars).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidMethod(_)));
}

#[test]
fn test_invalid_task_id_control_characters() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "https://httpbin.org/get".to_string(),
    );
    vars.insert(
        "TASK_ID".to_string(),
        "task_foo\r\nInjected: evil".to_string(),
    );
    let err = BenchmarkConfig::from_map(&vars).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidTaskId(_)));
}

#[test]
fn test_invalid_headers_control_characters_and_missing_colon() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "https://httpbin.org/get".to_string(),
    );

    // Missing colon
    vars.insert(
        "HEADERS".to_string(),
        "InvalidHeaderWithoutColon".to_string(),
    );
    let err = BenchmarkConfig::from_map(&vars).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidHeaders(_)));

    // Control character
    vars.insert("HEADERS".to_string(), "X-Test: value\x07bell".to_string());
    let err = BenchmarkConfig::from_map(&vars).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidHeaders(_)));
}

#[test]
fn test_buffer_size_bounds_validation() {
    let mut vars = HashMap::new();
    vars.insert(
        "TARGET_URL".to_string(),
        "https://httpbin.org/get".to_string(),
    );

    // Below 1 KB
    vars.insert("BUFFER_SIZE".to_string(), "512".to_string());
    assert!(matches!(
        BenchmarkConfig::from_map(&vars).unwrap_err(),
        ConfigError::InvalidBufferSize(_)
    ));

    // Above 4 MB
    vars.insert("BUFFER_SIZE".to_string(), "5000000".to_string());
    assert!(matches!(
        BenchmarkConfig::from_map(&vars).unwrap_err(),
        ConfigError::InvalidBufferSize(_)
    ));

    // Valid buffer size
    vars.insert("BUFFER_SIZE".to_string(), "65536".to_string());
    let cfg = BenchmarkConfig::from_map(&vars).unwrap();
    assert_eq!(cfg.buffer_size, 65536);
}
