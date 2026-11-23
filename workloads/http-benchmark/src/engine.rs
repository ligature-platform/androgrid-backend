//! Load generation benchmark execution engine.
//!
//! Orchestrates the benchmark loop, measures round-trip request timing,
//! enforces ADR-011 idempotency tokens on mutating requests with per-iteration sequence scoping,
//! aborts immediately on fatal sandbox security violations or unrecoverable error loops,
//! and accumulates metrics.
//!
//! Traces to: AG-SPEC-2026-V2, [REQ-OP-002], [REQ-OP-003], [INV-001], [INV-006], [NFR-PERF-001], ADR-011

use crate::config::BenchmarkConfig;
use crate::metrics::{BenchmarkReport, MetricsCollector};
use crate::transport::{HttpRequest, HttpTransport};
use std::time::Instant;

/// Maximum consecutive I/O errors allowed before breaking loop to prevent spin loops.
pub const MAX_CONSECUTIVE_ERRORS: u32 = 10;

/// Benchmark execution engine.
///
/// Traces to: [REQ-OP-002], [INV-006]
pub struct BenchmarkEngine<'a, T: HttpTransport> {
    config: &'a BenchmarkConfig,
    transport: &'a mut T,
}

impl<'a, T: HttpTransport> BenchmarkEngine<'a, T> {
    /// Creates a new benchmark engine instance with the given configuration and transport.
    pub fn new(config: &'a BenchmarkConfig, transport: &'a mut T) -> Self {
        Self { config, transport }
    }

    /// Builds the canonical HTTP request to dispatch during benchmark iterations.
    ///
    /// Applies ADR-011 required idempotency tokens for mutating methods (POST, PUT, DELETE, PATCH),
    /// scoping each iteration with `<task_id>:<iteration>`.
    ///
    /// Traces to: ADR-011 Section 7
    pub fn build_request(&self, iteration: u64) -> HttpRequest {
        let mut headers = String::with_capacity(256);
        headers.push_str("User-Agent: androgrid-benchmark/0.0.1 (WASI)\r\n");
        headers.push_str("Accept: */*\r\n");

        let method = self.config.method.to_uppercase();
        let is_mutating = matches!(method.as_str(), "POST" | "PUT" | "DELETE" | "PATCH");

        if is_mutating {
            headers.push_str(&format!(
                "Idempotency-Key: {}:{}\r\n",
                self.config.task_id, iteration
            ));
        }

        let has_explicit_content_type = self
            .config
            .custom_headers
            .as_deref()
            .map(|raw| {
                raw.lines().any(|line| {
                    line.trim()
                        .to_ascii_lowercase()
                        .starts_with("content-type:")
                })
            })
            .unwrap_or(false);

        let body_bytes = if let Some(ref body) = self.config.request_body {
            if is_mutating && !has_explicit_content_type {
                headers.push_str("Content-Type: application/json\r\n");
            }
            body.as_bytes().to_vec()
        } else {
            Vec::new()
        };

        if let Some(ref custom) = self.config.custom_headers {
            for line in custom.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    headers.push_str(trimmed);
                    headers.push_str("\r\n");
                }
            }
        }

        HttpRequest {
            url: self.config.target_url.clone(),
            method: self.config.method.clone(),
            headers,
            body: body_bytes,
        }
    }

    /// Executes the benchmark run to completion and returns the aggregated metrics.
    ///
    /// Traces to: [REQ-OP-002], [NFR-PERF-001]
    pub fn run(&mut self) -> BenchmarkReport {
        let mut collector = MetricsCollector::new();
        let start_time = Instant::now();
        let target_duration = std::time::Duration::from_secs(self.config.duration_secs);

        let mut total_requests: u64 = 0;
        let mut total_bytes_sent: u64 = 0;
        let mut consecutive_errors: u32 = 0;

        while start_time.elapsed() < target_duration {
            if let Some(limit) = self.config.max_requests {
                if total_requests >= limit {
                    break;
                }
            }

            let iteration = total_requests + 1;
            let request = self.build_request(iteration);
            let outbound_bytes_per_req =
                (request.url.len() + request.headers.len() + request.body.len()) as u64;

            total_requests += 1;
            total_bytes_sent += outbound_bytes_per_req;

            let req_start = Instant::now();
            let result = self.transport.execute(&request);

            match result {
                Ok(resp) => {
                    consecutive_errors = 0;
                    let latency = if resp.latency_micros > 0 {
                        resp.latency_micros
                    } else {
                        req_start.elapsed().as_micros() as u64
                    };
                    collector.record_response(resp.status_code, resp.bytes_written, latency);
                }
                Err(err) => {
                    consecutive_errors += 1;
                    let err_latency = req_start.elapsed().as_micros() as u64;
                    let is_fatal = err.is_fatal();
                    collector.record_error(&err, err_latency);

                    if is_fatal || consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        break;
                    }
                }
            }
        }

        let total_duration_micros = start_time.elapsed().as_micros();

        collector.finalize(
            self.config.task_id.clone(),
            self.config.target_url.clone(),
            self.config.method.clone(),
            total_duration_micros,
            total_bytes_sent,
        )
    }
}
