//! Statistical metrics aggregation and output formatting.
//!
//! Tracks nanosecond-precision request latencies, calculates percentiles
//! (min, p50, p90, p95, p99, max), aggregates HTTP status code distributions,
//! and renders human-readable tabular summaries and machine-readable JSON payloads.
//!
//! Traces to: AG-SPEC-2026-V2, [REQ-OP-002], [NFR-PERF-001]

use crate::transport::TransportError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Latency percentiles computed in milliseconds.
///
/// Traces to: [NFR-PERF-001]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LatencyPercentiles {
    /// Minimum recorded latency in milliseconds.
    pub min_ms: f64,
    /// 50th percentile (median) latency in milliseconds.
    pub p50_ms: f64,
    /// 90th percentile latency in milliseconds.
    pub p90_ms: f64,
    /// 95th percentile latency in milliseconds.
    pub p95_ms: f64,
    /// 99th percentile latency in milliseconds.
    pub p99_ms: f64,
    /// Maximum recorded latency in milliseconds.
    pub max_ms: f64,
    /// Mean average latency in milliseconds.
    pub mean_ms: f64,
}

impl Default for LatencyPercentiles {
    fn default() -> Self {
        Self {
            min_ms: 0.0,
            p50_ms: 0.0,
            p90_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            max_ms: 0.0,
            mean_ms: 0.0,
        }
    }
}

/// Breakdown of transport and sandbox security error encounters.
///
/// Traces to: [INV-001], [INV-006], ADR-011
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorCounts {
    /// Remote I/O or DNS connection failures (-1).
    pub io_failure: u64,
    /// Egress security policy or SSRF rejections (-403).
    pub security_violation: u64,
    /// Response buffer capacity overflows (-413).
    pub buffer_too_small: u64,
    /// Cumulative byte transfer quota violations (-429).
    pub quota_exceeded: u64,
    /// Other unmapped negative error codes.
    pub other_errors: u64,
}

impl ErrorCounts {
    /// Returns total number of encountered errors.
    pub fn total(&self) -> u64 {
        self.io_failure
            + self.security_violation
            + self.buffer_too_small
            + self.quota_exceeded
            + self.other_errors
    }
}

/// Comprehensive benchmark execution report.
///
/// Traces to: [REQ-OP-002], [NFR-PERF-001]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkReport {
    /// Orchestrator task identifier.
    pub task_id: String,
    /// Target destination URL.
    pub target_url: String,
    /// HTTP method verb.
    pub method: String,
    /// Simulated concurrency worker count.
    pub concurrency: usize,
    /// Total execution duration in seconds.
    pub duration_secs: f64,
    /// Total requests dispatched.
    pub total_requests: u64,
    /// Total successful HTTP requests (2xx status codes).
    pub successful_requests: u64,
    /// Rate of completed requests per second.
    pub requests_per_sec: f64,
    /// Total bytes transferred (sent and received).
    pub total_bytes_transferred: u64,
    /// Rate of throughput in bytes per second.
    pub bytes_per_sec: f64,
    /// Distribution of observed HTTP status codes.
    pub status_codes: BTreeMap<String, u64>,
    /// Summary of network and sandbox error counts.
    pub errors: ErrorCounts,
    /// Latency percentile distribution in milliseconds.
    pub latency_percentiles: LatencyPercentiles,
}

impl BenchmarkReport {
    /// Formats a human-readable tabular summary report.
    ///
    /// Traces to: [REQ-OP-002]
    pub fn format_tabular(&self) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str("================================================================================\n");
        out.push_str("                     AndroGrid Distributed HTTP Benchmark                       \n");
        out.push_str("================================================================================\n");
        out.push_str(&format!("Task ID:             {}\n", self.task_id));
        out.push_str(&format!("Target URL:          {}\n", self.target_url));
        out.push_str(&format!("HTTP Method:         {}\n", self.method));
        out.push_str(&format!("Concurrency:         {}\n", self.concurrency));
        out.push_str(&format!("Duration:            {:.2}s\n", self.duration_secs));
        out.push_str(&format!("Total Requests:      {}\n", self.total_requests));
        out.push_str(&format!("Successful (2xx):    {}\n", self.successful_requests));
        out.push_str(&format!("Total Errors:        {}\n", self.errors.total()));
        out.push_str(&format!("Total Bytes:         {} bytes\n", self.total_bytes_transferred));
        out.push_str(&format!(
            "Throughput:          {:.2} req/sec ({:.2} KB/sec)\n",
            self.requests_per_sec,
            self.bytes_per_sec / 1024.0
        ));

        if !self.status_codes.is_empty() {
            out.push_str("\nHTTP Status Distribution:\n");
            for (code, count) in &self.status_codes {
                out.push_str(&format!("  HTTP {code}:         {count}\n"));
            }
        }

        if self.errors.total() > 0 {
            out.push_str("\nError Breakdown:\n");
            if self.errors.io_failure > 0 {
                out.push_str(&format!("  IO Failures (-1):            {}\n", self.errors.io_failure));
            }
            if self.errors.security_violation > 0 {
                out.push_str(&format!("  Security Violations (-403):  {}\n", self.errors.security_violation));
            }
            if self.errors.buffer_too_small > 0 {
                out.push_str(&format!("  Buffer Too Small (-413):     {}\n", self.errors.buffer_too_small));
            }
            if self.errors.quota_exceeded > 0 {
                out.push_str(&format!("  Quota Exceeded (-429):       {}\n", self.errors.quota_exceeded));
            }
            if self.errors.other_errors > 0 {
                out.push_str(&format!("  Other Errors:                {}\n", self.errors.other_errors));
            }
        }

        out.push_str("\nLatency Distribution (ms):\n");
        out.push_str(&format!("  Min:               {:.2} ms\n", self.latency_percentiles.min_ms));
        out.push_str(&format!("  p50:               {:.2} ms\n", self.latency_percentiles.p50_ms));
        out.push_str(&format!("  p90:               {:.2} ms\n", self.latency_percentiles.p90_ms));
        out.push_str(&format!("  p95:               {:.2} ms\n", self.latency_percentiles.p95_ms));
        out.push_str(&format!("  p99:               {:.2} ms\n", self.latency_percentiles.p99_ms));
        out.push_str(&format!("  Max:               {:.2} ms\n", self.latency_percentiles.max_ms));
        out.push_str(&format!("  Mean:              {:.2} ms\n", self.latency_percentiles.mean_ms));
        out.push_str("================================================================================\n");
        out
    }

    /// Serializes report to formatted JSON string.
    ///
    /// Traces to: [REQ-OP-002]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Dynamic statistical metrics accumulator.
///
/// Traces to: [NFR-PERF-001]
#[derive(Debug, Default)]
pub struct MetricsCollector {
    total_requests: u64,
    successful_requests: u64,
    status_codes: BTreeMap<String, u64>,
    errors: ErrorCounts,
    latencies_micros: Vec<u64>,
    total_bytes_received: u64,
}

impl MetricsCollector {
    /// Initializes a new metrics collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a completed HTTP response.
    pub fn record_response(&mut self, status_code: u16, bytes_received: usize, latency_micros: u64) {
        self.total_requests += 1;
        self.latencies_micros.push(latency_micros);
        self.total_bytes_received += bytes_received as u64;

        if (200..=299).contains(&status_code) {
            self.successful_requests += 1;
        }

        let code_str = status_code.to_string();
        *self.status_codes.entry(code_str).or_insert(0) += 1;
    }

    /// Records a transport or security error.
    pub fn record_error(&mut self, error: &TransportError, latency_micros: u64) {
        self.total_requests += 1;
        self.latencies_micros.push(latency_micros);

        match error {
            TransportError::IoFailure => self.errors.io_failure += 1,
            TransportError::SecurityViolation => self.errors.security_violation += 1,
            TransportError::BufferTooSmall => self.errors.buffer_too_small += 1,
            TransportError::QuotaExceeded => self.errors.quota_exceeded += 1,
            TransportError::Unknown(_) => self.errors.other_errors += 1,
        }
    }

    /// Computes percentiles from sorted latencies in milliseconds.
    fn calculate_percentiles(mut latencies: Vec<u64>) -> LatencyPercentiles {
        if latencies.is_empty() {
            return LatencyPercentiles::default();
        }

        latencies.sort_unstable();
        let len = latencies.len();
        let sum: u64 = latencies.iter().sum();
        let mean_ms = (sum as f64 / len as f64) / 1000.0;
        let min_ms = latencies[0] as f64 / 1000.0;
        let max_ms = latencies[len - 1] as f64 / 1000.0;

        let calc_pct = |pct: f64| -> f64 {
            if len == 1 {
                return latencies[0] as f64 / 1000.0;
            }
            let rank = pct * (len - 1) as f64;
            let lower = rank.floor() as usize;
            let upper = rank.ceil() as usize;
            if lower == upper {
                latencies[lower] as f64 / 1000.0
            } else {
                let weight = rank - lower as f64;
                let val = (latencies[lower] as f64 * (1.0 - weight))
                    + (latencies[upper] as f64 * weight);
                val / 1000.0
            }
        };

        LatencyPercentiles {
            min_ms,
            p50_ms: calc_pct(0.50),
            p90_ms: calc_pct(0.90),
            p95_ms: calc_pct(0.95),
            p99_ms: calc_pct(0.99),
            max_ms,
            mean_ms,
        }
    }

    /// Consolidates recorded metrics into a final immutable benchmark report.
    pub fn finalize(
        self,
        task_id: String,
        target_url: String,
        method: String,
        concurrency: usize,
        total_duration_micros: u128,
        total_bytes_sent: u64,
    ) -> BenchmarkReport {
        let duration_secs = (total_duration_micros as f64 / 1_000_000.0).max(0.000001);
        let total_bytes_transferred = total_bytes_sent + self.total_bytes_received;
        let requests_per_sec = self.total_requests as f64 / duration_secs;
        let bytes_per_sec = total_bytes_transferred as f64 / duration_secs;

        let latency_percentiles = Self::calculate_percentiles(self.latencies_micros);

        BenchmarkReport {
            task_id,
            target_url,
            method,
            concurrency,
            duration_secs,
            total_requests: self.total_requests,
            successful_requests: self.successful_requests,
            requests_per_sec,
            total_bytes_transferred,
            bytes_per_sec,
            status_codes: self.status_codes,
            errors: self.errors,
            latency_percentiles,
        }
    }
}
