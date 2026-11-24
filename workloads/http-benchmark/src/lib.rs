//! Canonical WebAssembly (WASI Preview 1) Distributed HTTP/HTTPS Benchmark Workload
//!
//! Provides distributed mobile edge load-testing capability using sandboxed
//! outbound WASI egress (`androgrid_net:http_fetch`).
//!
//! Traces to: AG-SPEC-2026-V2, [REQ-OP-002], [REQ-OP-003], [INV-001], [INV-006], [NFR-PERF-001], ADR-011

pub mod config;
pub mod engine;
pub mod metrics;
pub mod transport;

pub use config::{BenchmarkConfig, ConfigError};
pub use engine::BenchmarkEngine;
pub use metrics::{BenchmarkReport, ErrorCounts, LatencyPercentiles, MetricsCollector};
pub use transport::{
    HttpRequest, HttpResponse, HttpTransport, MockHttpTransport, TransportError, WasiHttpTransport,
};
