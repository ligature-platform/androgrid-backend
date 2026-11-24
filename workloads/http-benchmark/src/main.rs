//! Main entry point for the WebAssembly (WASI Preview 1) HTTP benchmark workload.
//!
//! Executes inside the in-memory Chicory WASI sandbox on Android mobile worker nodes,
//! reads environment configuration, conducts load testing via `androgrid_net:http_fetch`,
//! and emits human-readable and structured JSON metrics to standard output.
//!
//! Traces to: AG-SPEC-2026-V2, [REQ-OP-002], [REQ-OP-003], [INV-001], [INV-006], [NFR-PERF-001], ADR-011

use http_benchmark::{BenchmarkConfig, BenchmarkEngine, WasiHttpTransport};

fn main() {
    let config = match BenchmarkConfig::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Configuration Error: {err}");
            std::process::exit(1);
        }
    };

    let mut transport = WasiHttpTransport::new(config.buffer_size);
    let mut engine = BenchmarkEngine::new(&config, &mut transport);

    let report = engine.run();

    // Emit human-readable summary
    println!("{}", report.format_tabular());

    // Emit machine-readable JSON payload
    match report.to_json() {
        Ok(json_str) => {
            println!("JSON Report:\n{json_str}");
        }
        Err(e) => {
            eprintln!("Failed to serialize JSON report: {e}");
            std::process::exit(2);
        }
    }
}
