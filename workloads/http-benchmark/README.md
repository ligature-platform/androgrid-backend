# Distributed HTTP/HTTPS Load Testing Benchmark Workload

## 1. Executive Summary & Overview
This directory contains the canonical WebAssembly (WASI Preview 1) distributed HTTP/HTTPS load testing benchmark workload for AndroGrid. It provides an immediate, tangible demonstration that proves the platform's core capability: executing sandboxed computations across mobile devices with real network I/O.

Similar in function to `hey` or `wrk`, this workload runs in the Chicory WASI sandbox on mobile workers, issues concurrent HTTP GET/POST/PUT/DELETE requests to target URLs permitted by the orchestrator egress allowlist, computes nanosecond-precision latency percentiles (min, p50, p90, p95, p99, max), and emits structured tabular and JSON reports to standard output.

Traces to: AG-SPEC-2026-V2, [REQ-OP-002], [REQ-OP-003], [INV-001], [INV-006], [NFR-PERF-001], ADR-011

---

## 2. Capabilities & Architectural Invariants

| Attribute | Specification | Traceability |
| :--- | :--- | :--- |
| **Target Runtime** | Chicory WASI Preview 1 (In-Memory Interpreter) | [INV-006], [REQ-VER-003] |
| **Compilation Target** | `wasm32-wasip1` | [REQ-OP-002] |
| **Network Egress** | `androgrid_net:http_fetch` host module | [INV-001], ADR-011 |
| **Memory Bound** | < 16 MB peak linear memory usage | [NFR-PERF-001] |
| **Binary Size** | < 500 KB release bytecode payload | [NFR-PERF-001] |
| **Idempotency** | Injects `Idempotency-Key: <task_id>` on mutating methods | ADR-011 |

---

## 3. Configuration Environment Variables

The workload reads runtime parameters via standard environment variables:

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `TARGET_URL` | Yes | None | Destination endpoint URL (e.g. `https://httpbin.org/get`). Must use `http://` or `https://`. |
| `METHOD` | No | `GET` | HTTP verb: `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `PATCH`. |
| `CONCURRENCY` | No | `4` | Number of simulated concurrent workers (1 to 1024). |
| `DURATION_SECS` | No | `10` | Total duration of the load generation window in seconds. |
| `MAX_REQUESTS` | No | Unlimited | Optional maximum number of requests to execute before stopping. |
| `REQUEST_BODY` | No | Empty | Request body string sent with mutating methods (`POST`, `PUT`, `PATCH`). |
| `REQUEST_HEADERS` | No | Empty | Newline-delimited list of custom headers (`Header-Name: Value`). |
| `BUFFER_SIZE` | No | `65536` | Maximum response buffer capacity (64 KB default). |
| `ANDROGRID_TASK_ID` | No | `task_local_bench` | Task identifier used to populate `Idempotency-Key` headers. |

---

## 4. Compilation

Ensure the `wasm32-wasip1` target is installed:
```bash
rustup target add wasm32-wasip1
```

Compile the optimized release WebAssembly binary:
```bash
cargo build --target wasm32-wasip1 --release
```

The compiled binary is placed at:
`target/wasm32-wasip1/release/http_benchmark.wasm`

To run the hermetic unit tests locally:
```bash
cargo test
```

---

## 5. Submitting Workload via AndroGrid CLI

Submit the compiled workload to an active AndroGrid cluster using the canonical CLI:

```bash
androgrid submit \
  --wasm target/wasm32-wasip1/release/http_benchmark.wasm \
  --entrypoint "_start" \
  --timeout 60 \
  --egress-policy allowlist \
  --allowed-hostnames "api.staging.target.com" \
  --max-egress-bytes 10485760 \
  --env TARGET_URL=https://api.staging.target.com/get \
  --env METHOD=GET \
  --env CONCURRENCY=4 \
  --env DURATION_SECS=10
```

Verify the task status and output metrics:
```bash
androgrid status <task_id>
```

---

## 6. Execution Output Format

The workload writes a human-readable tabular summary and a machine-readable JSON payload to standard output (`stdout`):

```text
================================================================================
                     AndroGrid Distributed HTTP Benchmark                       
================================================================================
Task ID:             task_bench_001
Target URL:          https://api.staging.target.com/get
HTTP Method:         GET
Concurrency:         4
Duration:            10.02s
Total Requests:      150
Successful (2xx):    150
Total Errors:        0
Total Bytes:         45120 bytes
Throughput:          14.97 req/sec (4.40 KB/sec)

HTTP Status Distribution:
  HTTP 200:         150

Latency Distribution (ms):
  Min:               12.34 ms
  p50:               45.67 ms
  p90:               78.90 ms
  p95:               85.12 ms
  p99:               95.43 ms
  Max:               112.50 ms
  Mean:              48.21 ms
================================================================================
JSON Report:
{
  "task_id": "task_bench_001",
  "target_url": "https://api.staging.target.com/get",
  "method": "GET",
  "concurrency": 4,
  "duration_secs": 10.02,
  "total_requests": 150,
  "successful_requests": 150,
  "requests_per_sec": 14.97,
  "total_bytes_transferred": 45120,
  "bytes_per_sec": 4502.99,
  "status_codes": {
    "200": 150
  },
  "errors": {
    "io_failure": 0,
    "security_violation": 0,
    "buffer_too_small": 0,
    "quota_exceeded": 0,
    "other_errors": 0
  },
  "latency_percentiles": {
    "min_ms": 12.34,
    "p50_ms": 45.67,
    "p90_ms": 78.9,
    "p95_ms": 85.12,
    "p99_ms": 95.43,
    "max_ms": 112.5,
    "mean_ms": 48.21
  }
}
```

---

## 7. Security and Operational Guards

1. **Egress Allowlist Guard:** Outbound requests are permitted strictly to hostnames matching the orchestrator allowlist declared on `TaskSpec`. Attempts to contact unlisted domains are blocked with `-403` (`ERR_SECURITY_VIOLATION`).
2. **In-Socket Anti-SSRF:** IP resolution is evaluated inside the socket pipeline. Private IPv4/IPv6 spaces, loopback addresses, and link-local metadata addresses are blocked.
3. **Fail-Closed Quotas:** Cumulative transfer volume is billed against `max_egress_bytes`. Exceeding quota immediately aborts with `-429` (`ERR_QUOTA_EXCEEDED`).
4. **Zero-Redirects Policy:** Automatic 3xx redirection is disabled to eliminate SSRF bypasses.
