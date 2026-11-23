# Distributed HTTP/HTTPS Load Testing Guide

**Specification Baseline:** AG-SPEC-2026-V2 (`AndroGrid_SDD.md`)  
**Architecture References:** [ADR-007: NodeGroup Partitioning](../adr/ADR-007-node-group-partitioning.md), [ADR-011: Controlled WASM Outbound Network Access](../adr/ADR-011-controlled-wasm-outbound-network-access.md)  
**Standard Compliance:** ISO/IEC/IEEE 29148:2018  
**Typographic Standard:** Zero Unicode em dashes (U+2014) or en dashes (U+2013). Strict ASCII hyphen (-) conformance.

---

## 1. Overview and Trust Boundary

AndroGrid enables edge-native distributed HTTP/HTTPS load and stress simulation by coordinating Android mobile worker devices. In accordance with ADR-011, outbound network execution operates strictly within a **single-operator, operator-controlled cluster** environment:

1. **Authorized Target Scoping:** The operator explicitly defines allowed destination hostnames in the `TaskSpec` via `NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST`.
2. **Quota Bounds:** Egress transfer volume is constrained per task attempt via `max_egress_bytes`.
3. **At-Least-Once Execution:** Mutating load requests (POST, PUT, DELETE) must provide application-level `Idempotency-Key: <task_id>` headers to avoid unintended duplicate execution across retry boundaries.
4. **Single-Attempt Scheduling:** Egress tasks default to `max_attempts = 1`, and speculative dual-assignment (ADR-004) is disabled to prevent duplicate side effects.

---

## 2. Multi-NodeGroup Load Partitioning Architecture

Using NodeGroup partitioning (ADR-007), an operator can partition the edge cluster into heterogeneous simulated cohorts representing diverse real-world mobile network conditions:

```
+-------------------------------------------------------------------+
|                     Operator Control Plane                        |
|   - TaskGroup Dispatcher with NetworkEgressPolicy: ALLOWLIST      |
|   - Destination: api.staging.target.com | Quota: 10 MB / attempt  |
+---------------------------------+---------------------------------+
                                  |
         +------------------------+------------------------+
         |                                                 |
         v                                                 v
+-----------------------------+           +-----------------------------+
|    NodeGroup: "wifi-fast"   |           |    NodeGroup: "lab-cellular"|
| - High-throughput Wi-Fi     |           | - Edge rate-limited Wi-Fi   |
| - Unmetered interface       |           | - Simulated jitter / latency|
| - 50 concurrent worker nodes|           | - 25 concurrent worker nodes|
+-----------------------------+           +-----------------------------+
```

### NodeGroup Affinity Specification
Operators target specific node groups using the `node_group_affinity` field on `TaskSpec`:
- Tasks destined for fast ramp-up tests target the `wifi-fast` group.
- Tasks testing mobile latency resilience target the `lab-cellular` group.

---

## 3. Submitting a Distributed Load Testing TaskGroup

Below is an example submission utilizing the `androgrid` CLI to dispatch a distributed load generation TaskGroup:

```bash
androgrid admin submit-task \
  --entrypoint "_start" \
  --timeout 120 \
  --engine wasm_wasi \
  --egress-policy allowlist \
  --allowed-hostnames "api.staging.target.com,*.loadtest.internal" \
  --max-egress-bytes 10485760 \
  --wasm-file target/wasm32-wasip1/release/http_load_generator.wasm
```

### Task Specification Details
- `egress_policy: NETWORK_EGRESS_POLICY_ALLOWLIST` (enables `androgrid_net:http_fetch` host module).
- `allowed_hostnames`: Target FQDNs. Apex domains must be explicitly declared; wildcards must have at least 3 domain components.
- `max_egress_bytes`: Total byte quota (headers + request body + response body) allowed for the task execution attempt.

---

## 4. WASM Guest Workload Example (Rust WASI)

Workloads compiled to WASI call the `androgrid_net:http_fetch` host function to issue HTTP requests:

```rust
// Link to the Chicory host module bridge
#[link(wasm_import_module = "androgrid_net")]
extern "C" {
    fn http_fetch(
        url_ptr: *const u8,
        url_len: i32,
        method_ptr: *const u8,
        method_len: i32,
        headers_ptr: *const u8,
        headers_len: i32,
        body_ptr: *const u8,
        body_len: i32,
        out_buf_ptr: *mut u8,
        out_buf_cap: i32,
        out_written_ptr: *mut i32,
    ) -> i32;
}

pub fn execute_http_get(url: &str) -> Result<Vec<u8>, i32> {
    let method = "GET";
    let headers = "Accept: application/json\r\n";
    let body = "";
    let mut out_buf = vec![0u8; 65536];
    let mut written: i32 = 0;

    let status = unsafe {
        http_fetch(
            url.as_ptr(),
            url.len() as i32,
            method.as_ptr(),
            method.len() as i32,
            headers.as_ptr(),
            headers.len() as i32,
            body.as_ptr(),
            body.len() as i32,
            out_buf.as_mut_ptr(),
            out_buf.len() as i32,
            &mut written as *mut i32,
        )
    };

    if status >= 100 {
        out_buf.truncate(written as usize);
        Ok(out_buf)
    } else {
        // Negative return code signifies error:
        // -1 = ERR_IO_FAILURE
        // -403 = ERR_SECURITY_VIOLATION
        // -413 = ERR_BUFFER_TOO_SMALL
        // -429 = ERR_QUOTA_EXCEEDED
        Err(status)
    }
}
```

---

## 5. Security & Operational Constraints

1. **SSRF Guard:** All target endpoints are validated at socket connection time. Any attempt to reach RFC 1918 private subnets, loopback (`127.0.0.1`), or link-local cloud metadata addresses (`169.254.169.254`) is deterministically aborted with `-403` (`ERR_SECURITY_VIOLATION`).
2. **Buffer Sizing:** If a remote server returns a response larger than `out_buf_cap`, the stream is aborted immediately with `-413` (`ERR_BUFFER_TOO_SMALL`). Guest modules must size buffers adequately or query headers.
3. **Metered Protection:** Tasks with outbound network egress are never dispatched across metered cellular links, upholding mobile battery and data invariants ([ANTI-003], [NFR-POW-001]).
