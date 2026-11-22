# ADR-011: Controlled Outbound Network Access for Sandboxed Workloads

## Status
Accepted

## Architectural Scope & Requirements
- Issue Reference: #56 (feat(wasm): support controlled outbound network access for sandboxed workloads)
- Traceability: [INV-001], [INV-003], [INV-006], [ANTI-003], [NFR-SEC-001], [NFR-POW-001], [NFR-PERF-001]
- Standard: ISO/IEC/IEEE 29148:2018

---

## Context
Worker nodes execute untrusted WebAssembly workloads inside an in-process Chicory WASI sandbox ([INV-006], [REQ-VER-003]). Several real-world distributed edge workloads (e.g., distributed public web scraping, external API telemetry aggregation, webhook dispatch, content verification) require outbound HTTP/HTTPS network access.

However, granting uncontrolled network egress from mobile devices introduces grave security and operational risks:
1. **Server-Side Request Forgery (SSRF) & LAN Lateral Movement:** A malicious or compromised WASM payload running on an Android worker device connected to a home, enterprise, or lab Wi-Fi network could probe and exploit private subnet targets (e.g., RFC 1918 addresses `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), device loopback (`127.0.0.1`, `::1`), router configuration portals, local IoT endpoints, or cloud link-local metadata endpoints (`169.254.169.254`).
2. **Open Proxy & Residential IP Abuse:** Without strict destination allowlisting, malicious actors could submit workloads transforming the mobile edge cluster into an anonymous residential proxy network for credential stuffing, spamming, or denial-of-service amplification.
3. **Bandwidth Exhaustion & Data Exfiltration:** Workloads could exfiltrate gigabytes of sensitive data or saturate device network interfaces without transfer quotas.
4. **Metered Cellular Radio & Battery Drain ([INV-003], [ANTI-003], [NFR-POW-001]):** Keeping cellular baseband radios active for long-running outbound data streaming violates baseband power management invariants, drains battery, and incurs unexpected cellular data billing.
5. **Worker Thread Hanging on Cancellation:** Outbound socket operations can block indefinitely on slow or unresponsive remote servers. If the orchestrator preempts a task (`cancel_task_ids`) or the Android service watchdog fires (`WorkerForegroundService.onTimeout`), blocking socket calls must abort immediately to avoid thread and resource leakage.

---

## Decision

We implement a multi-layered, secure, and metered outbound network egress subsystem for sandboxed WebAssembly workloads across `androgrid-backend` and `androgrid-android`:

### 1. Protobuf Contract Alignment (`NetworkEgressPolicy`)
We extend `androgrid/v1/orchestrator.proto` with explicit declarative network egress controls:
```protobuf
enum NetworkEgressPolicy {
  NETWORK_EGRESS_POLICY_UNSPECIFIED = 0;
  NETWORK_EGRESS_POLICY_BLOCKED = 1;
  NETWORK_EGRESS_POLICY_ALLOWLIST = 2;
}
```
`TaskSpec` is extended with:
- `NetworkEgressPolicy egress_policy = 15;` (Default: `BLOCKED`)
- `repeated string allowed_hostnames = 16;` (Explicit allowed FQDNs or wildcards, e.g., `api.example.com`, `*.public.org`)
- `uint64 max_egress_bytes = 17;` (Cumulative payload transfer budget per task attempt)

### 2. Multi-Layer Threat Model & SSRF Guard
Before any socket connection or TCP handshake is initiated:
1. **Pre-flight URL Validation:** Target URLs must strictly use `http` or `https` schemes. Raw TCP socket binding or non-HTTP protocols remain strictly prohibited, upholding [INV-001].
2. **Destination Allowlist Verification:** If `egress_policy == NETWORK_EGRESS_POLICY_ALLOWLIST`, the target hostname must match an entry in `allowed_hostnames`. Exact matches and subdomain wildcards (`*.domain.tld`) are supported. If `egress_policy == NETWORK_EGRESS_POLICY_BLOCKED` or unlisted, the request is rejected with `SecurityException`.
3. **DNS Resolution & Private IP Guard:**
   - Hostnames are resolved to IP addresses prior to connection.
   - Every resolved IP address is verified against private, loopback, and link-local ranges:
     - Loopback (`127.0.0.0/8`, `::1`, `localhost`)
     - RFC 1918 Private Spaces (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
     - Link-Local / Cloud Metadata (`169.254.0.0/16`, `fe80::/10`)
     - Carrier-Grade NAT (`100.64.0.0/10`)
     - Multicast (`224.0.0.0/4`, `ff00::/8`)
     - Wildcard / Unspecified (`0.0.0.0`, `::`)
   - Any match immediately aborts the call with `SecurityException`, completely eliminating DNS rebinding attacks.

### 3. Metered Network Guard ([ANTI-003], [INV-003], [NFR-POW-001])
- Outbound network requests originating from WASM workloads are strictly rejected when the worker node reports an active metered connection (`capabilities.is_metered == true` or `current_transport == NETWORK_TRANSPORT_CELLULAR_WAN`), unless explicitly authorized by the scheduler and task policy.
- Cellular spot instances remain dedicated to offline compute followed by fast baseband radio teardown (< 200 ms per [NFR-POW-001]).

### 4. Quota and Frame Limits ([NFR-PERF-001])
- Egress transfer bytes (request body plus response body) are tracked against `max_egress_bytes`. If the transferred bytes exceed the allocated budget, the connection is terminated and an error code (`EGRESS_QUOTA_EXCEEDED`) is returned to the WASM caller.
- Single response payloads cannot exceed the 16 MB frame sizing boundary ([NFR-PERF-001]).

### 5. Chicory Host Function Bridge (`androgrid_net`)
- Chicory runtime exposes the `androgrid_net` host module:
  - `http_fetch(url_ptr: i32, url_len: i32, method_ptr: i32, method_len: i32, body_ptr: i32, body_len: i32, out_buf_ptr: i32, out_buf_cap: i32, out_written_ptr: i32) -> i32`
- Host functions read memory directly from `instance.memory()`. No shared object (.so) files or native libraries are written to disk, maintaining in-memory W^X compliance ([INV-006], [REQ-VER-003]).

### 6. Cooperative Cancellation & Preemption Hook
- To prevent worker threads from hanging during long-running or delayed network I/O, the host module hooks into the active coroutine job:
  ```kotlin
  val handle = executionJob?.invokeOnCompletion(onCancelling = true) { cause ->
      if (cause != null) {
          activeCall?.cancel()
      }
  }
  ```
- When the job is cancelled by orchestrator preemption (`cancel_task_ids`) or service timeout (`WorkerForegroundService.onTimeout`), the underlying OkHttp `Call` is cancelled immediately, tearing down the TCP socket in under 50 ms.

---

## Consequences

### Positive
- Enables rich distributed edge computing workloads (data aggregation, web querying, external validation) while maintaining cryptographic sandboxing.
- Eliminates SSRF, local subnet scanning, and DNS rebinding attacks via deterministic IP filtering.
- Protects mobile battery life and cellular carrier data allowances by enforcing the metered network guard.
- Guarantees zero worker thread leakage upon preemption or task cancellation.

### Negative / Trade-offs
- Slight latency overhead (typically 10-30 ms) during initial DNS pre-flight address validation.
- Raw TCP and UDP sockets remain unsupported for WASM payloads; workloads must utilize HTTP/HTTPS request semantics.
