# ADR-011: Controlled Outbound Network Access for Sandboxed Workloads

## Status
Accepted

## Architectural Scope & Requirements
- Issue Reference: #56 (feat(wasm): support controlled outbound network access for sandboxed workloads)
- Traceability: [INV-001], [INV-003], [INV-004], [INV-006], [ANTI-003], [NFR-SEC-001], [NFR-POW-001], [NFR-PERF-001]
- Standard: ISO/IEC/IEEE 29148:2018

---

## Context
Worker nodes execute untrusted WebAssembly workloads inside an in-process Chicory WASI sandbox ([INV-006], [REQ-VER-003]). Several real-world distributed edge workloads (e.g., distributed public web scraping, external API telemetry aggregation, webhook dispatch, content verification, and distributed load/stress testing on single-operator, operator-controlled clusters supporting multi-node-group load simulation via [ADR-007]) require outbound HTTP/HTTPS network access.

However, granting uncontrolled network egress from mobile devices introduces grave security, operational, and distributed systems risks:
1. **Server-Side Request Forgery (SSRF) & LAN Lateral Movement:** A malicious or compromised WASM payload running on an Android worker device connected to a home, enterprise, or lab Wi-Fi network could probe and exploit private subnet targets (e.g., RFC 1918 addresses `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), device loopback (`127.0.0.1`, `::1`), router configuration portals, local IoT endpoints, or cloud link-local metadata endpoints (`169.254.169.254`).
2. **DNS Rebinding & TOCTOU Sockets:** If DNS resolution validation occurs prior to socket connection, an attacker's nameserver can respond with a short TTL (TTL=0) and return a public IP during pre-flight checks, followed by an internal/private IP during socket connection.
3. **Open Proxy & Residential IP Abuse:** Without strict destination allowlisting and public-suffix protections, malicious actors could submit workloads transforming the mobile edge cluster into an anonymous residential proxy network for credential stuffing, spamming, or denial-of-service amplification. Untrusted multi-tenant SaaS access is strictly out of scope until cryptographic target-ownership verification is introduced.
4. **Bandwidth Exhaustion & Memory DOS:** Streaming unmetered responses or gzip bombs can exhaust device heap memory or saturate cellular/Wi-Fi quotas without streaming bounds.
5. **Metered Cellular Radio & Battery Drain ([INV-003], [ANTI-003], [NFR-POW-001]):** Keeping cellular baseband radios active for long-running outbound data streaming violates baseband power management invariants, drains battery, and incurs unexpected cellular data billing.
6. **Distributed Dual-Assignment Race Conditions ([INV-005], [ADR-004]):** If the orchestrator speculatively reassigns a running cellular task to a faster Wi-Fi node, non-idempotent outbound HTTP mutations (e.g., POST, PUT, DELETE) will execute multiple times across external servers, violating expected execution semantics.
7. **Thread & Socket Leaks on Preemption:** Outbound socket operations can block indefinitely on slow or unresponsive remote servers. If the orchestrator preempts a task (`cancel_task_ids`) or the Android service watchdog fires (`WorkerForegroundService.onTimeout`), blocking socket calls must abort immediately to avoid thread and resource leakage.

---

## Decision

We establish a multi-layered, secure, and metered outbound network egress subsystem for sandboxed WebAssembly workloads across `androgrid-backend` and `androgrid-android`:

### 1. MVP Protocol Scope & Tenancy Boundary (HTTP/HTTPS Only)
- This ADR approves an **HTTP/HTTPS-only** egress boundary as our MVP for **single-operator, operator-controlled clusters (supporting multi-node-group load simulation via ADR-007)**.
- Untrusted multi-tenant SaaS access is explicitly out of scope until cryptographic target-ownership verification (such as DNS TXT / TLS ACME challenge proof) is introduced.
- Raw TCP and UDP socket egress is **strictly out of scope for this ADR** and explicitly deferred to a future ADR.

### 2. Protobuf Contract Alignment (`NetworkEgressPolicy`)
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
- `repeated string allowed_hostnames = 16;` (Explicit allowed FQDNs or scoped subdomains)
- `uint64 max_egress_bytes = 17;` (Cumulative payload transfer budget per task attempt)

### 3. Threat Model & Socket-Level Security Guards

1. **Pre-flight Scheme & Protocol Enforcement:** Target URLs must strictly use `http` or `https` schemes. Raw TCP/UDP socket binding and arbitrary ports are strictly prohibited, upholding [INV-001].
2. **Destination Allowlist & Public-Suffix Boundaries:**
   - Exact FQDN matching is preferred (e.g., `api.example.com`).
   - Bare `*` wildcards are strictly prohibited and rejected by scheduler validation.
   - Wildcards must have at least three dot-separated components (e.g., `*.api.example.com`). Wildcards across Public Suffixes (e.g., `*.co.uk`, `*.com`) are rejected.
   - Wildcards strictly match subdomains and never match the apex domain (`*.example.com` matches `sub.example.com` but does NOT match `example.com`).
3. **In-Socket Anti-TOCTOU DNS Validation:**
   - DNS validation is not performed as a disconnected pre-flight check. Instead, IP address validation is bound directly to `OkHttpClient`'s `Dns` resolver interface.
   - When the HTTP engine resolves hostnames immediately prior to socket establishment, every resolved `InetAddress` is evaluated. If any returned IP falls within a disallowed range, resolution aborts with `UnknownHostException` / `SecurityException`.
   - Disallowed address spaces:
     - Loopback (`127.0.0.0/8`, `::1`, `localhost`)
     - RFC 1918 Private Spaces (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
     - IPv6 Unique Local Addresses (`fc00::/7`, RFC 4193)
     - Link-Local / Cloud Metadata (`169.254.0.0/16`, `fe80::/10`)
     - Carrier-Grade NAT (`100.64.0.0/10`)
     - Multicast (`224.0.0.0/4`, `ff00::/8`)
     - Wildcard / Unspecified (`0.0.0.0`, `::`)
     - IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) are unpacked and evaluated against the full IPv4 disallow list.
4. **Zero Redirect Following (Anti-SSRF):**
   - The egress HTTP client explicitly configures `followRedirects = false` and `followSslRedirects = false`.
   - Automatic 3xx redirection is forbidden to prevent open-redirect SSRF bypasses to internal services.

### 4. Fail-Closed Quotas and Streaming Execution

1. **Fail-Closed Default Quotas:**
   - In accordance with proto3 defaults, if `egress_policy == ALLOWLIST` but `max_egress_bytes == 0`, the backend scheduler rejects the task as invalid. At runtime, `max_egress_bytes == 0` is treated as 0 allowed bytes (fail-closed).
2. **Chunked Streaming without Heap Buffering:**
   - To prevent Out-Of-Memory (OOM) crashes from large responses or compression bombs, the response body is streamed via Okio `BufferedSource` in bounded chunks directly into WASM linear memory.
   - Total transferred bytes (headers + request body + response body) are tracked dynamically against `max_egress_bytes`. If the incoming stream exceeds the remaining quota or the 16 MB frame limit ([NFR-PERF-001]), the socket is aborted immediately.
3. **Fail-Closed Metered Network Guard:**
   - The engine's `isMeteredProvider` defaults to `{ true }` (fail-closed). Network egress is blocked unless an active, verified unmetered connection is explicitly confirmed.

### 5. Chicory Host Function Contract & Locked WASM ABI

The runtime exposes the `androgrid_net` host module:
```wasm
(import "androgrid_net" "http_fetch" (func $http_fetch 
  (param $url_ptr i32) (param $url_len i32)
  (param $method_ptr i32) (param $method_len i32)
  (param $headers_ptr i32) (param $headers_len i32)
  (param $body_ptr i32) (param $body_len i32)
  (param $out_buf_ptr i32) (param $out_buf_cap i32)
  (param $out_written_ptr i32)
  (result i32)))
```

1. **Return Codes (Zero Traps for Network Errors, No Status Code Drop):**
   - **Success (`i32 >= 100`):** Returns the HTTP response status code (e.g. `200`, `201`, `404`, `500`). The full response body is written into `out_buf_ptr`, and the exact byte count is written as an `i32` into `out_written_ptr`.
   - **Failure (`i32 < 0`):** Returns a fixed negative error code enum:
     - `-1`: `ERR_IO_FAILURE` (remote connection failure, TCP timeout, or DNS resolution failure)
     - `-403`: `ERR_SECURITY_VIOLATION` (SSRF guard triggered, disallowed IP/scheme, unlisted destination, or metered cellular route)
     - `-413`: `ERR_BUFFER_TOO_SMALL` (response payload exceeded `out_buf_cap`; stream aborted immediately without silent data truncation)
     - `-429`: `ERR_QUOTA_EXCEEDED` (cumulative task transfer exceeded `max_egress_bytes`)
2. **Headers Specification & Anti-Smuggling:**
   - Headers are passed as a newline-delimited (`\n` or `\r\n`) list of `Key: Value` strings.
   - Total serialized headers length is capped at 8192 bytes (`MAX_HEADERS_BYTES`) and counted byte-for-byte against `max_egress_bytes`.
   - Forbidden hop-by-hop and smuggling headers: `Host`, `Transfer-Encoding`, `Content-Length`, `Connection`, `Keep-Alive`, `Proxy-Connection`, `Upgrade`, `TE`, `Trailer`, `Proxy-Authorization`, `Proxy-Authenticate`. Rejection occurs if present.
   - All header keys and values are verified to be free of ASCII control characters (`\0`, `\r`, `\n`).
3. **Memory Bounds Verification:**
   - Host functions assert `url_len >= 0`, `method_len >= 0`, `headers_len >= 0`, `body_len >= 0`, `out_buf_cap >= 0`, and `out_written_ptr >= 0`.
   - Bounds are checked against linear memory size prior to reading or writing.

### 6. Client Lifecycle, Timeouts & Per-Task Scoping

1. **Aggressive Timeout Bounds:**
   - `connectTimeout = 10s`
   - `readTimeout = 15s`
   - `writeTimeout = 15s`
   - `callTimeout = minOf(30s, task_timeout)`
2. **Shared Base Client & Per-Task Scoping:**
   - `WasmComputeEngine` maintains a single shared base `OkHttpClient` instance configured with an isolated daemon `Dispatcher` and `ConnectionPool(maxIdleConnections = 4, keepAliveDuration = 15s)`.
   - Each task derives a lightweight child client via `sharedClient.newBuilder().dns(taskScopedDnsGuard).build()`, safely sharing underlying threads while strictly isolating per-task `allowed_hostnames`, quota counters, and structured cancellation.
   - **Socket Reuse Note:** Per-task `Dns` isolation intentionally prevents cross-task TCP connection reuse across different task allowlist security boundaries. This strict isolation is a deliberate security feature to avoid cross-tenant connection pooling or host spoofing.
   - All active calls are tracked and cleanly cancelled via coroutine cancellation hooks (`invokeOnCompletion(onCancelling = true)`).
   - On engine close, `dispatcher.executorService.shutdownNow()` and `connectionPool.evictAll()` ensure zero socket or thread leakage.

### 7. Distributed Semantics & Scheduler Invariants

1. **At-Least-Once External Semantics & Idempotency Key Scoping:**
   - Outbound HTTP requests over distributed networks exhibit **at-least-once execution semantics**. If a node encounters a network disconnection or battery failure after dispatching an outbound request, the orchestrator cannot guarantee whether the remote endpoint processed the request.
   - Workloads performing mutating operations (POST, PUT, DELETE) must supply application-level idempotency tokens scoped strictly to `<task_id>` (and **never** `<task_id>_<run_attempt>`, which would defeat cross-attempt deduplication across retries).
2. **Disabling Speculative Preemption & Automatic Retries:**
   - To mitigate duplicate outbound side effects, tasks configured with `egress_policy == ALLOWLIST`:
     - Have `max_attempts = 1` by default.
     - Speculative preemption and dual-assignment ([ADR-004], [INV-005]) are strictly **disabled**. Egress-enabled tasks execute exclusively on a single assigned worker.
3. **Static Bytecode Validation (`wasi_validator.rs`):**
   - The control plane's `WasiValidator` inspects WebAssembly import sections during artifact upload and task submission.
   - If a binary imports `androgrid_net:*` host functions while `TaskSpec.egress_policy == BLOCKED` (or unspecified), the task is rejected at submission time with `INVALID_ARGUMENT`.

---

## Consequences

### Positive
- Clarifies MVP protocol boundaries (HTTP/HTTPS only) for single-operator, operator-controlled load and stress testing clusters (supporting multi-node-group simulation via ADR-007).
- Closes the TOCTOU DNS rebinding vulnerability by validating IP records within the socket connection pipeline.
- Eliminates open-redirect SSRF vulnerabilities by disabling automatic HTTP redirection.
- Enforces strict public-suffix, apex, and CIDR space boundaries (including IPv6 ULA `fc00::/7` and IPv4-mapped IPv6).
- Prevents JVM memory exhaustion via bounded streaming Okio reads.
- Eliminates fail-open security flaws in default quotas and metered network detection.
- Locks a robust WASM ABI returning HTTP status codes on success and fixed negative error enums on failure, eliminating status code drop and error code collision.
- Safely isolates per-task DNS security boundaries without connection pooling cross-contamination.
- Protects external third-party systems from duplicate non-idempotent calls by disabling speculative dual-assignment and scoping idempotency keys strictly to `<task_id>`.

### Negative / Trade-offs
- Raw TCP and UDP socket egress is unavailable and deferred to a future ADR.
- Outbound requests cannot automatically follow HTTP 3xx redirects; workloads needing redirection must execute subsequent hops explicitly.
- Speculative speedup optimization ([ADR-004]) is unavailable for egress-enabled tasks.
- Wildcards are restricted to third-level subdomains or deeper; apex domains must be explicitly listed.
