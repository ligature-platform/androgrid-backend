//! Transport layer abstraction for outbound HTTP execution.
//!
//! Provides the host module interface bridge (`androgrid_net:http_fetch`) when
//! executing in Chicory WebAssembly, along with a mockable transport for hermetic
//! unit testing.
//!
//! Traces to: AG-SPEC-2026-V2, [REQ-OP-002], [REQ-OP-003], [INV-001], [INV-006], ADR-011

use std::fmt;

/// Standard negative error codes returned by the `androgrid_net` host module.
///
/// Traces to: ADR-011 Section 5
pub const ERR_IO_FAILURE: i32 = -1;
pub const ERR_SECURITY_VIOLATION: i32 = -403;
pub const ERR_BUFFER_TOO_SMALL: i32 = -413;
pub const ERR_QUOTA_EXCEEDED: i32 = -429;

/// Outbound HTTP request parameters passed to the transport.
///
/// Traces to: [REQ-OP-002], [INV-006]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// Destination endpoint URL.
    pub url: String,
    /// HTTP method (e.g. GET, POST).
    pub method: String,
    /// Newline-delimited headers (`Key: Value\r\n`).
    pub headers: String,
    /// Request payload body bytes.
    pub body: Vec<u8>,
}

/// Outbound HTTP execution response returned from the transport.
///
/// Zero-heap response record avoiding payload buffer copying in the benchmark hot loop.
///
/// Traces to: [REQ-OP-002], [INV-006], [NFR-PERF-001]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP response status code (e.g. 200, 404, 500).
    pub status_code: u16,
    /// Exact byte count written into buffer.
    pub bytes_written: usize,
    /// Measured request round-trip latency in microseconds.
    pub latency_micros: u64,
}

/// Error categories encountered during outbound network execution.
///
/// Traces to: ADR-011 Section 5
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Remote network connection failure, TCP timeout, or DNS lookup error.
    IoFailure,
    /// Egress security policy violation (SSRF, disallowed IP, unlisted hostname, metered route).
    SecurityViolation,
    /// Response payload exceeded buffer capacity.
    BufferTooSmall,
    /// Cumulative task network transfer exceeded max_egress_bytes quota.
    QuotaExceeded,
    /// Unrecognized negative error code.
    Unknown(i32),
}

impl TransportError {
    /// Indicates whether the error is fatal and cannot recover with retries.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::SecurityViolation | Self::QuotaExceeded)
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoFailure => write!(f, "Network I/O failure (ERR_IO_FAILURE: -1)"),
            Self::SecurityViolation => {
                write!(
                    f,
                    "Egress security policy violation (ERR_SECURITY_VIOLATION: -403)"
                )
            }
            Self::BufferTooSmall => {
                write!(
                    f,
                    "Response buffer capacity exceeded (ERR_BUFFER_TOO_SMALL: -413)"
                )
            }
            Self::QuotaExceeded => {
                write!(
                    f,
                    "Cumulative egress byte quota exceeded (ERR_QUOTA_EXCEEDED: -429)"
                )
            }
            Self::Unknown(code) => write!(f, "Unknown transport error code: {code}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<i32> for TransportError {
    fn from(code: i32) -> Self {
        match code {
            ERR_IO_FAILURE => Self::IoFailure,
            ERR_SECURITY_VIOLATION => Self::SecurityViolation,
            ERR_BUFFER_TOO_SMALL => Self::BufferTooSmall,
            ERR_QUOTA_EXCEEDED => Self::QuotaExceeded,
            other => Self::Unknown(other),
        }
    }
}

/// Abstract contract for HTTP execution, enabling hermetic mocking and WASI bridging.
///
/// Traces to: [REQ-OP-002], [INV-006]
pub trait HttpTransport {
    /// Executes an HTTP request and measures latency and status.
    ///
    /// # Arguments
    /// * `request` - Specification of the outbound HTTP request.
    ///
    /// # Returns
    /// * `Ok(HttpResponse)` on successful HTTP response (status code >= 100).
    /// * `Err(TransportError)` on network or security sandbox failure.
    fn execute(&mut self, request: &HttpRequest) -> Result<HttpResponse, TransportError>;
}

#[cfg(target_arch = "wasm32")]
mod wasi_ffi {
    #[link(wasm_import_module = "androgrid_net")]
    extern "C" {
        pub fn http_fetch(
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
}

/// WebAssembly WASI implementation of the HTTP transport using `androgrid_net:http_fetch`.
///
/// Reuses a single preallocated linear memory buffer to prevent allocation churn.
///
/// Traces to: [INV-001], [INV-006], [NFR-PERF-001], ADR-011
pub struct WasiHttpTransport {
    #[allow(dead_code)]
    buffer: Vec<u8>,
}

impl WasiHttpTransport {
    /// Creates a new WASI transport with preallocated response buffer.
    pub fn new(buffer_capacity: usize) -> Self {
        Self {
            buffer: vec![0u8; buffer_capacity],
        }
    }
}

impl HttpTransport for WasiHttpTransport {
    fn execute(&mut self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let start_time = std::time::Instant::now();

        #[cfg(target_arch = "wasm32")]
        {
            let mut bytes_written: i32 = 0;
            let status = unsafe {
                wasi_ffi::http_fetch(
                    request.url.as_ptr(),
                    request.url.len() as i32,
                    request.method.as_ptr(),
                    request.method.len() as i32,
                    request.headers.as_ptr(),
                    request.headers.len() as i32,
                    request.body.as_ptr(),
                    request.body.len() as i32,
                    self.buffer.as_mut_ptr(),
                    self.buffer.len() as i32,
                    &mut bytes_written as *mut i32,
                )
            };

            let latency_micros = start_time.elapsed().as_micros() as u64;

            if status >= 100 {
                let written = (bytes_written.max(0) as usize).min(self.buffer.len());
                Ok(HttpResponse {
                    status_code: status as u16,
                    bytes_written: written,
                    latency_micros,
                })
            } else {
                Err(TransportError::from(status))
            }
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = request;
            let _ = start_time;
            let _ = &self.buffer;
            Err(TransportError::IoFailure)
        }
    }
}

/// Hermetic mock HTTP transport for deterministic unit and concurrency testing.
#[derive(Debug, Default)]
pub struct MockHttpTransport {
    /// Configured responses to return sequentially.
    pub canned_responses: Vec<Result<HttpResponse, TransportError>>,
    /// Recorded requests executed through this transport.
    pub recorded_requests: Vec<HttpRequest>,
    /// Fallback response when canned responses are exhausted.
    pub default_response: Option<Result<HttpResponse, TransportError>>,
    /// Call index counter.
    cursor: usize,
}

impl MockHttpTransport {
    /// Creates an empty mock transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a successful response to the canned queue.
    pub fn queue_response(
        &mut self,
        status_code: u16,
        bytes_written: usize,
        latency_micros: u64,
    ) -> &mut Self {
        self.canned_responses.push(Ok(HttpResponse {
            status_code,
            bytes_written,
            latency_micros,
        }));
        self
    }

    /// Appends an error to the canned queue.
    pub fn queue_error(&mut self, error: TransportError) -> &mut Self {
        self.canned_responses.push(Err(error));
        self
    }

    /// Sets a persistent default response for repeating loops.
    pub fn set_default_success(
        &mut self,
        status_code: u16,
        bytes_written: usize,
        latency_micros: u64,
    ) -> &mut Self {
        self.default_response = Some(Ok(HttpResponse {
            status_code,
            bytes_written,
            latency_micros,
        }));
        self
    }
}

impl HttpTransport for MockHttpTransport {
    fn execute(&mut self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        self.recorded_requests.push(request.clone());

        if self.cursor < self.canned_responses.len() {
            let res = self.canned_responses[self.cursor].clone();
            self.cursor += 1;
            res
        } else if let Some(ref default) = self.default_response {
            default.clone()
        } else {
            Ok(HttpResponse {
                status_code: 200,
                bytes_written: 2,
                latency_micros: 1000,
            })
        }
    }
}
