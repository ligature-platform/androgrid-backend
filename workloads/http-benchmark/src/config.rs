//! Workload configuration and runtime environment parser.
//!
//! Parses load testing parameters from environment variables injected by the
//! orchestrator runtime or provided via task definitions.
//!
//! Traces to: AG-SPEC-2026-V2, [REQ-OP-002], [REQ-OP-003], [INV-006]

use std::collections::HashMap;
use std::env;

/// Errors arising from invalid or missing benchmark configuration parameters.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfigError {
    /// Target URL was missing or empty.
    MissingTargetUrl,
    /// Target URL has an invalid or unsupported scheme.
    InvalidTargetUrlScheme(String),
    /// HTTP method is unsupported or invalid.
    InvalidMethod(String),
    /// Concurrency value was invalid or non-positive.
    InvalidConcurrency(String),
    /// Duration value was invalid or non-positive.
    InvalidDuration(String),
    /// Max requests value was invalid or non-positive.
    InvalidMaxRequests(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTargetUrl => write!(f, "TARGET_URL environment variable is required"),
            Self::InvalidTargetUrlScheme(url) => {
                write!(f, "TARGET_URL '{url}' must start with http:// or https://")
            }
            Self::InvalidMethod(m) => write!(f, "Invalid HTTP method '{m}'"),
            Self::InvalidConcurrency(c) => write!(f, "Invalid CONCURRENCY value '{c}'"),
            Self::InvalidDuration(d) => write!(f, "Invalid DURATION_SECS value '{d}'"),
            Self::InvalidMaxRequests(r) => write!(f, "Invalid MAX_REQUESTS value '{r}'"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Configuration parameters governing the HTTP benchmark execution.
///
/// Traces to: [REQ-OP-002], [INV-006]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkConfig {
    /// Target URL to benchmark (e.g. `https://httpbin.org/get`).
    pub target_url: String,
    /// HTTP method verb (GET, POST, PUT, DELETE, HEAD, PATCH). Default: "GET".
    pub method: String,
    /// Number of simulated concurrent workers. Default: 4.
    pub concurrency: usize,
    /// Total duration of the benchmark run in seconds. Default: 10.
    pub duration_secs: u64,
    /// Optional limit on total requests before stopping early.
    pub max_requests: Option<u64>,
    /// Optional request body to send for mutating verbs.
    pub request_body: Option<String>,
    /// Optional newline-delimited custom headers.
    pub custom_headers: Option<String>,
    /// Task identifier assigned by AndroGrid orchestrator.
    pub task_id: String,
    /// Maximum response buffer size in bytes. Default: 65536 (64 KB).
    pub buffer_size: usize,
}

impl BenchmarkConfig {
    /// Default response buffer size (64 KB) to bound linear memory usage.
    pub const DEFAULT_BUFFER_SIZE: usize = 65536;

    /// Default concurrency level for virtual load generation.
    pub const DEFAULT_CONCURRENCY: usize = 4;

    /// Default load duration in seconds.
    pub const DEFAULT_DURATION_SECS: u64 = 10;

    /// Supported HTTP request methods.
    pub const SUPPORTED_METHODS: &'static [&'static str] =
        &["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"];

    /// Parses configuration from process environment variables.
    ///
    /// Traces to: [REQ-OP-002], [INV-006]
    pub fn from_env() -> Result<Self, ConfigError> {
        let vars: HashMap<String, String> = env::vars().collect();
        Self::from_map(&vars)
    }

    /// Parses configuration from a key-value map for hermetic unit testing.
    ///
    /// Traces to: [REQ-OP-002], [INV-006]
    pub fn from_map(vars: &HashMap<String, String>) -> Result<Self, ConfigError> {
        let target_url = vars
            .get("TARGET_URL")
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .ok_or(ConfigError::MissingTargetUrl)?;

        let trimmed_url = target_url.trim();
        if !trimmed_url.starts_with("http://") && !trimmed_url.starts_with("https://") {
            return Err(ConfigError::InvalidTargetUrlScheme(target_url));
        }

        let method = match vars.get("METHOD").map(|s| s.trim().to_uppercase()) {
            Some(m) if !m.is_empty() => {
                if !Self::SUPPORTED_METHODS.contains(&m.as_str()) {
                    return Err(ConfigError::InvalidMethod(m));
                }
                m
            }
            _ => "GET".to_string(),
        };

        let concurrency = match vars.get("CONCURRENCY").map(|s| s.trim()) {
            Some(c) if !c.is_empty() => {
                let parsed = c
                    .parse::<usize>()
                    .map_err(|_| ConfigError::InvalidConcurrency(c.to_string()))?;
                if parsed == 0 || parsed > 1024 {
                    return Err(ConfigError::InvalidConcurrency(c.to_string()));
                }
                parsed
            }
            _ => Self::DEFAULT_CONCURRENCY,
        };

        let duration_secs = match vars.get("DURATION_SECS").map(|s| s.trim()) {
            Some(d) if !d.is_empty() => {
                let parsed = d
                    .parse::<u64>()
                    .map_err(|_| ConfigError::InvalidDuration(d.to_string()))?;
                if parsed == 0 {
                    return Err(ConfigError::InvalidDuration(d.to_string()));
                }
                parsed
            }
            _ => Self::DEFAULT_DURATION_SECS,
        };

        let max_requests = match vars.get("MAX_REQUESTS").map(|s| s.trim()) {
            Some(r) if !r.is_empty() => {
                let parsed = r
                    .parse::<u64>()
                    .map_err(|_| ConfigError::InvalidMaxRequests(r.to_string()))?;
                if parsed == 0 {
                    return Err(ConfigError::InvalidMaxRequests(r.to_string()));
                }
                Some(parsed)
            }
            _ => None,
        };

        let request_body = vars
            .get("REQUEST_BODY")
            .or_else(|| vars.get("BODY"))
            .filter(|s| !s.is_empty())
            .cloned();

        let custom_headers = vars
            .get("REQUEST_HEADERS")
            .or_else(|| vars.get("HEADERS"))
            .filter(|s| !s.is_empty())
            .cloned();

        let task_id = vars
            .get("ANDROGRID_TASK_ID")
            .or_else(|| vars.get("TASK_ID"))
            .cloned()
            .unwrap_or_else(|| "task_local_bench".to_string());

        let buffer_size = match vars.get("BUFFER_SIZE").map(|s| s.trim()) {
            Some(b) if !b.is_empty() => b.parse::<usize>().unwrap_or(Self::DEFAULT_BUFFER_SIZE),
            _ => Self::DEFAULT_BUFFER_SIZE,
        };

        Ok(Self {
            target_url: trimmed_url.to_string(),
            method,
            concurrency,
            duration_secs,
            max_requests,
            request_body,
            custom_headers,
            task_id,
            buffer_size,
        })
    }
}
