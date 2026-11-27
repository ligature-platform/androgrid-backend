//! Embedded Web Dashboard, Pairing Management, and Observability Service
//!
//! Exposes Axum HTTP routes serving the embedded single-page dashboard,
//! real-time device pairing QR generation, worker APK distribution, JSON cluster state
//! snapshots, and real-time SSE event streams.
//!
//! Traces to: AG-SPEC-2026-V2, [INV-001], [INV-002], [INV-004], [INV-005], [NFR-REL-001], [REQ-OP-001], [REQ-OP-004]

use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::observability::snapshot::ClusterSnapshot;
use crate::pairing::{
    render_png_bytes, render_png_data_url, PairingError, PairingPayload, PairingTokenStore,
};
use crate::scheduler::engine::ClusterScheduler;

/// Embedded single-page dashboard HTML asset.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// State container for the dedicated Operator Web UI and Pairing Dashboard.
///
/// Traces to: [REQ-OP-001], [INV-001], [INV-002], [INV-004], [INV-005]
#[derive(Clone)]
pub struct WebUiState {
    /// Atomic cluster scheduler managing compute nodes and task queues.
    pub scheduler: Arc<ClusterScheduler>,
    /// Ephemeral token store for mobile worker pairing enrollment.
    pub token_store: Option<Arc<PairingTokenStore>>,
    /// Hexadecimal SHA-256 fingerprint of the cluster Root CA.
    pub ca_fingerprint: String,
    /// Canonical routable cluster endpoint (`host:port`).
    pub cluster_endpoint: String,
    /// URL for downloading the worker APK package from GitHub Releases or mirror.
    pub apk_download_url: String,
    /// Configured pairing token TTL in seconds (default: 300).
    pub pairing_token_ttl_seconds: u32,
    /// Optional operator confirmation PIN (e.g. 6-digit numeric PIN).
    pub operator_pin: Option<String>,
    /// Optional operator confirmation token.
    pub confirmation_token: Option<String>,
}

/// JSON payload containing pairing parameters and QR representation.
///
/// Traces to: [REQ-OP-001], [INV-002]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingWebResponse {
    pub pairing_token: String,
    pub cluster_endpoint: String,
    pub ca_fingerprint: String,
    pub expires_at_epoch_s: u64,
    pub pairing_payload_json: String,
    pub qr_png_data_url: String,
    pub apk_download_url: String,
    #[serde(default)]
    pub confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub confirmation_pin: Option<String>,
}

/// Request body for POST /api/pair with optional operator credentials.
#[derive(Debug, Deserialize, Default)]
pub struct PairingPostRequest {
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub confirmation_token: Option<String>,
}

/// Request body for POST /api/pair/confirm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmPairingRequest {
    pub token: String,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub confirmation_token: Option<String>,
}

/// Response body for POST /api/pair/confirm.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfirmPairingResponse {
    pub success: bool,
    pub token: String,
    pub confirmed: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub message: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error: String,
}

/// JSON payload containing worker APK download metadata and QR representation.
///
/// Traces to: [REQ-OP-001]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkInfoResponse {
    pub apk_download_url: String,
    pub qr_png_data_url: String,
}

/// Builds the Axum router configured with cluster dashboard and observability routes
/// backed only by the ClusterScheduler.
///
/// Traces to: [INV-004], [INV-005], [NFR-REL-001]
pub fn dashboard_router(scheduler: Arc<ClusterScheduler>) -> Router {
    Router::new()
        .route("/", get(handle_dashboard))
        .route("/dashboard", get(handle_dashboard))
        .route("/api/snapshot", get(handle_snapshot))
        .route("/api/events", get(handle_events))
        .route("/events", get(handle_events))
        .with_state(scheduler)
}

/// Builds the dedicated Operator Web UI router for port 8080.
///
/// Provides the embedded dashboard, real-time pairing QR code display,
/// worker APK distribution metadata, JSON cluster snapshots, and SSE telemetry.
///
/// Traces to: [REQ-OP-001], [INV-001], [INV-002], [INV-004], [INV-005]
pub fn web_ui_router(state: WebUiState) -> Router {
    Router::new()
        .route("/", get(handle_dashboard))
        .route("/dashboard", get(handle_dashboard))
        .route("/api/snapshot", get(handle_web_snapshot))
        .route("/api/events", get(handle_web_events))
        .route("/events", get(handle_web_events))
        .route("/api/pair", get(handle_get_pairing))
        .route("/api/pair", post(handle_post_pairing))
        .route("/api/pair/confirm", post(handle_confirm_pairing))
        .route("/api/pair/qr.png", get(handle_pairing_qr_png))
        .route("/api/apk-info", get(handle_apk_info))
        .route("/api/apk/qr.png", get(handle_apk_qr_png))
        .with_state(state)
}

/// Serves the self-contained HTML5 dashboard interface.
async fn handle_dashboard() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        "text/html; charset=utf-8".parse().expect("Valid header"),
    );
    headers.insert(
        CACHE_CONTROL,
        "no-cache, no-store, must-revalidate"
            .parse()
            .expect("Valid header"),
    );
    (StatusCode::OK, headers, DASHBOARD_HTML).into_response()
}

/// Serves point-in-time JSON snapshot of cluster state.
///
/// Traces to: [REQ-OP-001], [REQ-OP-004]
async fn handle_snapshot(State(scheduler): State<Arc<ClusterScheduler>>) -> Json<ClusterSnapshot> {
    Json(scheduler.get_snapshot())
}

/// Serves point-in-time JSON snapshot from WebUiState.
async fn handle_web_snapshot(State(state): State<WebUiState>) -> Json<ClusterSnapshot> {
    Json(state.scheduler.get_snapshot())
}

/// Serves asynchronous Server-Sent Events stream of real-time cluster state transitions.
///
/// Traces to: [INV-004], [INV-005], [NFR-REL-001]
async fn handle_events(
    State(scheduler): State<Arc<ClusterScheduler>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>> + Send + 'static> {
    let rx = scheduler.subscribe_events();
    let stream = BroadcastStream::new(rx).filter_map(|res| match res {
        Ok(ev) => match serde_json::to_string(&ev) {
            Ok(json) => Some(Ok(Event::default().data(json))),
            Err(_) => None,
        },
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Serves asynchronous Server-Sent Events stream from WebUiState.
async fn handle_web_events(
    State(state): State<WebUiState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>> + Send + 'static> {
    handle_events(State(state.scheduler)).await
}

/// Helper verifying operator confirmation credentials from headers or body.
fn check_operator_auth(
    state: &WebUiState,
    pin: Option<&str>,
    confirmation_token: Option<&str>,
) -> bool {
    if let Some(expected_pin) = state.operator_pin.as_deref() {
        if let Some(provided) = pin {
            if provided.trim() == expected_pin {
                return true;
            }
        }
    }
    if let Some(expected_token) = state.confirmation_token.as_deref() {
        if let Some(provided) = confirmation_token {
            if provided.trim() == expected_token {
                return true;
            }
        }
    }
    false
}

/// Generates a fresh ephemeral pairing token and returns the full pairing response.
fn build_pairing_response(
    state: &WebUiState,
    operator_auth_provided: bool,
) -> Result<PairingWebResponse, (StatusCode, &'static str)> {
    let token_store = state.token_store.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Pairing token store is not configured or pairing is disabled",
    ))?;

    let ttl = if state.pairing_token_ttl_seconds > 0 {
        Some(state.pairing_token_ttl_seconds)
    } else {
        Some(300)
    };

    let record = token_store
        .generate_token_with_preconfirmation(None, ttl, operator_auth_provided)
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate pairing token",
            )
        })?;

    if !operator_auth_provided {
        tracing::info!(
            token = %record.token,
            pin = %record.confirmation_pin,
            "Pairing token generated; awaiting operator confirmation PIN [NFR-SEC-001]"
        );
    }

    let payload = PairingPayload {
        cluster_endpoint: state.cluster_endpoint.clone(),
        ca_fingerprint: state.ca_fingerprint.clone(),
        pairing_token: record.token.clone(),
        node_id: None,
        expires_at_epoch_s: record.expires_at_epoch_s,
    };

    let payload_json = payload.to_compact_json().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to serialize pairing payload",
        )
    })?;

    let qr_png_data_url = render_png_data_url(&payload_json).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to render QR code matrix",
        )
    })?;

    Ok(PairingWebResponse {
        pairing_token: record.token,
        cluster_endpoint: state.cluster_endpoint.clone(),
        ca_fingerprint: state.ca_fingerprint.clone(),
        expires_at_epoch_s: record.expires_at_epoch_s,
        pairing_payload_json: payload_json,
        qr_png_data_url,
        apk_download_url: state.apk_download_url.clone(),
        confirmed: record.is_confirmed,
        confirmation_pin: if operator_auth_provided {
            Some(record.confirmation_pin)
        } else {
            None
        },
    })
}

/// GET /api/pair: Deprecated idempotency alias returning fresh pairing token with QR representation.
/// Deprecated in favor of explicit POST /api/pair to prevent pre-fetchers from creating tokens.
///
/// Traces to: [REQ-OP-001], [INV-002]
async fn handle_get_pairing(
    State(state): State<WebUiState>,
    headers: HeaderMap,
) -> Result<Json<PairingWebResponse>, (StatusCode, &'static str)> {
    let pin_hdr = headers.get("x-operator-pin").and_then(|v| v.to_str().ok());
    let token_hdr = headers
        .get("x-confirmation-token")
        .and_then(|v| v.to_str().ok());
    let is_auth = check_operator_auth(&state, pin_hdr, token_hdr);
    let resp = build_pairing_response(&state, is_auth)?;
    Ok(Json(resp))
}

/// POST /api/pair: Generates a new ephemeral device pairing token with QR representation.
///
/// Traces to: [REQ-OP-001], [INV-002]
async fn handle_post_pairing(
    State(state): State<WebUiState>,
    headers: HeaderMap,
    body: Option<Json<PairingPostRequest>>,
) -> Result<Json<PairingWebResponse>, (StatusCode, &'static str)> {
    let pin_hdr = headers.get("x-operator-pin").and_then(|v| v.to_str().ok());
    let token_hdr = headers
        .get("x-confirmation-token")
        .and_then(|v| v.to_str().ok());
    let pin_body = body.as_ref().and_then(|b| b.pin.as_deref());
    let token_body = body.as_ref().and_then(|b| b.confirmation_token.as_deref());

    let is_auth = check_operator_auth(&state, pin_hdr.or(pin_body), token_hdr.or(token_body));
    let resp = build_pairing_response(&state, is_auth)?;
    Ok(Json(resp))
}

/// POST /api/pair/confirm: Operator confirmation gate for ephemeral pairing tokens.
/// Requires 6-digit console/dashboard PIN or confirmation token before worker CSR signing.
///
/// Traces to: [REQ-OP-001], [INV-002], [NFR-SEC-001]
async fn handle_confirm_pairing(
    State(state): State<WebUiState>,
    headers: HeaderMap,
    Json(payload): Json<ConfirmPairingRequest>,
) -> Response {
    let token_store = match state.token_store.as_ref() {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ConfirmPairingResponse {
                    success: false,
                    token: payload.token,
                    confirmed: false,
                    message: String::new(),
                    error: "Pairing token store is not configured".to_string(),
                }),
            )
                .into_response();
        }
    };

    let pin = payload
        .pin
        .as_deref()
        .or_else(|| headers.get("x-operator-pin").and_then(|v| v.to_str().ok()));
    let conf_token = payload.confirmation_token.as_deref().or_else(|| {
        headers
            .get("x-confirmation-token")
            .and_then(|v| v.to_str().ok())
    });

    let candidate = match pin.or(conf_token) {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ConfirmPairingResponse {
                    success: false,
                    token: payload.token,
                    confirmed: false,
                    message: String::new(),
                    error: "Operator confirmation PIN or token must be provided".to_string(),
                }),
            )
                .into_response();
        }
    };

    match token_store.confirm_token(&payload.token, candidate) {
        Ok(()) => (
            StatusCode::OK,
            Json(ConfirmPairingResponse {
                success: true,
                token: payload.token,
                confirmed: true,
                message: "Pairing session confirmed by operator".to_string(),
                error: String::new(),
            }),
        )
            .into_response(),
        Err(PairingError::TokenNotFound) => (
            StatusCode::NOT_FOUND,
            Json(ConfirmPairingResponse {
                success: false,
                token: payload.token,
                confirmed: false,
                message: String::new(),
                error: "Specified pairing token not found".to_string(),
            }),
        )
            .into_response(),
        Err(PairingError::TokenExpired { .. }) => (
            StatusCode::GONE,
            Json(ConfirmPairingResponse {
                success: false,
                token: payload.token,
                confirmed: false,
                message: String::new(),
                error: "Pairing token has expired".to_string(),
            }),
        )
            .into_response(),
        Err(PairingError::RateLimitExceeded) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ConfirmPairingResponse {
                success: false,
                token: payload.token,
                confirmed: false,
                message: String::new(),
                error: "Rate limit exceeded for pairing confirmation".to_string(),
            }),
        )
            .into_response(),
        Err(PairingError::InvalidConfirmationPin) => (
            StatusCode::UNAUTHORIZED,
            Json(ConfirmPairingResponse {
                success: false,
                token: payload.token,
                confirmed: false,
                message: String::new(),
                error: "Invalid operator confirmation PIN or token".to_string(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::FORBIDDEN,
            Json(ConfirmPairingResponse {
                success: false,
                token: payload.token,
                confirmed: false,
                message: String::new(),
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// Query parameters for /api/pair/qr.png
#[derive(Debug, Deserialize)]
pub struct PairingQrQuery {
    pub token: Option<String>,
}

/// GET /api/pair/qr.png: Serves direct binary PNG image of the pairing QR code.
/// If `?token=<token>` is supplied, validates that the token exists and is active,
/// rendering the QR code with the real expiration timestamp.
/// If `?token=` is omitted, generates a fresh token.
///
/// Traces to: [REQ-OP-001], [INV-002]
async fn handle_pairing_qr_png(
    State(state): State<WebUiState>,
    axum::extract::Query(query): axum::extract::Query<PairingQrQuery>,
) -> Result<Response, (StatusCode, &'static str)> {
    let payload_json = if let Some(ref tok) = query.token {
        let token_store = state.token_store.as_ref().ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            "Pairing token store is not configured or pairing is disabled",
        ))?;

        let record = token_store.get_token(tok).ok_or((
            StatusCode::NOT_FOUND,
            "Specified pairing token not found or already purged",
        ))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();

        if record.expires_at_epoch_s < now || record.is_redeemed {
            return Err((
                StatusCode::GONE,
                "Specified pairing token has expired or has already been redeemed",
            ));
        }

        let payload = PairingPayload {
            cluster_endpoint: state.cluster_endpoint.clone(),
            ca_fingerprint: state.ca_fingerprint.clone(),
            pairing_token: record.token,
            node_id: record.target_node_id,
            expires_at_epoch_s: record.expires_at_epoch_s,
        };
        payload.to_compact_json().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to serialize pairing payload",
            )
        })?
    } else {
        let resp = build_pairing_response(&state, false)?;
        resp.pairing_payload_json
    };

    let png_bytes = render_png_bytes(&payload_json).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to render PNG QR code",
        )
    })?;

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "image/png".parse().expect("Valid header"));
    headers.insert(
        CACHE_CONTROL,
        "no-cache, no-store, must-revalidate"
            .parse()
            .expect("Valid header"),
    );

    Ok((StatusCode::OK, headers, png_bytes).into_response())
}

/// GET /api/apk-info: Returns worker APK download link and QR representation.
///
/// Traces to: [REQ-OP-001]
async fn handle_apk_info(
    State(state): State<WebUiState>,
) -> Result<Json<ApkInfoResponse>, (StatusCode, &'static str)> {
    let qr_png_data_url = render_png_data_url(&state.apk_download_url).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to render APK QR code",
        )
    })?;

    Ok(Json(ApkInfoResponse {
        apk_download_url: state.apk_download_url,
        qr_png_data_url,
    }))
}

/// GET /api/apk/qr.png: Serves direct binary PNG image of the worker APK download link QR.
///
/// Traces to: [REQ-OP-001]
async fn handle_apk_qr_png(
    State(state): State<WebUiState>,
) -> Result<Response, (StatusCode, &'static str)> {
    let png_bytes = render_png_bytes(&state.apk_download_url).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to render APK PNG QR code",
        )
    })?;

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "image/png".parse().expect("Valid header"));
    headers.insert(
        CACHE_CONTROL,
        "public, max-age=86400".parse().expect("Valid header"),
    );

    Ok((StatusCode::OK, headers, png_bytes).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_web_ui_router_dashboard_endpoint() {
        let scheduler = Arc::new(ClusterScheduler::new());
        let token_store = Arc::new(PairingTokenStore::default());
        let state = WebUiState {
            scheduler,
            token_store: Some(token_store),
            ca_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            cluster_endpoint: "192.168.1.100:50051".to_string(),
            apk_download_url: "https://example.com/worker.apk".to_string(),
            pairing_token_ttl_seconds: 300,
            operator_pin: None,
            confirmation_token: None,
        };

        let app = web_ui_router(state);

        let req = Request::builder()
            .uri("/")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn test_web_ui_router_pair_endpoint() {
        let scheduler = Arc::new(ClusterScheduler::new());
        let token_store = Arc::new(PairingTokenStore::default());
        let state = WebUiState {
            scheduler,
            token_store: Some(token_store),
            ca_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            cluster_endpoint: "192.168.1.100:50051".to_string(),
            apk_download_url: "https://example.com/worker.apk".to_string(),
            pairing_token_ttl_seconds: 300,
            operator_pin: None,
            confirmation_token: None,
        };

        let app = web_ui_router(state);

        let req = Request::builder()
            .uri("/api/pair")
            .method("POST")
            .body(Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: PairingWebResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(payload.cluster_endpoint, "192.168.1.100:50051");
        assert_eq!(payload.pairing_token.len(), 64);
        assert!(payload
            .qr_png_data_url
            .starts_with("data:image/png;base64,"));
        assert_eq!(payload.apk_download_url, "https://example.com/worker.apk");
    }

    #[tokio::test]
    async fn test_web_ui_router_pair_qr_png_endpoint() {
        let scheduler = Arc::new(ClusterScheduler::new());
        let token_store = Arc::new(PairingTokenStore::default());
        let state = WebUiState {
            scheduler,
            token_store: Some(token_store),
            ca_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            cluster_endpoint: "192.168.1.100:50051".to_string(),
            apk_download_url: "https://example.com/worker.apk".to_string(),
            pairing_token_ttl_seconds: 300,
            operator_pin: None,
            confirmation_token: None,
        };

        let app = web_ui_router(state);

        let req = Request::builder()
            .uri("/api/pair/qr.png")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(CONTENT_TYPE).unwrap(), "image/png");

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body_bytes[..4], &[0x89, 0x50, 0x4E, 0x47]);
    }

    #[tokio::test]
    async fn test_web_ui_router_apk_info_endpoint() {
        let scheduler = Arc::new(ClusterScheduler::new());
        let token_store = Arc::new(PairingTokenStore::default());
        let state = WebUiState {
            scheduler,
            token_store: Some(token_store),
            ca_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            cluster_endpoint: "192.168.1.100:50051".to_string(),
            apk_download_url: "https://example.com/worker.apk".to_string(),
            pairing_token_ttl_seconds: 300,
            operator_pin: None,
            confirmation_token: None,
        };

        let app = web_ui_router(state);

        let req = Request::builder()
            .uri("/api/apk-info")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: ApkInfoResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(payload.apk_download_url, "https://example.com/worker.apk");
        assert!(payload
            .qr_png_data_url
            .starts_with("data:image/png;base64,"));
    }

    #[tokio::test]
    async fn test_web_ui_router_pair_confirm_endpoint_lifecycle() {
        let scheduler = Arc::new(ClusterScheduler::new());
        let token_store = Arc::new(PairingTokenStore::with_operator_gate(
            true,
            5,
            true,
            Some("123456".to_string()),
            Some("operator-secret".to_string()),
        ));

        let state = WebUiState {
            scheduler,
            token_store: Some(Arc::clone(&token_store)),
            ca_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            cluster_endpoint: "192.168.1.100:50051".to_string(),
            apk_download_url: "https://example.com/worker.apk".to_string(),
            pairing_token_ttl_seconds: 300,
            operator_pin: Some("123456".to_string()),
            confirmation_token: Some("operator-secret".to_string()),
        };

        let app = web_ui_router(state);

        // 1. Unauthenticated POST /api/pair generates unconfirmed token
        let post_req = Request::builder()
            .uri("/api/pair")
            .method("POST")
            .body(Body::empty())
            .unwrap();
        let post_resp = app.clone().oneshot(post_req).await.unwrap();
        assert_eq!(post_resp.status(), StatusCode::OK);
        let post_bytes = axum::body::to_bytes(post_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let pair_data: PairingWebResponse = serde_json::from_slice(&post_bytes).unwrap();
        assert!(!pair_data.confirmed);
        assert!(pair_data.confirmation_pin.is_none());

        // 2. Confirming with invalid PIN yields 401 Unauthorized
        let bad_confirm_req = Request::builder()
            .uri("/api/pair/confirm")
            .method("POST")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_string(&ConfirmPairingRequest {
                    token: pair_data.pairing_token.clone(),
                    pin: Some("999999".to_string()),
                    confirmation_token: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let bad_confirm_resp = app.clone().oneshot(bad_confirm_req).await.unwrap();
        assert_eq!(bad_confirm_resp.status(), StatusCode::UNAUTHORIZED);

        // 3. Confirming with valid operator PIN yields 200 OK
        let good_confirm_req = Request::builder()
            .uri("/api/pair/confirm")
            .method("POST")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_string(&ConfirmPairingRequest {
                    token: pair_data.pairing_token.clone(),
                    pin: Some("123456".to_string()),
                    confirmation_token: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let good_confirm_resp = app.clone().oneshot(good_confirm_req).await.unwrap();
        assert_eq!(good_confirm_resp.status(), StatusCode::OK);
        let good_bytes = axum::body::to_bytes(good_confirm_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let confirm_data: ConfirmPairingResponse = serde_json::from_slice(&good_bytes).unwrap();
        assert!(confirm_data.success);
        assert!(confirm_data.confirmed);

        // 4. Token is now marked confirmed in store
        let confirmed_rec = token_store.get_token(&pair_data.pairing_token).unwrap();
        assert!(confirmed_rec.is_confirmed);
    }
}
