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
use crate::pairing::{render_png_bytes, render_png_data_url, PairingPayload, PairingTokenStore};
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

/// Generates a fresh ephemeral pairing token and returns the full pairing response.
fn build_pairing_response(
    state: &WebUiState,
) -> Result<PairingWebResponse, (StatusCode, &'static str)> {
    let token_store = state.token_store.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Pairing token store is not configured or pairing is disabled",
    ))?;

    let record = token_store.generate_token(None, Some(300)).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate pairing token",
        )
    })?;

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
    })
}

/// GET /api/pair: Generates or retrieves an ephemeral device pairing token with QR representation.
///
/// Traces to: [REQ-OP-001], [INV-002]
async fn handle_get_pairing(
    State(state): State<WebUiState>,
) -> Result<Json<PairingWebResponse>, (StatusCode, &'static str)> {
    let resp = build_pairing_response(&state)?;
    Ok(Json(resp))
}

/// POST /api/pair: Generates a new ephemeral device pairing token with QR representation.
///
/// Traces to: [REQ-OP-001], [INV-002]
async fn handle_post_pairing(
    State(state): State<WebUiState>,
) -> Result<Json<PairingWebResponse>, (StatusCode, &'static str)> {
    let resp = build_pairing_response(&state)?;
    Ok(Json(resp))
}

/// GET /api/pair/qr.png: Serves direct binary PNG image of the pairing QR code.
///
/// Traces to: [REQ-OP-001], [INV-002]
async fn handle_pairing_qr_png(
    State(state): State<WebUiState>,
) -> Result<Response, (StatusCode, &'static str)> {
    let resp = build_pairing_response(&state)?;
    let png_bytes = render_png_bytes(&resp.pairing_payload_json).map_err(|_| {
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
        };

        let app = web_ui_router(state);

        let req = Request::builder()
            .uri("/api/pair")
            .method("GET")
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
}
