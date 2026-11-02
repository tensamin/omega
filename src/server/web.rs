use crate::server::{api, index::index_handler};
use crate::state::OmegaState;
use http::{Method, StatusCode};
use mtp::webserver::{HttpRequest, HttpResponse, RouteParams, WebServerConfig};
use std::{future::Future, pin::Pin, sync::Arc};

type RouteFuture = Pin<Box<dyn Future<Output = HttpResponse> + Send>>;

struct TransportMetrics;

impl mtp::webserver::WebServerMetrics for TransportMetrics {
    fn error_occurred(&self, error: &mtp::webserver::WebServerError) {
        crate::log_event!(
            0,
            crate::util::logger::PrintType::Omega,
            crate::util::logger::LogLevel::Error,
            "transport.error",
            "error={}",
            error
        );
    }

    fn request_completed(&self, _path: &str, status: u16, duration: std::time::Duration) {
        if status >= 400 {
            crate::log_event!(
                0,
                crate::util::logger::PrintType::Omega,
                crate::util::logger::LogLevel::Warn,
                "transport.request_failed",
                "status={} elapsed_ms={}",
                status,
                duration.as_millis()
            );
        }
    }
}

fn api_handler(
    state: Arc<OmegaState>,
) -> impl Fn(HttpRequest, HttpResponse) -> RouteFuture + Send + Sync + 'static {
    move |request, response| Box::pin(api::handle(request, response, state.clone()))
}

fn api_pattern_handler(
    state: Arc<OmegaState>,
) -> impl Fn(HttpRequest, HttpResponse, RouteParams) -> RouteFuture + Send + Sync + 'static {
    move |request, response, params| {
        Box::pin(api::handle_pattern(
            request,
            response,
            params,
            state.clone(),
        ))
    }
}

pub fn build_web_config(
    state: Arc<OmegaState>,
) -> Result<WebServerConfig, mtp::webserver::RouterError> {
    WebServerConfig::new()
        .with_metrics(Arc::new(TransportMetrics))
        .route("/.well-known/tensamin", api_handler(state.clone()))?
        .route("/api/download/iota_frontend", api_handler(state.clone()))?
        .route("/api/get/omikron", api_handler(state.clone()))?
        .route("/api/get/public_key", api_handler(state.clone()))?
        .route_pattern("/api/get/omikron/{id}", api_pattern_handler(state.clone()))?
        .route_pattern(
            "/api/get/registration-omikron/{id}",
            api_pattern_handler(state.clone()),
        )?
        .route_pattern("/api/get/iota/{id}", api_pattern_handler(state.clone()))?
        .route_pattern("/api/get/id/{username}", api_pattern_handler(state.clone()))?
        .route_pattern("/api/get/user/{id}", api_pattern_handler(state.clone()))?
        .route_pattern(
            "/federation/v1/users/id/{id}",
            api_pattern_handler(state.clone()),
        )?
        .route_pattern(
            "/federation/v1/users/name/{username}",
            api_pattern_handler(state.clone()),
        )?
        .route_pattern(
            "/federation/v1/iotas/{id}/node",
            api_pattern_handler(state.clone()),
        )?
        .route_pattern("/direct/{short}", api_pattern_handler(state.clone()))?
        .fallback(move |request, response| {
            let state = state.clone();
            async move {
                if request.uri.path() == "/api" || request.uri.path().starts_with("/api/") {
                    return api::handle(request, response, state).await;
                }
                if request.method == Method::OPTIONS {
                    return crate::server::with_cors(response.status(StatusCode::NO_CONTENT));
                }

                index_handler(response)
            }
        })
}
