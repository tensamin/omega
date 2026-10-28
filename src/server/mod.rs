pub mod api;
pub mod index;
pub mod middleware;
pub mod short_link;
pub mod validation;
pub mod web;

use mtp::webserver::HttpResponse;

pub(crate) fn with_cors(response: HttpResponse) -> HttpResponse {
    response
        .header("access-control-allow-origin", crate::config::cors_origin())
        .header("access-control-allow-methods", "GET, POST, OPTIONS")
        .header("access-control-allow-headers", "*")
        .header("access-control-expose-headers", "x-request-id")
        .header("access-control-allow-private-network", "true")
}

#[cfg(test)]
mod tests {
    use super::with_cors;
    use mtp::webserver::HttpResponse;

    #[test]
    fn web_responses_allow_all_origins() {
        let response = with_cors(HttpResponse::default());
        assert_eq!(response.headers["access-control-allow-origin"], "*");
        assert_eq!(
            response.headers["access-control-allow-methods"],
            "GET, POST, OPTIONS"
        );
        assert_eq!(response.headers["access-control-allow-headers"], "*");
        assert_eq!(
            response.headers["access-control-allow-private-network"],
            "true"
        );
    }
}
