//! Static admin UI, bundled into the binary (no runtime CDN assets).

use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use http::header;

const INDEX: &str = include_str!("../../../apps/aegis-ui/index.html");
const APP_JS: &str = include_str!("../../../apps/aegis-ui/app.js");
const STYLE: &str = include_str!("../../../apps/aegis-ui/style.css");

fn asset(content_type: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

/// The same pages for the user portal, which lives under `/portal/`.
fn portal_index() -> &'static str {
    static INDEX_PORTAL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    INDEX_PORTAL.get_or_init(|| {
        INDEX
            .replace("href=\"/style.css\"", "href=\"/portal/style.css\"")
            .replace("src=\"/app.js\"", "src=\"/portal/app.js\"")
            .replace(
                "<title>AegisBorne Console</title>",
                "<title>AegisBorne</title>",
            )
    })
}

pub fn portal_routes<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route(
            "/",
            get(|| async { asset("text/html; charset=utf-8", portal_index()) }),
        )
        .route(
            "/app.js",
            get(|| async { asset("text/javascript; charset=utf-8", APP_JS) }),
        )
        .route(
            "/style.css",
            get(|| async { asset("text/css; charset=utf-8", STYLE) }),
        )
}

pub fn routes<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route(
            "/",
            get(|| async { asset("text/html; charset=utf-8", INDEX) }),
        )
        .route(
            "/app.js",
            get(|| async { asset("text/javascript; charset=utf-8", APP_JS) }),
        )
        .route(
            "/style.css",
            get(|| async { asset("text/css; charset=utf-8", STYLE) }),
        )
}
