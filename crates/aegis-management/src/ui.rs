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
