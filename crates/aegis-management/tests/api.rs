#![allow(clippy::panic)]
//! Management API contract tests: TC-A01, TC-A02, TC-A03, TC-A05, TC-PRIV06,
//! TC-V13.

use aegis_config::parse_toml;
use aegis_contracts::capability::OsFamily;
use aegis_contracts::observability::NoopObservability;
use aegis_contracts::Role;
use aegis_core::{AdmissionGate, AgentCell, CapabilityEnv, Coordinator, NoFailPoints};
use aegis_identity::pki;
use aegis_identity::{IdentitySnapshot, IdentityStore};
use aegis_management::{router, ManagementContext};
use aegis_platform::host_vpn_capabilities;
use aegis_storage::Store;
use aegis_telemetry::{CoreGauges, DiagnosticSink, LocalMetrics};
use axum::body::Body;
use http::{header, Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const GATEWAY: &str = r#"
schema_version = "0.1"
node_id = "gw-1"
role = "gateway"
[identity]
peer_auth = "mutual_tls_1_3"
server_identity = "secret://identity/server-cert"
server_private_key = "secret://identity/server-key"
trusted_client_ca = "secret://identity/client-ca"
[[inbounds]]
id = "ws"
kind = "websocket"
bind = "127.0.0.1:18080"
[[outbounds]]
id = "egress"
kind = "direct_tcp"
[routing]
default_outbound = "egress"
default_action = "deny"
[[routing.rules]]
id = "public"
match = "authenticated-and-public-destination"
action = "proxy"
outbound = "egress"
[dns]
mode = "remote_required"
ipv6_policy = "follow-routing-policy"
resolver = "system"
"#;

const HOST: &str = "127.0.0.1:9080";

struct T {
    _dir: tempfile::TempDir,
    ctx: Arc<ManagementContext>,
    app: axum::Router,
}

fn env() -> Arc<CapabilityEnv> {
    let os = OsFamily::Linux;
    Arc::new(CapabilityEnv::new(
        aegis_node_registry(os),
        host_vpn_capabilities(os),
    ))
}

// Same module set as the node's composition root (kept local to avoid a
// management -> node dependency).
fn aegis_node_registry(os: OsFamily) -> aegis_platform::Registry {
    use aegis_config::ModuleIds;
    use aegis_contracts::capability::{Capability::*, Maturity, ModuleDescriptor, ResourceBudget};
    let mk = |id: &'static str,
              provides: &'static [aegis_contracts::Capability],
              requires: &'static [aegis_contracts::Capability]| ModuleDescriptor {
        module_id: id,
        module_version: "0.1.0",
        api_version: 1,
        roles: &[Role::Client, Role::Gateway],
        operating_systems: &[OsFamily::Linux, OsFamily::Windows, OsFamily::Macos],
        provides,
        requires,
        budget: ResourceBudget::default(),
        maturity: Maturity::Experimental,
        conformance_hash: "",
    };
    let mut r = aegis_platform::Registry::new(os);
    for d in [
        mk(
            ModuleIds::WEBSOCKET,
            &[ByteStream, HttpReverseProxyCompatible],
            &[],
        ),
        mk(ModuleIds::MTLS, &[InnerMutualTls], &[ByteStream]),
        mk(
            ModuleIds::SESSION,
            &[ConnectionMultiplexing],
            &[InnerMutualTls],
        ),
        mk(ModuleIds::SOCKS5, &[ByteStream], &[]),
        mk(ModuleIds::HTTP_CONNECT, &[ByteStream], &[]),
        mk(ModuleIds::DIRECT, &[ByteStream, EgressAcl], &[]),
        mk(ModuleIds::TUNNEL, &[ByteStream], &[ConnectionMultiplexing]),
    ] {
        r.register(d).expect("register");
    }
    r
}

fn setup(with_ca: bool) -> T {
    let dir = tempfile::tempdir().expect("tmp");
    let store = Arc::new(Store::open(dir.path().join("s.db")).expect("store"));
    let gate = AdmissionGate::new(IdentityStore::new(IdentitySnapshot::default()));
    let coord = Arc::new(Coordinator::new(
        store,
        gate,
        env(),
        Arc::new(AgentCell::default()),
        "gw-1".into(),
        Role::Gateway,
        Arc::new(NoFailPoints),
        Arc::new(NoopObservability),
    ));
    coord.recover().expect("recover");
    coord
        .import_initial(&parse_toml(GATEWAY).expect("cfg"))
        .expect("import");
    let ca = with_ca.then(|| pki::generate_ca("api-ca", pki::DEFAULT_CA_VALIDITY).expect("ca"));
    let ctx = ManagementContext::new(
        coord,
        Arc::new(LocalMetrics::new(None)),
        Arc::new(CoreGauges::default),
        Arc::new(DiagnosticSink::new()),
        ca,
        dir.path().join("secrets"),
        HOST.parse().expect("addr"),
        vec![],
    );
    let app = router(Arc::clone(&ctx));
    T {
        _dir: dir,
        ctx,
        app,
    }
}

struct Resp {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Value,
}

async fn call(app: &axum::Router, req: Request<Body>) -> Resp {
    let r = app.clone().oneshot(req).await.expect("response");
    let status = r.status();
    let headers = r.headers().clone();
    let bytes = axum::body::to_bytes(r.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Resp {
        status,
        headers,
        body,
    }
}

fn req(method: &str, path: &str) -> http::request::Builder {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
}

fn json_body(v: &Value) -> Body {
    Body::from(serde_json::to_vec(v).expect("json"))
}

/// Bootstrap the owner and log in. Returns (cookie header, csrf token).
async fn owner_session(t: &T) -> (String, String) {
    let (token, _) = t.ctx.create_bootstrap_token().expect("bootstrap token");
    let r = call(
        &t.app,
        req("POST", "/api/v1/bootstrap/claim")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&json!({"bootstrap_token": token, "owner_username": "owner", "owner_password": "correct horse battery staple"})))
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let r = call(
        &t.app,
        req("POST", "/api/v1/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(
                &json!({"username": "owner", "password": "correct horse battery staple"}),
            ))
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let cookie = r
        .headers
        .get(header::SET_COOKIE)
        .expect("cookie")
        .to_str()
        .expect("str")
        .to_owned();
    assert!(
        cookie.contains("HttpOnly")
            && cookie.contains("Secure")
            && cookie.contains("SameSite=Strict")
    );
    assert_eq!(
        r.headers
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap_or("")),
        Some("no-store")
    );
    let session = cookie.split(';').next().expect("kv").to_owned();
    (
        session,
        r.body["csrf_token"].as_str().expect("csrf").to_owned(),
    )
}

#[tokio::test]
async fn tc_a02_bootstrap_is_one_use_and_login_rate_limited() {
    let t = setup(false);
    let (token, _) = t.ctx.create_bootstrap_token().expect("token");
    let claim = |tok: &str, user: &str| {
        req("POST", "/api/v1/bootstrap/claim")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&json!({"bootstrap_token": tok, "owner_username": user, "owner_password": "a long enough password"})))
            .expect("req")
    };
    assert_eq!(
        call(&t.app, claim("wrong-token", "owner")).await.status,
        StatusCode::UNAUTHORIZED
    );
    let short = req("POST", "/api/v1/bootstrap/claim")
        .header(header::CONTENT_TYPE, "application/json")
        .body(json_body(
            &json!({"bootstrap_token": token, "owner_username": "o", "owner_password": "short"}),
        ))
        .expect("req");
    assert_eq!(call(&t.app, short).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        call(&t.app, claim(&token, "owner")).await.status,
        StatusCode::CREATED
    );
    // Reuse after first claim: endpoint permanently disabled.
    assert_eq!(
        call(&t.app, claim(&token, "second")).await.status,
        StatusCode::CONFLICT
    );
    assert!(
        t.ctx.create_bootstrap_token().is_err(),
        "no new bootstrap tokens once an owner exists"
    );
    // Lockout after repeated failures.
    let bad = || {
        req("POST", "/api/v1/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&json!({"username": "owner", "password": "nope"})))
            .expect("req")
    };
    for _ in 0..5 {
        assert_eq!(call(&t.app, bad()).await.status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        call(&t.app, bad()).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn tc_a02_host_origin_cors_and_headers() {
    let t = setup(false);
    let r = call(
        &t.app,
        Request::builder()
            .uri("/api/v1/system/health")
            .header(header::HOST, "evil.example:9080")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.body["aegis_error_code"], "host_not_allowed");
    let r = call(
        &t.app,
        req("GET", "/api/v1/system/health")
            .header(header::ORIGIN, "http://evil.example")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = call(
        &t.app,
        req("OPTIONS", "/api/v1/profiles")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(
        r.headers.get("access-control-allow-origin").is_none(),
        "no CORS"
    );
    let r = call(
        &t.app,
        req("GET", "/api/v1/system/health")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        r.headers.get(header::CONTENT_TYPE).expect("ct"),
        "application/problem+json"
    );
    assert!(r.body["correlation_id"].as_str().is_some());
    let ui = call(&t.app, req("GET", "/").body(Body::empty()).expect("req")).await;
    assert_eq!(ui.status, StatusCode::OK);
    let csp = ui
        .headers
        .get("content-security-policy")
        .expect("csp")
        .to_str()
        .expect("str");
    assert!(csp.contains("frame-ancestors 'none'") && csp.contains("script-src 'self'"));
    assert_eq!(ui.headers.get("x-frame-options").expect("xfo"), "DENY");
}

#[tokio::test]
async fn tc_a02_csrf_required_for_cookie_mutations() {
    let t = setup(false);
    let (cookie, csrf) = owner_session(&t).await;
    let body = json!({"role": "agent"});
    let no_csrf = req("POST", "/api/v1/nodes/enrollment")
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(json_body(&body))
        .expect("req");
    assert_eq!(call(&t.app, no_csrf).await.status, StatusCode::FORBIDDEN);
    let wrong = req("POST", "/api/v1/nodes/enrollment")
        .header(header::COOKIE, &cookie)
        .header("x-csrf-token", "x".repeat(csrf.len()))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json_body(&body))
        .expect("req");
    assert_eq!(call(&t.app, wrong).await.status, StatusCode::FORBIDDEN);
    let ok = req("POST", "/api/v1/nodes/enrollment")
        .header(header::COOKIE, &cookie)
        .header("x-csrf-token", &csrf)
        .header(header::CONTENT_TYPE, "application/json")
        .body(json_body(&body))
        .expect("req");
    let r = call(&t.app, ok).await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert!(r.body["token"].as_str().is_some_and(|s| s.len() >= 32));
    // After logout the session (and its CSRF token) are dead.
    let lo = req("POST", "/api/v1/auth/logout")
        .header(header::COOKIE, &cookie)
        .header("x-csrf-token", &csrf)
        .body(Body::empty())
        .expect("req");
    assert_eq!(call(&t.app, lo).await.status, StatusCode::NO_CONTENT);
    let me = req("GET", "/api/v1/auth/me")
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .expect("req");
    assert_eq!(call(&t.app, me).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tc_a01_a03_profile_validate_activate_flow() {
    let t = setup(false);
    let (cookie, csrf) = owner_session(&t).await;
    let get = |path: &str| {
        req("GET", path)
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("req")
    };
    let list = call(&t.app, get("/api/v1/profiles")).await;
    assert_eq!(list.status, StatusCode::OK);
    assert!(
        list.body["items"][0].get("specification").is_none(),
        "summaries exclude payloads"
    );
    let id = list.body["items"][0]["id"].as_str().expect("id").to_owned();
    let p = call(&t.app, get(&format!("/api/v1/profiles/{id}"))).await;
    let etag = p
        .headers
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("str")
        .to_owned();
    assert!(etag.starts_with('"') && etag.ends_with('"'));
    let patch = |if_match: Option<&str>, body: Value| {
        let mut b = req("PATCH", &format!("/api/v1/profiles/{id}"))
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header(header::CONTENT_TYPE, "application/merge-patch+json");
        if let Some(m) = if_match {
            b = b.header(header::IF_MATCH, m);
        }
        b.body(json_body(&body)).expect("req")
    };
    let change = json!({"specification": {"routing": {"default_action": "proxy"}}});
    assert_eq!(
        call(&t.app, patch(None, change.clone())).await.status,
        StatusCode::PRECONDITION_REQUIRED
    );
    assert_eq!(
        call(&t.app, patch(Some("\"stale\""), change.clone()))
            .await
            .status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        call(&t.app, patch(Some("*"), change.clone())).await.status,
        StatusCode::BAD_REQUEST
    );
    let invalid = json!({"specification": {"transport": {"allow_insecure_fallback": true}}});
    let r = call(&t.app, patch(Some(&etag), invalid)).await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "a draft may be saved; validation rejects it later"
    );
    let etag = r
        .headers
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("s")
        .to_owned();
    let desired = r.body["desired_revision_id"]
        .as_str()
        .expect("rev")
        .to_owned();
    let validate = |if_match: &str, rev: &str| {
        req("POST", &format!("/api/v1/profiles/{id}/validate"))
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header(header::IF_MATCH, if_match)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&json!({"target_revision_id": rev})))
            .expect("req")
    };
    let rep = call(&t.app, validate(&etag, &desired)).await;
    assert_eq!(rep.status, StatusCode::OK);
    assert_eq!(rep.body["valid"], false);
    assert!(rep.body["errors"]
        .as_array()
        .expect("errors")
        .iter()
        .any(|e| e.as_str().unwrap_or("").contains("allow_insecure_fallback")));
    // Fix it and validate again.
    let r = call(&t.app, patch(Some(&etag), json!({"specification": {"transport": {"allow_insecure_fallback": false}, "routing": {"default_action": "proxy"}}}))).await;
    let etag = r
        .headers
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("s")
        .to_owned();
    let desired = r.body["desired_revision_id"]
        .as_str()
        .expect("rev")
        .to_owned();
    let rep = call(&t.app, validate(&etag, &desired)).await;
    assert_eq!(rep.body["valid"], true, "{:?}", rep.body);
    let activate = |key: Option<&str>| {
        let mut b = req("POST", &format!("/api/v1/profiles/{id}/activate"))
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header(header::IF_MATCH, &etag)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(k) = key {
            b = b.header("idempotency-key", k);
        }
        b.body(json_body(&json!({
            "target_revision_id": rep.body["target_revision_id"],
            "config_digest": rep.body["config_digest"],
            "validation_id": rep.body["validation_id"],
        })))
        .expect("req")
    };
    assert_eq!(
        call(&t.app, activate(None)).await.status,
        StatusCode::PRECONDITION_REQUIRED
    );
    let accepted = call(&t.app, activate(Some("api-test-key-000001"))).await;
    assert_eq!(accepted.status, StatusCode::ACCEPTED, "{:?}", accepted.body);
    let job_id = accepted.body["id"].as_str().expect("job").to_owned();
    assert_eq!(
        accepted.headers.get(header::LOCATION).expect("loc"),
        &format!("/api/v1/jobs/{job_id}")
    );
    let again = call(&t.app, activate(Some("api-test-key-000001"))).await;
    assert_eq!(
        again.body["id"], accepted.body["id"],
        "idempotent retry returns the same job"
    );
    let mut status = String::new();
    for _ in 0..50 {
        let j = call(&t.app, get(&format!("/api/v1/jobs/{job_id}"))).await;
        status = j.body["status"].as_str().unwrap_or("").to_owned();
        if status == "succeeded" {
            assert_eq!(j.body["commit_state"], "applied");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(status, "succeeded");
    let h = call(&t.app, get("/api/v1/system/health")).await;
    assert_eq!(
        h.body["applied_revision_id"],
        rep.body["target_revision_id"]
    );
    // Revision history and explain.
    let revs = call(
        &t.app,
        get(&format!("/api/v1/profiles/{id}/revisions?limit=2")),
    )
    .await;
    assert_eq!(revs.body["items"].as_array().expect("items").len(), 2);
    let cursor = revs.body["next_cursor"]
        .as_str()
        .expect("cursor")
        .to_owned();
    let page2 = call(
        &t.app,
        get(&format!(
            "/api/v1/profiles/{id}/revisions?limit=2&cursor={cursor}"
        )),
    )
    .await;
    assert_eq!(page2.status, StatusCode::OK);
    assert_eq!(
        call(
            &t.app,
            get(&format!("/api/v1/profiles/{id}/revisions?cursor=bogus"))
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&t.app, get("/api/v1/profiles?limit=0")).await.status,
        StatusCode::BAD_REQUEST
    );
    let explain = req("POST", "/api/v1/diagnostics/explain")
        .header(header::COOKIE, &cookie)
        .header("x-csrf-token", &csrf)
        .header(header::CONTENT_TYPE, "application/json")
        .body(json_body(&json!({"profile_id": id, "revision_id": rep.body["target_revision_id"], "destination_host": "10.0.0.1", "destination_port": 443, "protocol": "tcp"})))
        .expect("req");
    let e = call(&t.app, explain).await;
    assert_eq!(e.status, StatusCode::OK);
    assert_eq!(
        e.body["action"], "deny",
        "private literal denied by egress policy: {:?}",
        e.body
    );
}

#[tokio::test]
async fn tc_a05_scoped_bearer_and_object_access() {
    let t = setup(false);
    let _ = owner_session(&t).await;
    let (token, _) = t
        .ctx
        .mint_bearer(
            Some(vec!["profiles:read".into()]),
            std::time::Duration::from_secs(60),
        )
        .expect("bearer");
    let bearer = format!("Bearer {token}");
    let r = call(
        &t.app,
        req("GET", "/api/v1/profiles")
            .header(header::AUTHORIZATION, &bearer)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = call(
        &t.app,
        req("GET", "/api/v1/telemetry/settings")
            .header(header::AUTHORIZATION, &bearer)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::FORBIDDEN,
        "aggregate read cannot view/change export settings"
    );
    let r = call(
        &t.app,
        req("GET", "/api/v1/audit")
            .header(header::AUTHORIZATION, &bearer)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Bearer mutations need no CSRF token but still need permission.
    let r = call(
        &t.app,
        req("POST", "/api/v1/nodes/enrollment")
            .header(header::AUTHORIZATION, &bearer)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&json!({"role": "agent"})))
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(t
        .ctx
        .mint_bearer(
            Some(vec!["superuser".into()]),
            std::time::Duration::from_secs(60)
        )
        .is_err());
    // Unknown jobs are indistinguishable from forbidden ones.
    let r = call(
        &t.app,
        req("GET", &format!("/api/v1/jobs/{}", uuid_like()))
            .header(header::AUTHORIZATION, &bearer)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

fn uuid_like() -> String {
    "00000000-0000-4000-8000-000000000000".into()
}

#[tokio::test]
async fn tc_priv06_export_requires_permission_etag_and_preview() {
    let t = setup(false);
    let (cookie, csrf) = owner_session(&t).await;
    let get = call(
        &t.app,
        req("GET", "/api/v1/telemetry/settings")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(get.status, StatusCode::OK);
    assert_eq!(get.body["export_enabled"], false);
    assert_eq!(get.body["export_profile"], "off");
    let etag = get
        .headers
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("s")
        .to_owned();
    let enable = json!({"export_enabled": true, "export_profile": "coarse_export", "collector_url": "https://127.0.0.1:9/v1/metrics", "service_name": "network-runtime"});
    let patch = |if_match: &str, digest: Option<&str>, body: &Value| {
        let mut b = req("PATCH", "/api/v1/telemetry/settings")
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header(header::IF_MATCH, if_match)
            .header(header::CONTENT_TYPE, "application/merge-patch+json");
        if let Some(d) = digest {
            b = b.header("x-aegis-export-preview-digest", d);
        }
        b.body(json_body(body)).expect("req")
    };
    let r = call(&t.app, patch(&etag, None, &enable)).await;
    assert_eq!(
        (r.status, r.body["aegis_error_code"].as_str()),
        (StatusCode::CONFLICT, Some("preview_required"))
    );
    let bad_url = json!({"export_enabled": true, "export_profile": "coarse_export", "collector_url": "http://collector.example/v1/metrics", "service_name": "x"});
    assert_eq!(
        call(&t.app, patch(&etag, None, &bad_url)).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let pv = call(
        &t.app,
        req(
            "GET",
            "/api/v1/telemetry/preview?service_name=network-runtime&collector_url=https%3A%2F%2F127.0.0.1%3A9%2Fv1%2Fmetrics",
        )
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .expect("req"),
    )
    .await;
    assert_eq!(pv.status, StatusCode::OK);
    let text = pv.body["payload"].to_string();
    assert!(!text.contains("vpn") && !text.contains("proxy") && !text.contains("host.name"));
    let digest = pv.body["preview_digest"]
        .as_str()
        .expect("digest")
        .to_owned();
    let r = call(&t.app, patch(&etag, Some(&digest), &enable)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["export_enabled"], true);
    // Stale write.
    assert_eq!(
        call(
            &t.app,
            patch(&etag, Some(&digest), &json!({"export_enabled": false}))
        )
        .await
        .status,
        StatusCode::PRECONDITION_FAILED
    );
    // A profile cannot enable export (validated as a config error).
    let profiles = call(
        &t.app,
        req("GET", "/api/v1/profiles")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    let id = profiles.body["items"][0]["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let p = call(
        &t.app,
        req("GET", &format!("/api/v1/profiles/{id}"))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    let petag = p
        .headers
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("s")
        .to_owned();
    let r = call(
        &t.app,
        req("PATCH", &format!("/api/v1/profiles/{id}"))
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header(header::IF_MATCH, &petag)
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(
                &json!({"specification": {"telemetry": {"otlp_export_enabled": true}}}),
            ))
            .expect("req"),
    )
    .await;
    let petag = r
        .headers
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("s")
        .to_owned();
    let rev = r.body["desired_revision_id"]
        .as_str()
        .expect("rev")
        .to_owned();
    let v = call(
        &t.app,
        req("POST", &format!("/api/v1/profiles/{id}/validate"))
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header(header::IF_MATCH, &petag)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&json!({"target_revision_id": rev})))
            .expect("req"),
    )
    .await;
    assert_eq!(v.body["valid"], false);
}

#[tokio::test]
async fn enrollment_redeem_is_one_use() {
    let t = setup(true);
    let (cookie, csrf) = owner_session(&t).await;
    let r = call(
        &t.app,
        req("POST", "/api/v1/nodes/enrollment")
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(
                &json!({"role": "agent", "expires_in_seconds": 120, "node_name":"laptop-9"}),
            ))
            .expect("req"),
    )
    .await;
    let token = r.body["token"].as_str().expect("token").to_owned();
    let (_key, csr) = pki::generate_key_and_csr("laptop-9").expect("csr");
    let redeem = |name: &str| {
        req("POST", "/api/v1/nodes/enrollment/redeem")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(
                &json!({"token": token, "node_name": name, "csr_pem": csr}),
            ))
            .expect("req")
    };
    let ok = call(&t.app, redeem("laptop-9")).await;
    assert_eq!(ok.status, StatusCode::CREATED, "{:?}", ok.body);
    assert!(ok.body["certificate_pem"]
        .as_str()
        .expect("cert")
        .contains("BEGIN CERTIFICATE"));
    assert!(
        ok.body.get("private_key").is_none(),
        "no private key is ever returned"
    );
    assert_eq!(
        call(&t.app, redeem("laptop-10")).await.status,
        StatusCode::UNAUTHORIZED,
        "used invitation rejected"
    );
    // The enrolled node is listed and revocable via the async job.
    let nodes = call(
        &t.app,
        req("GET", "/api/v1/nodes")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    let node_id = nodes.body["items"][0]["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let n = call(
        &t.app,
        req("GET", &format!("/api/v1/nodes/{node_id}"))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    let netag = n
        .headers
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("s")
        .to_owned();
    let rv = call(
        &t.app,
        req("POST", &format!("/api/v1/nodes/{node_id}/revoke"))
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header(header::IF_MATCH, &netag)
            .header("idempotency-key", "revoke-key-0000001")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(rv.status, StatusCode::ACCEPTED, "{:?}", rv.body);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let n = call(
        &t.app,
        req("GET", &format!("/api/v1/nodes/{node_id}"))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(n.body["status"], "revoked");
}

#[tokio::test]
async fn tc_v13_vpn_surface_is_read_only_and_honest() {
    let t = setup(false);
    let (cookie, csrf) = owner_session(&t).await;
    let caps = call(
        &t.app,
        req("GET", "/api/v1/network/vpn/capabilities")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(caps.status, StatusCode::OK);
    let modes = caps.body["modes"].as_array().expect("modes");
    assert_eq!(modes.len(), 4);
    assert!(modes.iter().all(|m| m["support"] == "unsupported"));
    let st = call(
        &t.app,
        req("GET", "/api/v1/network/vpn/status")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(
        st.body["kill_switch"], "unavailable",
        "observed state, not desired config"
    );
    let apps = call(
        &t.app,
        req("GET", "/api/v1/network/apps")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(apps.body["items"], json!([]));
    let profiles = call(
        &t.app,
        req("GET", "/api/v1/profiles")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    let rev = profiles.body["items"][0]["active_revision_id"]
        .as_str()
        .expect("rev")
        .to_owned();
    let pv = call(
        &t.app,
        req("POST", "/api/v1/network/policy/preview")
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&json!({"revision_id": rev, "target_node_id": uuid_like(), "flows": [{"protocol": "tcp", "remote_address": "1.1.1.1", "remote_port": 443}]})))
            .expect("req"),
    )
    .await;
    assert_eq!(
        pv.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "gateway revision has no system_vpn section"
    );
}

#[tokio::test]
async fn body_limit_and_media_type_enforced() {
    let t = setup(false);
    let (cookie, csrf) = owner_session(&t).await;
    let big = vec![b' '; 2 * 1024 * 1024];
    let r = call(
        &t.app,
        req("POST", "/api/v1/profiles")
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(big))
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let r = call(
        &t.app,
        req("POST", "/api/v1/profiles")
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("{}"))
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // Audit never records credentials.
    let a = call(
        &t.app,
        req("GET", "/api/v1/audit")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    let text = a.body.to_string();
    assert!(!text.contains("correct horse"));
    assert!(text.contains("bootstrap.claim"));
}

#[tokio::test]
async fn tunnel_only_refuses_direct_addresses_and_early_invitations() {
    let t = setup(true);
    let (cookie, csrf) = owner_session(&t).await;
    let send = |method: &str, path: &str, body: Value| {
        req(method, path)
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .expect("req")
    };
    let direct = json!({"public_host": "203.0.113.7", "public_port": 8444});
    t.ctx.set_tunnel_only(true);
    let r = call(
        &t.app,
        send("PUT", "/api/v1/system/connection", direct.clone()),
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert_eq!(r.body["aegis_error_code"], "tunnel_only");
    // An address set before (or by a direct install) still can't be used
    // for invitations while the tunnel isn't the device path.
    t.ctx.set_tunnel_only(false);
    let r = call(&t.app, send("PUT", "/api/v1/system/connection", direct)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    t.ctx.set_tunnel_only(true);
    let r = call(
        &t.app,
        send("POST", "/api/v1/devices/invite", json!({"name": "laptop"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert_eq!(r.body["aegis_error_code"], "tunnel_not_ready");
    let info = req("GET", "/api/v1/system/info")
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .expect("req");
    let r = call(&t.app, info).await;
    assert_eq!(r.body["tunnel_only"], true);
    assert_eq!(
        r.body["checklist"]["server_address_set"], false,
        "a direct address doesn't count"
    );
}
