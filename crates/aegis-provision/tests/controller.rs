use aegis_provision::{cloudflare::NoProvider, host, secrets::SecretStore, *};
use aegis_storage::Store;
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn desired() -> DesiredDeployment {
    DesiredDeployment {
        schema_version: 1,
        deployment_id: "b8279db0-b592-42f0-b264-234567890abc".into(),
        mode: Mode::LocalPrivate,
        host: HostKind::Compose,
        origin_service: None,
        node_id: "gateway".into(),
        inner_server_name: "gateway.aegis.internal".into(),
        hostname: None,
        account_id: None,
        zone_id: None,
        gateway_image: format!("example.invalid/aegis:0.1@sha256:{}", "a".repeat(64)),
        connector_image: None,
        nameservers: vec!["1.1.1.1:53".into()],
        verification_http_url: "http://example.test/".into(),
        verification_https_url: "https://example.test/".into(),
        acme: None,
        outer_trust_ca: None,
        nginx_image: None,
    }
}
struct Host {
    calls: AtomicUsize,
    fail: bool,
}
impl HostProvisioner for Host {
    fn apply<'a>(&'a self, _: &'a Plan, token: Option<&'a str>) -> StepFuture<'a, ()> {
        Box::pin(async move {
            assert!(token.is_none());
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(Error("host_fault"))
            } else {
                Ok(())
            }
        })
    }
    fn verify<'a>(&'a self, _: &'a Plan) -> StepFuture<'a, String> {
        Box::pin(async { Ok("verified-runtime-revision".into()) })
    }
    fn remove<'a>(&'a self, _: &'a Plan) -> StepFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}
struct Proof(bool);
impl Probe for Proof {
    fn verify<'a>(&'a self, _: &'a Plan) -> StepFuture<'a, Verification> {
        Box::pin(async move {
            Ok(Verification {
                provider_objects: self.0,
                connector: self.0,
                public_dns: self.0,
                wss: self.0,
                inner_mtls: self.0,
                socks_http: self.0,
                socks_https: self.0,
            })
        })
    }
}
#[test]
fn deterministic_plan_and_actor_isolation() {
    let c = Controller::new(Arc::new(Store::open_in_memory().expect("db")));
    let p = c.plan(desired(), "owner", None).expect("plan");
    let q = c.plan(desired(), "owner", None).expect("same plan");
    assert_eq!(p.id, q.id);
    assert_eq!(p.etag(), q.etag());
    assert!(c.get(&p.id, "other").is_err());
    assert!(c.list("other").expect("list").is_empty());
    assert_ne!(
        c.plan(desired(), "owner", Some("different-base".into()))
            .expect("new plan")
            .id,
        p.id
    );
}
#[tokio::test]
async fn active_requires_real_probe_evidence_and_reapply_has_no_host_mutation() {
    let c = Controller::new(Arc::new(Store::open_in_memory().expect("db")));
    let p = c.plan(desired(), "owner", None).expect("plan");
    let host = Host {
        calls: AtomicUsize::new(0),
        fail: false,
    };
    let err = c
        .apply(
            &p.id,
            "owner",
            &p.etag(),
            None,
            &NoProvider,
            &host,
            &Proof(false),
        )
        .await
        .expect_err("probe denied");
    assert_eq!(err.0, "data_path_not_verified");
    let p = c.get(&p.id, "owner").expect("persisted");
    assert_eq!(p.state, PlanState::RecoveryRequired);
    assert!(!p.inventory.verified);
    let active = c
        .apply(
            &p.id,
            "owner",
            &p.etag(),
            None,
            &NoProvider,
            &host,
            &Proof(true),
        )
        .await
        .expect("verified apply");
    assert_eq!(active.state, PlanState::Active);
    assert!(active.inventory.verified);
    let before = host.calls.load(Ordering::SeqCst);
    c.apply(
        &p.id,
        "owner",
        &active.etag(),
        Some("verified-runtime-revision"),
        &NoProvider,
        &host,
        &Proof(true),
    )
    .await
    .expect("idempotent apply");
    assert_eq!(host.calls.load(Ordering::SeqCst), before);
    // The same original ETag cannot start another apply.
    assert_eq!(
        c.apply(
            &p.id,
            "owner",
            &p.etag(),
            None,
            &NoProvider,
            &host,
            &Proof(true)
        )
        .await
        .expect_err("stale")
        .0,
        "stale_provision_plan"
    );
}
/// The host itself can't reach its public endpoint; everything else is fine.
struct Unreachable;
impl Probe for Unreachable {
    fn verify<'a>(&'a self, _: &'a Plan) -> StepFuture<'a, Verification> {
        Box::pin(async { Err(Error(DATA_PATH_UNVERIFIED_FROM_HOST)) })
    }
}

#[tokio::test]
async fn unreachable_from_host_commits_flagged_unverified() {
    let c = Controller::new(Arc::new(Store::open_in_memory().expect("db")));
    let p = c.plan(desired(), "owner", None).expect("plan");
    let host = Host {
        calls: AtomicUsize::new(0),
        fail: false,
    };
    let active = c
        .apply(
            &p.id,
            "owner",
            &p.etag(),
            None,
            &NoProvider,
            &host,
            &Unreachable,
        )
        .await
        .expect("committed despite the host-side test");
    assert_eq!(active.state, PlanState::Active);
    assert!(
        !active.inventory.verified,
        "never claims a verified data path"
    );
    assert_eq!(
        active.error_code.as_deref(),
        Some(DATA_PATH_UNVERIFIED_FROM_HOST)
    );
    // A later full verification marks nothing unverified any more; a
    // re-test that still can't reach the endpoint reports it and stays active.
    let again = c
        .apply(
            &p.id,
            "owner",
            &active.etag(),
            Some("verified-runtime-revision"),
            &NoProvider,
            &host,
            &Unreachable,
        )
        .await
        .expect_err("re-test reports the condition");
    assert_eq!(again.0, DATA_PATH_UNVERIFIED_FROM_HOST);
    assert_eq!(
        c.get(&p.id, "owner").expect("plan").state,
        PlanState::Active
    );
}

#[tokio::test]
async fn failures_survive_reopen_and_do_not_claim_rollback_or_active() {
    let dir = tempfile::tempdir().expect("temp");
    let path = dir.path().join("state.db");
    let c = Controller::new(Arc::new(Store::open(&path).expect("db")));
    let p = c.plan(desired(), "owner", None).expect("plan");
    let host = Host {
        calls: AtomicUsize::new(0),
        fail: true,
    };
    assert!(c
        .apply(
            &p.id,
            "owner",
            &p.etag(),
            None,
            &NoProvider,
            &host,
            &Proof(true)
        )
        .await
        .is_err());
    drop(c);
    let c = Controller::new(Arc::new(Store::open(&path).expect("reopen")));
    let p = c.get(&p.id, "owner").expect("recovered plan");
    assert_eq!(p.state, PlanState::RecoveryRequired);
    assert_eq!(p.error_code.as_deref(), Some("host_fault"));
    assert!(!p.inventory.verified);
    assert_eq!(host.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn stale_revision_fails_before_any_effect() {
    let c = Controller::new(Arc::new(Store::open_in_memory().expect("db")));
    let p = c
        .plan(desired(), "owner", Some("base".into()))
        .expect("plan");
    let host = Host {
        calls: AtomicUsize::new(0),
        fail: false,
    };
    assert_eq!(
        c.apply(
            &p.id,
            "owner",
            &p.etag(),
            Some("newer"),
            &NoProvider,
            &host,
            &Proof(true)
        )
        .await
        .expect_err("stale")
        .0,
        "stale_config_revision"
    );
    assert_eq!(host.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn single_durable_apply_and_explicit_crash_recovery() {
    let store = Arc::new(Store::open_in_memory().expect("db"));
    let c = Controller::new(Arc::clone(&store));
    let p = c.plan(desired(), "owner", None).expect("plan");
    let mut second = desired();
    second.node_id = "other".into();
    let q = c.plan(second, "owner", None).expect("other");
    store
        .tx(|db| {
            db.execute(
                "UPDATE provision_plans SET state='applying' WHERE id=?1",
                [&p.id],
            )?;
            Ok(())
        })
        .expect("simulate process kill");
    assert!(
        store
            .tx(|db| {
                db.execute(
                    "UPDATE provision_plans SET state='applying' WHERE id=?1",
                    [&q.id],
                )?;
                Ok(())
            })
            .is_err(),
        "separate processes serialize in SQLite"
    );
    let interrupted = c.get(&p.id, "owner").expect("plan");
    let recovered = c
        .recover(&p.id, "owner", &interrupted.etag())
        .expect("owner recovery");
    assert_eq!(recovered.state, PlanState::RecoveryRequired);
    assert!(c.recover(&p.id, "owner", &interrupted.etag()).is_err());
}
#[test]
fn generated_profiles_and_compose_keep_privilege_and_management_boundaries() {
    let d = desired();
    let b = host::Bootstrap {
        schema_version: 1,
        deployment_id: d.deployment_id.clone(),
        node_id: d.node_id.clone(),
        inner_server_name: d.inner_server_name.clone(),
        runtime_uid: 10001,
        runtime_gid: 10001,
    };
    let c = Controller::new(Arc::new(Store::open_in_memory().expect("db")));
    let mut p = c.plan(d, "owner", None).expect("plan");
    let root = std::path::Path::new("/tmp/aegis-owned");
    for cloudflare in [false, true] {
        if cloudflare {
            p.desired.mode = Mode::CloudflareTunnel;
            p.desired.hostname = Some("edge.example.test".into());
            p.desired.account_id = Some("a".repeat(32));
            p.desired.zone_id = Some("b".repeat(32));
            p.desired.connector_image = Some(format!(
                "cloudflare/cloudflared:2026.10.0@sha256:{}",
                "c".repeat(64)
            ));
        }
        let config = aegis_config::parse_json(&host::gateway_config(&p)).expect("typed gateway");
        aegis_node::validate_offline(&config).expect("gateway compiled");
        let client = aegis_config::parse_json(&host::probe_config(&p, root)).expect("typed client");
        aegis_node::validate_offline(&client).expect("client compiled");
        assert!(config.identity.require_enrollment);
        assert_eq!(config.identity.legacy_identity_until, Some(0));
        let compose = host::compose(&p, root, &b).expect("compose");
        let serialized = compose.to_string();
        assert!(
            !serialized.contains("docker.sock")
                && !serialized.contains("9080:")
                && !serialized.contains("privileged")
        );
        assert_eq!(compose["services"]["gateway"]["read_only"], true);
        assert_eq!(compose["services"]["gateway"]["cap_drop"], json!(["ALL"]));
        if cloudflare {
            assert!(compose["services"]["gateway"].get("ports").is_none());
            assert!(compose["services"].get("nginx").is_none());
            assert!(serialized.contains("--token-file"));
        } else {
            assert_eq!(
                compose["services"]["gateway"]["ports"],
                json!(["127.0.0.1:18080:18080"])
            );
        }
    }
}
#[cfg(unix)]
#[test]
fn secret_store_rejects_links_permissions_and_redacts_debug() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().expect("temp");
    let store = SecretStore::open(dir.path()).expect("secrets");
    store.put("token", "TOKEN_CANARY", false).expect("write");
    assert_eq!(store.read("token").expect("read").as_str(), "TOKEN_CANARY");
    assert!(!format!("{store:?}").contains("TOKEN_CANARY"));
    assert!(store.put("token", "replacement", false).is_err());
    assert!(store.put("../escape", "secret", false).is_err());
    std::fs::set_permissions(
        dir.path().join("token"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("mode");
    assert!(store.read("token").is_err());
    symlink(dir.path().join("token"), dir.path().join("link")).expect("link");
    assert!(store.read("link").is_err());
    assert!(store.put("link", "oops", true).is_err());
}
#[cfg(unix)]
#[test]
fn invalid_certificate_replacement_keeps_previous_manifest_and_key() {
    use aegis_identity::pki;
    let dir = tempfile::tempdir().expect("temp");
    let store = SecretStore::open(dir.path()).expect("secrets");
    let ca = pki::generate_ca("test", pki::DEFAULT_CA_VALIDITY).expect("ca");
    let (cert, key) = pki::issue_direct(
        &ca,
        "gateway",
        aegis_contracts::Role::Gateway,
        &["public.example.test".into()],
        pki::DEFAULT_NODE_VALIDITY,
    )
    .expect("cert");
    let status = aegis_provision::certificate::activate_public(
        &store,
        &cert,
        &key,
        "public.example.test",
        Some(&ca.cert_pem),
    )
    .expect("valid imported PKI");
    let manifest = store.read("public-tls.json").expect("manifest");
    assert!(aegis_provision::certificate::activate_public(
        &store,
        &cert,
        "invalid key",
        "public.example.test",
        Some(&ca.cert_pem)
    )
    .is_err());
    assert!(aegis_provision::certificate::activate_public(
        &store,
        &cert,
        &key,
        "wrong.example.test",
        Some(&ca.cert_pem)
    )
    .is_err());
    assert!(
        aegis_provision::certificate::activate_public(
            &store,
            &cert,
            &key,
            "public.example.test",
            None
        )
        .is_err(),
        "private PKI never silently trusted publicly"
    );
    assert_eq!(
        manifest.as_str(),
        store.read("public-tls.json").expect("unchanged").as_str()
    );
    assert_eq!(
        aegis_provision::certificate::public_status(&store)
            .expect("status")
            .generation,
        status.generation
    );
}
