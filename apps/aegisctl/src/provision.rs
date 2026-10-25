use super::{print, write_file, Opts};
use aegis_provision::{
    cloudflare::{Cloudflare, NoProvider},
    host::{self, LocalDocker},
    secrets::SecretStore,
    *,
};
use serde_json::json;
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroizing;

pub fn read_stdin_secret() -> std::result::Result<Zeroizing<String>, String> {
    let mut text = Zeroizing::new(String::new());
    std::io::stdin()
        .take(16 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| "stdin_unreadable")?;
    if text.len() > 16 * 1024 {
        return Err("secret_too_large".into());
    }
    let trimmed = text.trim_end_matches(['\r', '\n']).to_owned();
    Ok(Zeroizing::new(trimmed))
}
fn controller(root: &Path) -> Result<Controller> {
    let _ = LocalDocker::open(root)?;
    Ok(Controller::new(Arc::new(aegis_storage::Store::open(
        root.join("provision.db"),
    )?)))
}
fn provider(root: &Path) -> Result<Cloudflare> {
    Cloudflare::new(SecretStore::open(root.join("host-secrets"))?.read("cloudflare-token")?)
}

pub struct Runner {
    pub root: PathBuf,
}
pub struct TrafficProbe {
    root: PathBuf,
}
impl Probe for TrafficProbe {
    fn verify<'a>(&'a self, p: &'a Plan) -> StepFuture<'a, Verification> {
        Box::pin(async move {
            let cfg = aegis_config::parse_json(&host::probe_config(p, &self.root))
                .map_err(|_| Error("probe_config_invalid"))?;
            let node = aegis_node::start(aegis_node::StartOptions {
                config: cfg,
                store_path: self.root.join("probe-state.db"),
                failpoints: None,
            })
            .await
            .map_err(|_| Error("probe_client_start_failed"))?;
            let address = node
                .bound_addr("probe-socks")
                .ok_or(Error("probe_socks_unavailable"))?;
            // curl verifies public HTTPS normally. --socks5-hostname sends the
            // destination name through AGP; --noproxy '' disables ambient bypass.
            let check = async {
                for url in [
                    &p.desired.verification_http_url,
                    &p.desired.verification_https_url,
                ] {
                    let status = tokio::time::timeout(
                        Duration::from_secs(35),
                        tokio::process::Command::new("curl")
                            .args([
                                "--silent",
                                "--fail",
                                "--output",
                                "/dev/null",
                                "--max-time",
                                "30",
                                "--noproxy",
                                "",
                                "--socks5-hostname",
                                &address.to_string(),
                                url,
                            ])
                            .env_remove("http_proxy")
                            .env_remove("https_proxy")
                            .env_remove("ALL_PROXY")
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .kill_on_drop(true)
                            .status(),
                    )
                    .await
                    .map_err(|_| Error("probe_timeout"))?
                    .map_err(|_| Error("curl_not_available"))?;
                    if !status.success() {
                        return Err(Error("socks_http_or_https_probe_failed"));
                    }
                }
                Ok(Verification {
                    provider_objects: true,
                    connector: true,
                    public_dns: true,
                    wss: true,
                    inner_mtls: true,
                    socks_http: true,
                    socks_https: true,
                })
            }
            .await;
            node.shutdown(Duration::from_secs(1)).await;
            check
        })
    }
}
impl Runner {
    async fn current(&self, host: &LocalDocker) -> Option<String> {
        host.ipc(&json!({"cmd":"health"}))
            .await
            .ok()
            .and_then(|v| v["runtime_revision_id"].as_str().map(str::to_owned))
    }
    async fn apply_plan(&self, c: &Controller, id: &str, actor: &str, etag: &str) -> Result<Plan> {
        let plan = c.get(id, actor)?;
        let host = LocalDocker::open(&self.root)?;
        let current = self.current(&host).await;
        let probe = TrafficProbe {
            root: self.root.clone(),
        };
        if plan.desired.mode == Mode::CloudflareTunnel {
            c.apply(
                id,
                actor,
                etag,
                current.as_deref(),
                &provider(&self.root)?,
                &host,
                &probe,
            )
            .await
        } else {
            c.apply(
                id,
                actor,
                etag,
                current.as_deref(),
                &NoProvider,
                &host,
                &probe,
            )
            .await
        }
    }
}
impl Executor for Runner {
    fn apply<'a>(
        &'a self,
        c: &'a Controller,
        id: &'a str,
        actor: &'a str,
        etag: &'a str,
    ) -> StepFuture<'a, Plan> {
        Box::pin(self.apply_plan(c, id, actor, etag))
    }
}

pub fn run(o: &Opts) -> std::result::Result<bool, String> {
    if o.positional.first().map(String::as_str) == Some("config") {
        if o.positional.get(1).map(String::as_str) != Some("migrate") {
            return Err("config subcommand must be migrate".into());
        }
        let text =
            std::fs::read_to_string(o.req("config")?).map_err(|_| "configuration_unreadable")?;
        let cfg = if text.trim_start().starts_with('{') {
            aegis_config::parse_json(
                &serde_json::from_str(&text).map_err(|_| "configuration_invalid")?,
            )
        } else {
            aegis_config::parse_toml(&text)
        }
        .map_err(|_| "configuration_invalid")?;
        let (next, impact) = aegis_config::migrate_v02(&cfg);
        print(
            &json!({"dry_run":true,"source_digest":aegis_config::config_digest(&cfg),"target_digest":aegis_config::config_digest(&next),"specification":next,"security_impact":impact,"rollback":"restore the retained source as a new validated revision; revocations are never rolled back"}),
        );
        return Ok(true);
    }
    let rt = tokio::runtime::Runtime::new().map_err(|_| "runtime_unavailable")?;
    rt.block_on(run_async(o)).map_err(|e| e.to_string())
}

async fn run_async(o: &Opts) -> Result<bool> {
    let cmd = o.positional.first().map(String::as_str).unwrap_or("");
    let sub = o.positional.get(1).map(String::as_str).unwrap_or("");
    if cmd == "setup" && sub == "doctor" {
        print(&LocalDocker::doctor().await?);
        return Ok(true);
    }
    let root = PathBuf::from(o.req("root").map_err(|_| Error("root_required"))?);
    if cmd == "setup" && sub == "bootstrap" {
        let node = o.req("node-id").map_err(|_| Error("node_id_required"))?;
        let name = o
            .req("server-name")
            .map_err(|_| Error("server_name_required"))?;
        if let Some(target) = o.get("target") {
            let expected = if cfg!(target_os = "macos") {
                "macos-docker"
            } else {
                "linux-docker"
            };
            if target != expected {
                return Err(Error("unsupported_bootstrap_target"));
            }
        }
        let manifest = host::bootstrap(&root, node, name)?;
        print(
            &json!({"bootstrap":manifest,"status":"bootstrapped","root_key_location":"host-secrets/root-key.pem (never mounted in gateway)","next":"provision plan, then explicit apply; no deployment is active yet"}),
        );
        return Ok(true);
    }
    let host = LocalDocker::open(&root)?;
    if cmd == "certificate" {
        let runtime = SecretStore::open(root.join("runtime-secrets"))?;
        match sub {
            "status" => print(
                &json!({"local":aegis_provision::trust::local_status(&root)?,"public":aegis_provision::certificate::public_status(&runtime).ok(),"trust_rotation":aegis_provision::trust::status(&root).ok()}),
            ),
            "trust-stage" => {
                if o.get("confirm").is_none() {
                    return Err(Error("trust_change_requires_explicit_confirmation"));
                }
                let new =
                    std::fs::read_to_string(o.req("new-ca").map_err(|_| Error("new_ca_required"))?)
                        .map_err(|_| Error("new_ca_unreadable"))?;
                print(
                    &serde_json::to_value(aegis_provision::trust::stage(&root, &new)?)
                        .map_err(|_| Error("invalid_rotation"))?,
                );
                host.ipc(&json!({"cmd":"certificate_reload"})).await?;
            }
            "trust-recover" => {
                print(
                    &serde_json::to_value(aegis_provision::trust::finish_stage(&root)?)
                        .map_err(|_| Error("invalid_rotation"))?,
                );
                host.ipc(&json!({"cmd":"certificate_reload"})).await?;
            }
            "trust-retire" => {
                if o.get("confirm").is_none() {
                    return Err(Error("trust_change_requires_explicit_confirmation"));
                }
                print(
                    &serde_json::to_value(aegis_provision::trust::retire(&root)?)
                        .map_err(|_| Error("invalid_rotation"))?,
                );
                host.ipc(&json!({"cmd":"certificate_reload"})).await?;
            }
            "issuer-import" => {
                let cert = std::fs::read_to_string(
                    o.req("certificate")
                        .map_err(|_| Error("certificate_required"))?,
                )
                .map_err(|_| Error("certificate_unreadable"))?;
                let path =
                    PathBuf::from(o.req("key-file").map_err(|_| Error("key_file_required"))?);
                let key = aegis_config::secret::read(
                    path.parent().ok_or(Error("invalid_key_path"))?,
                    &format!(
                        "secret://{}",
                        path.file_name()
                            .and_then(|s| s.to_str())
                            .ok_or(Error("invalid_key_path"))?
                    ),
                )
                .map_err(|_| Error("key_unreadable_or_insecure_permissions"))?;
                aegis_provision::trust::import_issuer(
                    &root,
                    aegis_identity::pki::CaBundle {
                        cert_pem: cert,
                        key_pem: key,
                    },
                )?;
                host.ipc(&json!({"cmd":"certificate_reload"})).await?;
                print(&json!({"issuer_imported":true}));
            }
            "renew-local" => {
                if o.get("dry-run").is_some() {
                    print(
                        &json!({"dry_run":true,"local":aegis_provision::trust::local_status(&root)?}),
                    );
                } else {
                    aegis_provision::trust::renew_local(&root)?;
                    host.ipc(&json!({"cmd":"certificate_reload"})).await?;
                    let probe = SecretStore::open(root.join("probe-secrets"))?;
                    host.ipc(&json!({"cmd":"identity_register","certificate_pem":aegis_provision::trust::read_bundle(&probe,"probe-identity.json")?.cert_pem,"replace":true})).await?;
                    print(&aegis_provision::trust::local_status(&root)?);
                }
            }
            "import" => {
                let cert = std::fs::read_to_string(
                    o.req("certificate")
                        .map_err(|_| Error("certificate_required"))?,
                )
                .map_err(|_| Error("certificate_unreadable"))?;
                let key_path =
                    PathBuf::from(o.req("key-file").map_err(|_| Error("key_file_required"))?);
                let key = aegis_config::secret::read(
                    key_path.parent().ok_or(Error("invalid_key_path"))?,
                    &format!(
                        "secret://{}",
                        key_path
                            .file_name()
                            .and_then(|f| f.to_str())
                            .ok_or(Error("invalid_key_path"))?
                    ),
                )
                .map_err(|_| Error("key_unreadable_or_insecure_permissions"))?;
                let ca = o
                    .get("trust-ca")
                    .map(std::fs::read_to_string)
                    .transpose()
                    .map_err(|_| Error("trust_ca_unreadable"))?;
                let status = aegis_provision::certificate::activate_public(
                    &runtime,
                    &cert,
                    &key,
                    o.req("hostname").map_err(|_| Error("hostname_required"))?,
                    ca.as_deref(),
                )?;
                if let Some(ca) = ca {
                    runtime.put("outer-ca.pem", &ca, true)?;
                }
                host::runtime_permissions(&root)?;
                print(
                    &serde_json::to_value(status)
                        .map_err(|_| Error("invalid_certificate_status"))?,
                );
            }
            "issue" => {
                let text = std::fs::read_to_string(
                    o.req("settings")
                        .map_err(|_| Error("acme_settings_required"))?,
                )
                .map_err(|_| Error("acme_settings_unreadable"))?;
                let settings =
                    serde_json::from_str(&text).map_err(|_| Error("invalid_acme_settings"))?;
                if o.get("dns-token-stdin").is_some() {
                    SecretStore::open(root.join("host-secrets"))?.put(
                        "acme-dns-token",
                        &read_stdin_secret().map_err(|_| Error("invalid_dns_token"))?,
                        true,
                    )?;
                }
                let status = aegis_provision::certificate::acme(&root, &settings, false).await?;
                print(
                    &serde_json::to_value(status)
                        .map_err(|_| Error("invalid_certificate_status"))?,
                );
            }
            "renew" => {
                let settings = aegis_provision::certificate::renewal_settings(&root)?;
                if o.get("dry-run").is_some() {
                    print(
                        &json!({"dry_run":true,"settings":settings,"status":aegis_provision::certificate::public_status(&runtime)?}),
                    );
                } else {
                    print(
                        &serde_json::to_value(
                            aegis_provision::certificate::acme(&root, &settings, true).await?,
                        )
                        .map_err(|_| Error("invalid_certificate_status"))?,
                    );
                }
            }
            _ => return Err(Error("unsupported_certificate_command")),
        }
        return Ok(true);
    }
    if cmd == "setup" && sub == "serve" {
        return serve(&root, o.get("bind").unwrap_or("127.0.0.1:9082")).await;
    }
    if cmd == "local" {
        if o.get("request-stdin").is_none() {
            return Err(Error("request_stdin_required"));
        }
        let mut input = String::new();
        std::io::stdin()
            .take(65537)
            .read_to_string(&mut input)
            .map_err(|_| Error("stdin_unreadable"))?;
        if input.len() > 65536 {
            return Err(Error("request_too_large"));
        }
        let request = serde_json::from_str(&input).map_err(|_| Error("invalid_request"))?;
        print(&host.ipc(&request).await?);
        return Ok(true);
    }
    if cmd == "provider" {
        if sub != "cloudflare" {
            return Err(Error("unsupported_provider"));
        }
        match o.positional.get(2).map(String::as_str) {
            Some("connect" | "rotate-credential") => {
                if o.get("token-stdin").is_none() {
                    return Err(Error("token_stdin_required"));
                }
                let token = read_stdin_secret().map_err(|_| Error("token_stdin_invalid"))?;
                let cf = Cloudflare::new(token.clone())?;
                cf.check_token().await?;
                let secret = SecretStore::open(root.join("host-secrets"))?;
                secret.put("cloudflare-token", &token, true)?;
                let c = controller(&root)?;
                c.store.tx(|conn| {
                    conn.execute("INSERT INTO provider_credentials(provider,secret_ref,fingerprint,generation,updated_at) VALUES ('cloudflare','secret://cloudflare-token',?1,1,?2) ON CONFLICT(provider) DO UPDATE SET fingerprint=excluded.fingerprint,generation=generation+1,updated_at=excluded.updated_at",(aegis_storage::sha256_hex(token.as_bytes()),aegis_storage::now_unix()))?;
                    Ok(())
                })?;
                print(
                    &json!({"provider":"cloudflare","credential":"<redacted>","token_active":true,"write_permissions":"validated by zone/tunnel/DNS operations; token verification alone is insufficient"}),
                );
                return Ok(true);
            }
            Some("zones") => {
                print(&json!({"items":provider(&root)?.zones().await?}));
                return Ok(true);
            }
            _ => return Err(Error("unsupported_provider_command")),
        }
    }
    if cmd != "provision" {
        return Err(Error("unsupported_setup_command"));
    }
    let controller = controller(&root)?;
    let actor = "local-owner";
    let runner = Runner { root: root.clone() };
    if sub == "plan" {
        let desired = if let Some(file) = o.get("desired") {
            let bytes = std::fs::read(file).map_err(|_| Error("desired_unreadable"))?;
            if bytes.len() > 65536 {
                return Err(Error("desired_too_large"));
            }
            serde_json::from_slice(&bytes).map_err(|_| Error("invalid_desired_deployment"))?
        } else {
            let b = host.bootstrap_manifest();
            let mode = match o.get("mode").unwrap_or("cloudflare-tunnel") {
                "cloudflare-tunnel" => Mode::CloudflareTunnel,
                "local-private" => Mode::LocalPrivate,
                "direct-public" => Mode::DirectPublic,
                _ => return Err(Error("unsupported_provision_mode")),
            };
            let zone = if mode == Mode::CloudflareTunnel {
                let zones = provider(&root)?.zones().await?;
                let name = o.req("zone").map_err(|_| Error("zone_required"))?;
                Some(
                    zones
                        .into_iter()
                        .find(|z| z["name"] == name)
                        .ok_or(Error("zone_not_accessible"))?,
                )
            } else {
                None
            };
            DesiredDeployment {
                schema_version: 1,
                deployment_id: b.deployment_id.clone(),
                mode,
                host: HostKind::Compose,
                origin_service: None,
                node_id: b.node_id.clone(),
                inner_server_name: b.inner_server_name.clone(),
                hostname: o.get("hostname").map(str::to_owned),
                account_id: zone
                    .as_ref()
                    .and_then(|z| z["account_id"].as_str().map(str::to_owned)),
                zone_id: zone
                    .as_ref()
                    .and_then(|z| z["id"].as_str().map(str::to_owned)),
                gateway_image: o
                    .req("gateway-image")
                    .map_err(|_| Error("pinned_gateway_image_required"))?
                    .into(),
                connector_image: o.get("connector-image").map(str::to_owned),
                nameservers: o.all("nameserver"),
                verification_http_url: o
                    .req("verify-http-url")
                    .map_err(|_| Error("http_probe_url_required"))?
                    .into(),
                verification_https_url: o
                    .req("verify-https-url")
                    .map_err(|_| Error("https_probe_url_required"))?
                    .into(),
                acme: None,
                outer_trust_ca: o.get("outer-trust-ca").map(str::to_owned),
                nginx_image: o.get("nginx-image").map(str::to_owned),
            }
        };
        let plan = controller.plan(desired, actor, runner.current(&host).await)?;
        print(
            &json!({"plan":plan,"etag":plan.etag(),"dry_run":true,"permissions":["local Docker/Compose","Cloudflare Tunnel Edit and zone DNS Edit when selected"],"management":"container loopback + authenticated Docker exec IPC; no public mapping","trust":"outer edge TLS and independent inner device mTLS","caveat":"Cloudflare Free use remains subject to provider terms and limits"}),
        );
        return Ok(true);
    }
    if sub == "status" {
        print(&json!({"items":controller.list(actor)?}));
        return Ok(true);
    }
    let id = o.req("plan-id").map_err(|_| Error("plan_id_required"))?;
    let mut plan = controller.get(id, actor)?;
    match sub {
        "apply" => {
            if o.get("confirm").is_none() {
                return Err(Error("explicit_apply_confirmation_required"));
            }
            let applied = runner
                .apply_plan(&controller, id, actor, &plan.etag())
                .await?;
            print(&serde_json::to_value(applied).map_err(|_| Error("invalid_plan"))?);
        }
        "verify" => {
            let probe = TrafficProbe { root };
            let revision = if plan.desired.mode == Mode::CloudflareTunnel {
                controller
                    .verify(&plan, &provider(host.root())?, &host, &probe)
                    .await?
            } else {
                controller.verify(&plan, &NoProvider, &host, &probe).await?
            };
            print(
                &json!({"verified":true,"revision_id":revision,"endpoint":plan.desired.endpoint(),"socks_http":true,"socks_https":true}),
            );
        }
        "reconcile" => {
            if o.get("dry-run").is_some() || o.get("confirm").is_none() {
                print(
                    &json!({"dry_run":true,"plan":plan,"host_revision":runner.current(&host).await,"action":"explicit recovery of stranded operation, then read-before-write apply; unknown tunnel creation is blocked for ownership review"}),
                );
            } else {
                if matches!(
                    plan.state,
                    PlanState::Applying | PlanState::Verifying | PlanState::Compensating
                ) {
                    plan = controller.recover(id, actor, &plan.etag())?;
                }
                print(
                    &serde_json::to_value(
                        runner
                            .apply_plan(&controller, id, actor, &plan.etag())
                            .await?,
                    )
                    .map_err(|_| Error("invalid_plan"))?,
                );
            }
        }
        "uninstall" => {
            let keep_dns = o.get("keep-dns").is_some();
            let keep_tunnel = o.get("keep-tunnel").is_some();
            if keep_dns && !keep_tunnel {
                return Err(Error("keep_dns_requires_keep_tunnel"));
            }
            if o.get("confirm").is_none() {
                print(
                    &json!({"dry_run":true,"plan_id":id,"compose_project":format!("aegis-{}",plan.desired.deployment_id),"remove_dns":if !keep_dns&&plan.inventory.created_dns{plan.inventory.dns_id.clone()}else{None},"remove_tunnel":if !keep_tunnel&&plan.inventory.created_tunnel{plan.inventory.tunnel_id.clone()}else{None},"preserve":"state, keys, controller journal, images and unrelated resources"}),
                );
            } else {
                let result = if plan.desired.mode == Mode::CloudflareTunnel {
                    controller
                        .uninstall(
                            id,
                            actor,
                            &plan.etag(),
                            &provider(&root)?,
                            &host,
                            keep_dns,
                            keep_tunnel,
                        )
                        .await?
                } else {
                    controller
                        .uninstall(
                            id,
                            actor,
                            &plan.etag(),
                            &NoProvider,
                            &host,
                            keep_dns,
                            keep_tunnel,
                        )
                        .await?
                };
                print(&serde_json::to_value(result).map_err(|_| Error("invalid_plan"))?);
            }
        }
        _ => return Err(Error("unsupported_provision_command")),
    }
    Ok(true)
}

async fn serve(root: &Path, bind: &str) -> Result<bool> {
    let bind: std::net::SocketAddr = bind.parse().map_err(|_| Error("invalid_bind"))?;
    if !bind.ip().is_loopback() {
        return Err(Error("host_controller_requires_loopback"));
    }
    let controller = controller(root)?;
    let os = aegis_contracts::capability::OsFamily::current();
    let coord = Arc::new(aegis_core::Coordinator::new(
        Arc::clone(&controller.store),
        aegis_core::AdmissionGate::new(aegis_identity::IdentityStore::new(
            aegis_identity::IdentitySnapshot::default(),
        )),
        Arc::new(aegis_core::CapabilityEnv::new(
            aegis_node::modules::registry(os),
            aegis_platform::host_vpn_capabilities(os),
        )),
        Arc::new(aegis_core::AgentCell::default()),
        "host-controller".into(),
        aegis_contracts::Role::Gateway,
        Arc::new(aegis_core::NoFailPoints),
        Arc::new(aegis_contracts::observability::NoopObservability),
    ));
    let ctx = aegis_management::ManagementContext::new(
        coord,
        Arc::new(aegis_telemetry::LocalMetrics::new(None)),
        Arc::new(aegis_telemetry::CoreGauges::default),
        Arc::new(aegis_telemetry::DiagnosticSink::new()),
        None,
        root.join("host-secrets"),
        bind,
        vec![],
    );
    *ctx.provision_executor
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(Runner {
        root: root.to_owned(),
    }));
    #[cfg(unix)]
    tokio::spawn(aegis_management::ipc::serve(
        Arc::clone(&ctx),
        root.join("controller.sock"),
    ));
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|_| Error("controller_bind_failed"))?;
    aegis_management::serve(ctx, listener, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    .map_err(|_| Error("controller_serve_failed"))?;
    Ok(true)
}

pub fn enroll(o: &Opts) -> std::result::Result<bool, String> {
    let name = o.req("name")?;
    let out = PathBuf::from(o.req("out")?);
    let (key, csr) =
        aegis_identity::pki::generate_key_and_csr(name).map_err(|_| "csr_generation_failed")?;
    write_file(&out.join("key.pem"), &key, true)?;
    write_file(&out.join("csr.pem"), &csr, false)?;
    let mut flags = o.flags.clone();
    flags.push((
        "csr".into(),
        out.join("csr.pem").to_string_lossy().into_owned(),
    ));
    let options = Opts {
        positional: o.positional.clone(),
        flags,
    };
    if !super::cmd_redeem(&options)? {
        return Ok(false);
    }
    let config = json!({"schema_version":"0.2","node_id":name,"role":"client","management":{"bind":"127.0.0.1:9081","config_store":out.join("state.db")},"secrets":{"dir":std::fs::canonicalize(&out).map_err(|_|"invalid_output_directory")?},"identity":{"peer_auth":"mutual_tls_1_3","client_identity":"secret://cert.pem","client_private_key":"secret://key.pem","trusted_server_ca":"secret://ca.pem","require_enrollment":true,"legacy_identity_until":0},"inbounds":[{"id":"socks","kind":"socks5","bind":"127.0.0.1:1080"},{"id":"http-connect","kind":"http_connect","bind":"127.0.0.1:8080"}],"outbounds":[{"id":"gateway","kind":"agp_tunnel","url":o.req("url")?,"server_name":o.req("server-name")?}],"routing":{"default_action":"proxy","default_outbound":"gateway"},"dns":{"mode":"remote_required","ipv6_policy":"follow-routing-policy"}});
    let parsed = aegis_config::parse_json(&config).map_err(|_| "generated_profile_invalid")?;
    aegis_node::validate_offline(&parsed).map_err(|_| "generated_profile_invalid")?;
    write_file(&out.join("client.json"), &config.to_string(), false)?;
    print(
        &json!({"enrolled":true,"config":out.join("client.json"),"socks":"127.0.0.1:1080","http_connect":"127.0.0.1:8080","destination_dns":"remote_required"}),
    );
    Ok(true)
}
