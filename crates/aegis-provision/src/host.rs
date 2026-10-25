//! Explicit local installer adapter. Only fixed Docker/Compose operations are
//! executed; the gateway never receives Docker or host service authority.
use crate::{secrets::SecretStore, *};
use aegis_identity::pki;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub schema_version: u32,
    pub deployment_id: String,
    pub node_id: String,
    pub inner_server_name: String,
    pub runtime_uid: u32,
    pub runtime_gid: u32,
}

fn private_dir(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| !m.is_dir() || m.file_type().is_symlink()) {
        return Err(Error("host_path_not_owned"));
    }
    std::fs::create_dir_all(path).map_err(|_| Error("host_directory_unavailable"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("host_directory_permissions"))?;
    }
    Ok(())
}

pub fn bootstrap(root: &Path, node_id: &str, inner_server_name: &str) -> Result<Bootstrap> {
    if !aegis_identity::valid_node_id(node_id)
        || aegis_contracts::destination::normalize_domain(inner_server_name).as_deref()
            != Ok(inner_server_name)
    {
        return Err(Error("invalid_bootstrap_identity"));
    }
    if root.exists()
        && !root.join("host-secrets/bootstrap.json").exists()
        && std::fs::read_dir(root)
            .map_err(|_| Error("host_directory_unavailable"))?
            .next()
            .is_some()
    {
        return Err(Error(
            "bootstrap_requires_empty_directory_or_recovery_of_partial_install",
        ));
    }
    private_dir(root)?;
    let secrets = SecretStore::open(root.join("host-secrets"))?;
    if let Ok(manifest) = secrets.read("bootstrap.json") {
        let b: Bootstrap =
            serde_json::from_str(&manifest).map_err(|_| Error("corrupt_bootstrap"))?;
        if b.node_id != node_id || b.inner_server_name != inner_server_name {
            return Err(Error("bootstrap_identity_conflict"));
        }
        return Ok(b);
    }
    #[cfg(unix)]
    let (uid, gid) = {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(root).map_err(|_| Error("host_directory_unavailable"))?;
        if m.uid() == 0 {
            (10001, 10001)
        } else {
            (m.uid(), m.gid())
        }
    };
    #[cfg(not(unix))]
    let (uid, gid) = (10001, 10001);
    let b = Bootstrap {
        schema_version: 1,
        deployment_id: aegis_storage::new_id(),
        node_id: node_id.into(),
        inner_server_name: inner_server_name.into(),
        runtime_uid: uid,
        runtime_gid: gid,
    };
    let root_ca = pki::generate_offline_root("AegisNet offline root")
        .map_err(|_| Error("root_generation_failed"))?;
    // Root escrow is separate from runtime mount. The online intermediate has
    // path length zero and one-year validity; leaves retain their 90-day cap.
    secrets.put("root-key.pem", &root_ca.key_pem, false)?;
    secrets.put("root.pem", &root_ca.cert_pem, false)?;
    let issuer = pki::generate_intermediate(
        &root_ca,
        "AegisNet device issuer",
        Duration::from_secs(365 * 86400),
    )
    .map_err(|_| Error("issuer_generation_failed"))?;
    secrets.put("issuer-key.pem", &issuer.key_pem, false)?;
    secrets.put("issuer.pem", &issuer.cert_pem, false)?;
    let (gateway_cert, gateway_key) = pki::issue_direct(
        &issuer,
        node_id,
        aegis_contracts::Role::Gateway,
        &[inner_server_name.into()],
        pki::DEFAULT_NODE_VALIDITY,
    )
    .map_err(|_| Error("gateway_identity_failed"))?;
    let runtime = SecretStore::open(root.join("runtime-secrets"))?;
    runtime.put(
        "gateway-cert.pem",
        &format!("{gateway_cert}{}", issuer.cert_pem),
        false,
    )?;
    runtime.put("gateway-key.pem", &gateway_key, false)?;
    runtime.put("root.pem", &root_ca.cert_pem, false)?;
    runtime.put(
        "issuer-chain.pem",
        &format!("{}{}", issuer.cert_pem, root_ca.cert_pem),
        false,
    )?;
    runtime.put("issuer-key.pem", &issuer.key_pem, false)?;
    runtime.put("gateway-identity.json",&json!({"certificate":"secret://gateway-cert.pem","private_key":"secret://gateway-key.pem"}).to_string(),false)?;
    runtime.put(
        "issuer.json",
        &json!({"certificate":"secret://issuer-chain.pem","private_key":"secret://issuer-key.pem"})
            .to_string(),
        false,
    )?;
    let probe = SecretStore::open(root.join("probe-secrets"))?;
    let probe_name = format!("probe-{}", &b.deployment_id[..8]);
    let (key, csr) =
        pki::generate_key_and_csr(&probe_name).map_err(|_| Error("probe_identity_failed"))?;
    let cert = pki::sign_csr(
        &issuer,
        &csr,
        &probe_name,
        aegis_contracts::Role::Client,
        &[],
        pki::DEFAULT_NODE_VALIDITY,
    )
    .map_err(|_| Error("probe_identity_failed"))?;
    probe.put("cert.pem", &format!("{cert}{}", issuer.cert_pem), false)?;
    probe.put("key.pem", &key, false)?;
    probe.put("root.pem", &root_ca.cert_pem, false)?;
    probe.put(
        "probe-identity.json",
        &json!({"certificate":"secret://cert.pem","private_key":"secret://key.pem"}).to_string(),
        false,
    )?;
    private_dir(&root.join("runtime-state"))?;
    // This narrow ownership operation is needed only when the explicitly run
    // installer is root. Normal Mac/Linux users keep their own uid in Docker.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{chown, MetadataExt};
        if std::fs::metadata(root)
            .map_err(|_| Error("host_directory_unavailable"))?
            .uid()
            == 0
        {
            for subdir in ["runtime-secrets", "runtime-state"] {
                let path = root.join(subdir);
                if subdir == "runtime-secrets" {
                    for file in
                        std::fs::read_dir(&path).map_err(|_| Error("host_directory_unavailable"))?
                    {
                        let file = file.map_err(|_| Error("host_directory_unavailable"))?;
                        chown(file.path(), Some(uid), Some(gid))
                            .map_err(|_| Error("runtime_secret_ownership_failed"))?;
                    }
                }
                chown(path, Some(uid), Some(gid))
                    .map_err(|_| Error("runtime_secret_ownership_failed"))?;
            }
        }
    }
    secrets.put(
        "bootstrap.json",
        &serde_json::to_string(&b).map_err(|_| Error("bootstrap_serialization"))?,
        false,
    )?;
    Ok(b)
}

/// Generated JSON is also valid YAML. All paths come from a canonical owned
/// root, and all values are serialized data (never string-built shell code).
pub fn compose(p: &Plan, root: &Path, b: &Bootstrap) -> Result<Value> {
    p.desired.validate()?;
    if b.deployment_id != p.desired.deployment_id
        || b.node_id != p.desired.node_id
        || b.inner_server_name != p.desired.inner_server_name
    {
        return Err(Error("deployment_ownership_mismatch"));
    }
    let mount = |file: &str, target: &str, read_only: bool| json!({"type":"bind","source":root.join(file),"target":target,"read_only":read_only,"bind":{"create_host_path":false}});
    let mut gateway = json!({
        "image":p.desired.gateway_image,"user":format!("{}:{}",b.runtime_uid,b.runtime_gid),
        "read_only":true,"cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],
        "pids_limit":128,"mem_limit":"256m","restart":"unless-stopped",
        "tmpfs":["/tmp:rw,noexec,nosuid,size=16m"],"logging":{"driver":"none"},
        "volumes":[mount("gateway.json","/etc/aegisnet/config.toml",true),mount("runtime-secrets","/run/secrets/aegisnet",true),mount("runtime-state","/var/lib/aegisnet",false)],
        "networks":["origin","gateway-egress"],
        "healthcheck":{"test":["CMD","/usr/local/bin/aegisctl","health"],"interval":"10s","timeout":"5s","retries":6}
    });
    if p.desired.mode == Mode::LocalPrivate {
        gateway["ports"] = json!(["127.0.0.1:18080:18080"]);
    }
    if p.desired.mode == Mode::DirectPublic && p.desired.nginx_image.is_none() {
        gateway["ports"] = json!(["443:18080"]);
    }
    let mut services = json!({"gateway":gateway});
    let mut networks = json!({"origin":{"internal":true},"gateway-egress":{}});
    if p.desired.mode == Mode::CloudflareTunnel {
        services["cloudflared"] = json!({
            "image":p.desired.connector_image,"user":format!("{}:{}",b.runtime_uid,b.runtime_gid),
            "command":["tunnel","--no-autoupdate","--loglevel","fatal","run","--token-file","/run/secrets/tunnel-token"],
            "read_only":true,"cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],
            "pids_limit":64,"mem_limit":"128m","restart":"unless-stopped","logging":{"driver":"none"},
            "volumes":[mount("connector-secrets/token","/run/secrets/tunnel-token",true)],
            "networks":["origin","connector-egress"],"depends_on":{"gateway":{"condition":"service_healthy"}}
        });
        networks["connector-egress"] = json!({});
    }
    if let Some(image) = &p.desired.nginx_image {
        services["nginx"] = json!({"image":image,"entrypoint":["nginx"],"command":["-c","/etc/aegisnet/nginx.conf","-g","daemon off;"],"user":format!("{}:{}",b.runtime_uid,b.runtime_gid),"read_only":true,"cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],"pids_limit":64,"mem_limit":"64m","restart":"unless-stopped","logging":{"driver":"none"},"tmpfs":["/tmp:rw,noexec,nosuid,size=16m"],"volumes":[mount("nginx-state","/etc/aegisnet",true)],"ports":["443:8443"],"networks":["origin","nginx-egress"],"depends_on":{"gateway":{"condition":"service_healthy"}}});
        networks["nginx-egress"] = json!({});
    }
    Ok(json!({"name":format!("aegis-{}",b.deployment_id),"services":services,"networks":networks}))
}

pub fn gateway_config(p: &Plan) -> Value {
    let mut config = json!({
        "schema_version":"0.2","node_id":p.desired.node_id,"role":"gateway",
        "management":{"bind":"127.0.0.1:9080","config_store":"/var/lib/aegisnet/state.db"},
        "secrets":{"dir":"/run/secrets/aegisnet"},
        "identity":{"peer_auth":"mutual_tls_1_3","material_bundle":"secret://gateway-identity.json","trusted_client_ca":"secret://root.pem","issuer_bundle":"secret://issuer.json","require_enrollment":true,"legacy_identity_until":0},
        "inbounds":[{"id":"ingress-ws","kind":"websocket","bind":"0.0.0.0:18080","path":"/agp","max_frame_bytes":131072}],
        "outbounds":[{"id":"egress","kind":"direct_tcp","restricted_address_policy":"deny-private-and-metadata"}],
        "routing":{"default_action":"deny","rules":[{"id":"authenticated-public","match":"authenticated-and-public-destination","action":"proxy","outbound":"egress"}]},
        "dns":{"mode":"remote_required","ipv6_policy":"follow-routing-policy","resolver":"explicit","nameservers":p.desired.nameservers}
    });
    if p.desired.mode == Mode::DirectPublic && p.desired.nginx_image.is_none() {
        config["inbounds"][0]["outer_tls"] = json!({"bundle":"secret://public-tls.json","server_name":p.desired.hostname,"trusted_ca":p.desired.outer_trust_ca});
    }
    config
}

pub fn probe_config(p: &Plan, root: &Path) -> Value {
    json!({
        "schema_version":"0.2","node_id":format!("probe-{}",&p.desired.deployment_id[..8]),"role":"client",
        "management":{"enabled":false,"config_store":root.join("probe-state.db")},
        "secrets":{"dir":root.join("probe-secrets")},
        "identity":{"peer_auth":"mutual_tls_1_3","material_bundle":"secret://probe-identity.json","trusted_server_ca":"secret://root.pem","require_enrollment":true,"legacy_identity_until":0},
        "inbounds":[{"id":"probe-socks","kind":"socks5","bind":"127.0.0.1:0"}],
        "outbounds":[{"id":"gateway","kind":"agp_tunnel","url":p.desired.endpoint(),"server_name":p.desired.inner_server_name}],
        "routing":{"default_action":"proxy","default_outbound":"gateway"},
        "dns":{"mode":"remote_required","ipv6_policy":"follow-routing-policy"}
    })
}

pub fn runtime_permissions(root: &Path) -> Result<()> {
    #[cfg(not(unix))]
    let _ = root;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{chown, MetadataExt};
        if std::fs::metadata(root)
            .map_err(|_| Error("host_directory_unavailable"))?
            .uid()
            == 0
        {
            let host = LocalDocker::open(root)?;
            let b = host.bootstrap_manifest();
            for entry in std::fs::read_dir(root.join("runtime-secrets"))
                .map_err(|_| Error("host_directory_unavailable"))?
            {
                let entry = entry.map_err(|_| Error("host_directory_unavailable"))?;
                let meta = std::fs::symlink_metadata(entry.path())
                    .map_err(|_| Error("host_directory_unavailable"))?;
                if !meta.is_file() || meta.file_type().is_symlink() || meta.nlink() != 1 {
                    return Err(Error("runtime_secret_not_owned"));
                }
                chown(entry.path(), Some(b.runtime_uid), Some(b.runtime_gid))
                    .map_err(|_| Error("runtime_secret_ownership_failed"))?;
            }
        }
    }
    Ok(())
}

pub struct LocalDocker {
    root: PathBuf,
    bootstrap: Bootstrap,
}
impl LocalDocker {
    pub fn open(root: &Path) -> Result<Self> {
        let root = std::fs::canonicalize(root).map_err(|_| Error("setup_bootstrap_required"))?;
        let secrets = SecretStore::open(root.join("host-secrets"))?;
        let b = secrets.read("bootstrap.json")?;
        let bootstrap = serde_json::from_str(&b).map_err(|_| Error("corrupt_bootstrap"))?;
        Ok(Self { root, bootstrap })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn bootstrap_manifest(&self) -> &Bootstrap {
        &self.bootstrap
    }
    pub async fn doctor() -> Result<Value> {
        let version = command(
            &["version", "--format", "{{json .Server}}"],
            None,
            Duration::from_secs(10),
        )
        .await?;
        let context = command(
            &[
                "context",
                "inspect",
                "--format",
                "{{json .Endpoints.docker.Host}}",
            ],
            None,
            Duration::from_secs(10),
        )
        .await?;
        if !(context
            .trim_matches(['"', '\r', '\n'])
            .starts_with("unix://")
            || context
                .trim_matches(['"', '\r', '\n'])
                .starts_with("npipe://"))
        {
            return Err(Error("local_docker_context_required"));
        }
        let compose = command(
            &["compose", "version", "--short"],
            None,
            Duration::from_secs(10),
        )
        .await?;
        Ok(
            json!({"docker":serde_json::from_str::<Value>(&version).unwrap_or(Value::Null),"compose_version":compose.trim(),"platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,"native_system_vpn":false,"admin_access":"docker compose exec -> owner-only IPC; no published management port"}),
        )
    }
    async fn compose_command(
        &self,
        args: &[&str],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<String> {
        let file = self.root.join("compose.json");
        let file = file.to_str().ok_or(Error("invalid_host_path"))?;
        let mut argv = vec!["compose", "--file", file, "--project-name"];
        let project = format!("aegis-{}", self.bootstrap.deployment_id);
        argv.push(&project);
        argv.extend_from_slice(args);
        command(&argv, input, timeout).await
    }
    /// Secure equivalent of a Mac host loopback bridge: use the operator's
    /// existing local Docker authorization to reach only the container's UDS.
    pub async fn ipc(&self, request: &Value) -> Result<Value> {
        let mut bytes = serde_json::to_vec(request).map_err(|_| Error("invalid_ipc_request"))?;
        bytes.push(b'\n');
        let response = self
            .compose_command(
                &[
                    "exec",
                    "-T",
                    "gateway",
                    "/usr/local/bin/aegisctl",
                    "ipc-stdin",
                ],
                Some(&bytes),
                Duration::from_secs(60),
            )
            .await?;
        let response: Value =
            serde_json::from_str(&response).map_err(|_| Error("invalid_host_ipc_response"))?;
        if response["ok"] != true {
            return Err(Error("gateway_ipc_operation_rejected"));
        }
        Ok(response["result"].clone())
    }
    fn owned(&self, p: &Plan) -> Result<()> {
        if self.bootstrap.deployment_id != p.desired.deployment_id {
            return Err(Error("deployment_ownership_mismatch"));
        }
        Ok(())
    }

    fn stage_nginx(&self, p: &Plan) -> Result<(SecretStore, String, Option<String>)> {
        let runtime = SecretStore::open(self.root.join("runtime-secrets"))?;
        let refs: Value = serde_json::from_str(&runtime.read("public-tls.json")?)
            .map_err(|_| Error("invalid_public_tls_manifest"))?;
        let read = |field: &str| -> Result<_> {
            let reference = refs[field]
                .as_str()
                .ok_or(Error("invalid_public_tls_manifest"))?;
            let name = aegis_config::secret::parse_ref(reference)
                .map_err(|_| Error("invalid_public_tls_manifest"))?;
            runtime.read(name)
        };
        let cert = read("certificate")?;
        let key = read("private_key")?;
        let ca = p
            .desired
            .outer_trust_ca
            .as_ref()
            .map(|r| aegis_config::secret::read(runtime.root(), r))
            .transpose()
            .map_err(|_| Error("outer_trust_unavailable"))?;
        let hostname = p
            .desired
            .hostname
            .as_deref()
            .ok_or(Error("hostname_required"))?;
        aegis_identity::tls::public_server_config(&cert, &key, hostname, ca.as_deref())
            .map_err(|_| Error("nginx_certificate_rejected"))?;
        let generation = aegis_storage::sha256_hex(cert.as_bytes());
        let cert_file = format!("cert-{}.pem", &generation[..16]);
        let key_file = format!("key-{}.pem", &generation[..16]);
        let output = SecretStore::open(self.root.join("nginx-state"))?;
        for (name, value) in [(&cert_file, cert.as_str()), (&key_file, key.as_str())] {
            if !output.root().join(name).exists() {
                output.put(name, value, false)?;
            } else if output.read(name)?.as_str() != value {
                return Err(Error("nginx_generation_conflict"));
            }
        }
        let candidate = format!("candidate-{}.conf", &generation[..16]);
        output.put(
            &candidate,
            &crate::nginx::config(hostname, &cert_file, &key_file)?,
            true,
        )?;
        let previous = if output.root().join("nginx.conf").exists() {
            Some(output.read("nginx.conf")?.to_string())
        } else {
            None
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::{chown, MetadataExt};
            if std::fs::metadata(&self.root)
                .map_err(|_| Error("host_directory_unavailable"))?
                .uid()
                == 0
            {
                for entry in std::fs::read_dir(output.root())
                    .map_err(|_| Error("host_directory_unavailable"))?
                {
                    let entry = entry.map_err(|_| Error("host_directory_unavailable"))?;
                    if entry
                        .file_type()
                        .map_err(|_| Error("host_directory_unavailable"))?
                        .is_symlink()
                    {
                        return Err(Error("nginx_file_not_owned"));
                    }
                    chown(
                        entry.path(),
                        Some(self.bootstrap.runtime_uid),
                        Some(self.bootstrap.runtime_gid),
                    )
                    .map_err(|_| Error("nginx_permissions"))?;
                }
                chown(
                    output.root(),
                    Some(self.bootstrap.runtime_uid),
                    Some(self.bootstrap.runtime_gid),
                )
                .map_err(|_| Error("nginx_permissions"))?;
            }
        }
        Ok((output, candidate, previous))
    }

    pub async fn reload_nginx(&self, p: &Plan) -> Result<()> {
        if p.desired.nginx_image.is_none() {
            return Ok(());
        }
        let (output, candidate, previous) = self.stage_nginx(p)?;
        self.compose_command(
            &[
                "run",
                "--rm",
                "--no-deps",
                "nginx",
                "-t",
                "-c",
                &format!("/etc/aegisnet/{candidate}"),
            ],
            None,
            Duration::from_secs(30),
        )
        .await?;
        output.put("nginx.conf", &output.read(&candidate)?, true)?;
        // New atomic files need to be readable by the intentionally nonroot
        // Nginx worker before syntax test/reload.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{chown, MetadataExt};
            if std::fs::metadata(&self.root)
                .map_err(|_| Error("host_directory_unavailable"))?
                .uid()
                == 0
            {
                chown(
                    output.root().join("nginx.conf"),
                    Some(self.bootstrap.runtime_uid),
                    Some(self.bootstrap.runtime_gid),
                )
                .map_err(|_| Error("nginx_permissions"))?;
            }
        }
        let result = async {
            self.compose_command(
                &["up", "--detach", "--wait", "--wait-timeout", "60"],
                None,
                Duration::from_secs(90),
            )
            .await?;
            self.compose_command(
                &[
                    "exec",
                    "-T",
                    "nginx",
                    "nginx",
                    "-t",
                    "-c",
                    "/etc/aegisnet/nginx.conf",
                ],
                None,
                Duration::from_secs(15),
            )
            .await?;
            self.compose_command(
                &[
                    "exec",
                    "-T",
                    "nginx",
                    "nginx",
                    "-s",
                    "reload",
                    "-c",
                    "/etc/aegisnet/nginx.conf",
                ],
                None,
                Duration::from_secs(15),
            )
            .await?;
            Ok::<_, Error>(())
        }
        .await;
        if let Err(error) = result {
            if let Some(previous) = previous {
                output.put("nginx.conf", &previous, true)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{chown, MetadataExt};
                    if std::fs::metadata(&self.root)
                        .map_err(|_| Error("host_directory_unavailable"))?
                        .uid()
                        == 0
                    {
                        chown(
                            output.root().join("nginx.conf"),
                            Some(self.bootstrap.runtime_uid),
                            Some(self.bootstrap.runtime_gid),
                        )
                        .map_err(|_| Error("nginx_permissions"))?;
                    }
                }
                self.compose_command(
                    &[
                        "exec",
                        "-T",
                        "nginx",
                        "nginx",
                        "-s",
                        "reload",
                        "-c",
                        "/etc/aegisnet/nginx.conf",
                    ],
                    None,
                    Duration::from_secs(15),
                )
                .await
                .map_err(|_| Error("nginx_rollback_requires_recovery"))?;
            }
            return Err(error);
        }
        Ok(())
    }
}

/// Only Docker is executable through this adapter. Commands, environment and
/// arguments are not obtained from provider responses or profile scripts.
pub(crate) async fn command(
    args: &[&str],
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<String> {
    let mut child = tokio::process::Command::new("docker")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Error("docker_not_available"))?;
    let mut stdin = child.stdin.take().ok_or(Error("host_io_failure"))?;
    let stdout = child.stdout.take().ok_or(Error("host_io_failure"))?;
    let result = tokio::time::timeout(timeout, async {
        if let Some(input) = input {
            stdin
                .write_all(input)
                .await
                .map_err(|_| Error("host_io_failure"))?;
        }
        drop(stdin);
        let mut bytes = Vec::new();
        stdout
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| Error("host_io_failure"))?;
        if bytes.len() > 1024 * 1024 {
            return Err(Error("host_output_limit"));
        }
        if !child
            .wait()
            .await
            .map_err(|_| Error("host_io_failure"))?
            .success()
        {
            return Err(Error("docker_operation_failed"));
        }
        String::from_utf8(bytes).map_err(|_| Error("host_output_invalid"))
    })
    .await;
    match result {
        Ok(r) => r,
        Err(_) => Err(Error("host_operation_timeout")),
    }
}

impl HostProvisioner for LocalDocker {
    fn apply<'a>(&'a self, p: &'a Plan, token: Option<&'a str>) -> StepFuture<'a, ()> {
        Box::pin(async move {
            self.owned(p)?;
            Self::doctor().await?;
            if let Some(acme) = &p.desired.acme {
                let runtime = SecretStore::open(self.root.join("runtime-secrets"))?;
                let renew = crate::certificate::public_status(&runtime).is_ok();
                crate::certificate::acme(&self.root, acme, renew).await?;
            }
            if p.desired.mode == Mode::DirectPublic {
                crate::certificate::public_status(&SecretStore::open(
                    self.root.join("runtime-secrets"),
                )?)?;
            }
            runtime_permissions(&self.root)?;
            let cfg = gateway_config(p);
            aegis_config::parse_json(&cfg).map_err(|_| Error("generated_config_invalid"))?;
            if self.root.join("runtime-state/state.db").exists() {
                if self.ipc(&json!({"cmd":"config_inspect"})).await.is_err() {
                    // Restore the last owned deployment before changing its files.
                    self.compose_command(
                        &["up", "--detach", "--wait", "--wait-timeout", "60"],
                        None,
                        Duration::from_secs(90),
                    )
                    .await?;
                }
                let current = self.ipc(&json!({"cmd":"config_inspect"})).await?;
                let old = aegis_config::parse_json(&current["specification"])
                    .map_err(|_| Error("stored_configuration_invalid"))?;
                let new = aegis_config::parse_json(&cfg)
                    .map_err(|_| Error("generated_config_invalid"))?;
                if !aegis_config::security_diff(Some(&old), &new)
                    .restart_required
                    .is_empty()
                {
                    return Err(Error("host_configuration_restart_migration_required"));
                }
            }
            let files = SecretStore::open(&self.root)?;
            // The seed is immutable after first install. Subsequent changes go
            // through config_apply on the running coordinator below.
            if !self.root.join("gateway.json").exists() {
                files.put("gateway.json", &cfg.to_string(), false)?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{chown, MetadataExt};
                if std::fs::metadata(&self.root)
                    .map_err(|_| Error("host_directory_unavailable"))?
                    .uid()
                    == 0
                {
                    chown(
                        self.root.join("gateway.json"),
                        Some(self.bootstrap.runtime_uid),
                        Some(self.bootstrap.runtime_gid),
                    )
                    .map_err(|_| Error("runtime_secret_ownership_failed"))?;
                }
            }
            if let Some(token) = token {
                let secrets = SecretStore::open(self.root.join("connector-secrets"))?;
                secrets.put("token", token, true)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{chown, MetadataExt};
                    if std::fs::metadata(&self.root)
                        .map_err(|_| Error("host_directory_unavailable"))?
                        .uid()
                        == 0
                    {
                        chown(
                            secrets.root().join("token"),
                            Some(self.bootstrap.runtime_uid),
                            Some(self.bootstrap.runtime_gid),
                        )
                        .map_err(|_| Error("runtime_secret_ownership_failed"))?;
                    }
                }
            }
            let document = compose(p, &self.root, &self.bootstrap)?;
            files.put("compose.json", &document.to_string(), true)?;
            self.compose_command(&["config", "--quiet"], None, Duration::from_secs(30))
                .await?;
            self.compose_command(&["pull", "--quiet"], None, Duration::from_secs(300))
                .await?;
            if p.desired.nginx_image.is_some() {
                self.compose_command(
                    &[
                        "up",
                        "--detach",
                        "--wait",
                        "--wait-timeout",
                        "60",
                        "gateway",
                    ],
                    None,
                    Duration::from_secs(90),
                )
                .await?;
                self.reload_nginx(p).await?;
            } else {
                self.compose_command(
                    &["up", "--detach", "--wait", "--wait-timeout", "60"],
                    None,
                    Duration::from_secs(90),
                )
                .await?;
            }
            let applied=self.ipc(&json!({"cmd":"config_apply","specification":cfg,"expected_revision":p.expected_revision,"operation_key":p.id})).await?;
            if applied["applied"] != true {
                return Err(Error("configuration_not_applied"));
            }
            let probe = SecretStore::open(self.root.join("probe-secrets"))?;
            self.ipc(&json!({"cmd":"identity_register","certificate_pem":crate::trust::read_bundle(&probe,"probe-identity.json")?.cert_pem,"replace":true})).await?;
            Ok(())
        })
    }
    fn verify<'a>(&'a self, p: &'a Plan) -> StepFuture<'a, String> {
        Box::pin(async move {
            self.owned(p)?;
            let health = self.ipc(&json!({"cmd":"health"})).await?;
            if health["admission_enabled"] != true {
                return Err(Error("gateway_admission_closed"));
            }
            health["runtime_revision_id"]
                .as_str()
                .map(str::to_owned)
                .ok_or(Error("gateway_not_ready"))
        })
    }
    fn remove<'a>(&'a self, p: &'a Plan) -> StepFuture<'a, ()> {
        Box::pin(async move {
            self.owned(p)?;
            // No --volumes, rm -rf or image pruning. Preserve state, identity keys,
            // controller journal and independent Docker resources for recovery.
            self.compose_command(&["down", "--timeout", "15"], None, Duration::from_secs(60))
                .await?;
            Ok(())
        })
    }
}
