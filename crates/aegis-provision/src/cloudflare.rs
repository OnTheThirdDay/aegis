//! Cloudflare v4 remotely-managed Tunnel and DNS API. No Dashboard automation,
//! redirects, environment proxy, global API keys or error-body logging.
use crate::*;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::time::Duration;
use zeroize::Zeroizing;

pub struct Cloudflare {
    client: Client,
    base: String,
    token: Zeroizing<String>,
}
impl std::fmt::Debug for Cloudflare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cloudflare { credential: <redacted> }")
    }
}
impl Cloudflare {
    pub fn new(token: Zeroizing<String>) -> Result<Self> {
        if token.is_empty()
            || token.len() > 4096
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(Error("invalid_cloudflare_token"));
        }
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| Error("provider_client_unavailable"))?;
        Ok(Self {
            client,
            base: "https://api.cloudflare.com/client/v4".into(),
            token,
        })
    }

    async fn request(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        let mut req = self
            .client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(self.token.as_str());
        if let Some(body) = body {
            req = req.json(&body);
        }
        let mut response = req
            .send()
            .await
            .map_err(|_| Error("cloudflare_network_or_tls_failure"))?;
        match response.status().as_u16() {
            401 | 403 => return Err(Error("cloudflare_insufficient_permissions")),
            409 => return Err(Error("cloudflare_resource_conflict")),
            429 => return Err(Error("cloudflare_rate_limited_retry_later")),
            404 => return Err(Error("cloudflare_resource_not_found")),
            500..=599 => return Err(Error("cloudflare_temporarily_unavailable")),
            200..=299 => {}
            _ => return Err(Error("cloudflare_request_rejected")),
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Error("cloudflare_invalid_response"))?
        {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err(Error("cloudflare_response_too_large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let parsed: Value =
            serde_json::from_slice(&bytes).map_err(|_| Error("cloudflare_invalid_response"))?;
        if parsed["success"] != true {
            return Err(Error("cloudflare_operation_rejected"));
        }
        parsed
            .get("result")
            .cloned()
            .ok_or(Error("cloudflare_invalid_response"))
    }
    /// Read-only capability check; write authorization is additionally checked
    /// by each API operation. Token verification alone cannot prove write scopes.
    pub async fn check_token(&self) -> Result<()> {
        let result = self
            .request(Method::GET, "/user/tokens/verify", None)
            .await?;
        if result["status"] != "active" {
            return Err(Error("cloudflare_token_inactive"));
        }
        Ok(())
    }
    /// The accessible zone that most specifically contains `hostname`.
    pub async fn zone_for(&self, hostname: &str) -> Result<(String, String)> {
        if aegis_contracts::destination::normalize_domain(hostname).as_deref() != Ok(hostname) {
            return Err(Error("invalid_hostname"));
        }
        let mut best: Option<(String, String)> = None;
        for z in self.zones().await? {
            let (Some(id), Some(name)) = (z["id"].as_str(), z["name"].as_str()) else {
                continue;
            };
            let inside = hostname == name || hostname.ends_with(&format!(".{name}"));
            if inside && provider_id(id) && best.as_ref().is_none_or(|(_, n)| name.len() > n.len())
            {
                best = Some((id.to_owned(), name.to_owned()));
            }
        }
        best.ok_or(Error("zone_not_accessible"))
    }

    /// Create an ACME DNS-01 TXT record labelled with `comment` (ownership
    /// marker); returns the record id for removal.
    pub async fn create_txt(
        &self,
        zone_id: &str,
        name: &str,
        content: &str,
        comment: &str,
    ) -> Result<String> {
        let safe = |s: &str| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-:".contains(&b))
        };
        if !provider_id(zone_id)
            || aegis_contracts::destination::normalize_domain(name).as_deref() != Ok(name)
            || !safe(content)
            || !safe(comment)
        {
            return Err(Error("invalid_dns_challenge"));
        }
        let record = self
            .request(
                Method::POST,
                &format!("/zones/{zone_id}/dns_records"),
                Some(json!({"type":"TXT","name":name,"content":format!("\"{content}\""),"ttl":60,"comment":comment})),
            )
            .await?;
        record["id"]
            .as_str()
            .filter(|id| provider_id(id))
            .map(str::to_owned)
            .ok_or(Error("cloudflare_invalid_response"))
    }

    /// Delete a record this process created (by id; never by name).
    pub async fn delete_record(&self, zone_id: &str, id: &str) -> Result<()> {
        if !provider_id(zone_id) || !provider_id(id) {
            return Err(Error("invalid_dns_id"));
        }
        self.request(
            Method::DELETE,
            &format!("/zones/{zone_id}/dns_records/{id}"),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn zones(&self) -> Result<Vec<Value>> {
        let mut zones = Vec::new();
        for page in 1..=20 {
            let result = self
                .request(
                    Method::GET,
                    &format!("/zones?per_page=50&page={page}"),
                    None,
                )
                .await?;
            let items = result
                .as_array()
                .ok_or(Error("cloudflare_invalid_response"))?;
            for z in items {
                zones.push(json!({"id":z["id"],"name":z["name"],"account_id":z["account"]["id"],"status":z["status"]}));
            }
            if items.len() < 50 {
                return Ok(zones);
            }
        }
        Err(Error("cloudflare_zone_discovery_limit"))
    }
    fn tunnel_path(p: &Plan) -> Result<String> {
        let account = p
            .desired
            .account_id
            .as_deref()
            .filter(|s| provider_id(s))
            .ok_or(Error("invalid_account_id"))?;
        let id = p
            .inventory
            .tunnel_id
            .as_deref()
            .filter(|s| tunnel_id(s))
            .ok_or(Error("tunnel_id_required"))?;
        Ok(format!("/accounts/{account}/cfd_tunnel/{id}"))
    }
    fn dns_path(p: &Plan) -> Result<String> {
        let zone = p
            .desired
            .zone_id
            .as_deref()
            .filter(|s| provider_id(s))
            .ok_or(Error("invalid_zone_id"))?;
        Ok(format!("/zones/{zone}/dns_records"))
    }
    fn marker(p: &Plan) -> String {
        format!("aegis:{}", p.desired.deployment_id)
    }
    fn name(p: &Plan) -> String {
        format!("aegis-{}", p.desired.deployment_id)
    }
    /// Only the device paths reach the origin: the AGP WebSocket and the
    /// edge enrollment/renewal endpoints. Never the management console.
    /// Device paths and the user portal; nothing else of the gateway is
    /// published (the console never is).
    const ROUTES: &'static str = "^/(agp|enroll|renew|portal(/.*)?)$";
    /// Routes written before the user portal existed: recognised as this
    /// deployment's own and updated in place rather than treated as drift.
    const LEGACY_ROUTES: &'static str = "^/(agp|enroll|renew)$";

    fn ingress_config(p: &Plan) -> Value {
        Self::ingress_with(p, Self::ROUTES)
    }

    fn ingress_with(p: &Plan, path: &str) -> Value {
        let service = p
            .desired
            .origin_service
            .as_deref()
            .unwrap_or("http://gateway:18080");
        json!({"ingress":[{"hostname":p.desired.hostname,"path":path,"service":service},{"service":"http_status:404"}]})
    }

    /// The stored routing is exactly what an earlier AegisBorne wrote.
    fn legacy_ingress(actual: &Value, p: &Plan) -> bool {
        match (
            Self::routing(actual),
            Self::routing(&Self::ingress_with(p, Self::LEGACY_ROUTES)),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }
    /// The routing that matters in a stored tunnel configuration: each
    /// rule's (hostname, path, service). Cloudflare returns the stored
    /// document with server-side defaults added (`warp-routing`, empty
    /// `originRequest`), so byte equality is the wrong test. Any non-default
    /// extra (origin options, enabled WARP routing) counts as foreign.
    fn routing(config: &Value) -> Option<Vec<(Value, Value, Value)>> {
        let obj = config.as_object()?;
        for (k, v) in obj {
            let default = match k.as_str() {
                "ingress" => true,
                "warp-routing" => v.get("enabled").is_none_or(|e| e == false),
                "originRequest" => v.as_object().is_some_and(|o| o.is_empty()),
                _ => false,
            };
            if !default {
                return None;
            }
        }
        obj.get("ingress")?
            .as_array()?
            .iter()
            .map(|rule| {
                let r = rule.as_object()?;
                let allowed = r.iter().all(|(k, v)| match k.as_str() {
                    "hostname" | "path" | "service" => true,
                    "originRequest" => v.as_object().is_some_and(|o| o.is_empty()),
                    _ => false,
                });
                allowed.then(|| {
                    (
                        r.get("hostname").cloned().unwrap_or(Value::Null),
                        r.get("path").cloned().unwrap_or(Value::Null),
                        r.get("service").cloned().unwrap_or(Value::Null),
                    )
                })
            })
            .collect()
    }

    fn same_ingress(actual: &Value, p: &Plan) -> bool {
        match (
            Self::routing(actual),
            Self::routing(&Self::ingress_config(p)),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// A configuration with no routing yet (fresh remotely-managed tunnel).
    fn unconfigured(config: &Value) -> bool {
        config.is_null()
            || config == &json!({})
            || Self::routing(config).is_some_and(|r| r.is_empty())
    }

    async fn owned_tunnel(&self, p: &Plan) -> Result<Value> {
        let tunnel = self
            .request(Method::GET, &Self::tunnel_path(p)?, None)
            .await?;
        if tunnel["name"] != Self::name(p)
            || tunnel["remote_config"] != true
            || !tunnel["deleted_at"].is_null()
        {
            return Err(Error("tunnel_ownership_mismatch"));
        }
        Ok(tunnel)
    }
    async fn records(&self, p: &Plan) -> Result<Vec<Value>> {
        let host = p
            .desired
            .hostname
            .as_deref()
            .ok_or(Error("hostname_required"))?;
        // Validated canonical DNS names contain no query delimiters.
        let rows = self
            .request(
                Method::GET,
                &format!("{}?name={host}&per_page=100", Self::dns_path(p)?),
                None,
            )
            .await?;
        let rows = rows
            .as_array()
            .ok_or(Error("cloudflare_invalid_response"))?;
        if rows.len() >= 100 {
            return Err(Error("cloudflare_record_discovery_limit"));
        }
        Ok(rows.clone())
    }
    fn record_owned(p: &Plan, r: &Value) -> bool {
        r["comment"] == Self::marker(p)
            && r["name"] == p.desired.hostname.as_deref().unwrap_or("")
            && r["type"] == "CNAME"
            && r["content"]
                == format!(
                    "{}.cfargotunnel.com",
                    p.inventory.tunnel_id.as_deref().unwrap_or("")
                )
            && r["proxied"] == true
    }
}

impl InfrastructureProvider for Cloudflare {
    fn validate<'a>(&'a self, p: &'a Plan) -> StepFuture<'a, ()> {
        Box::pin(async move {
            p.desired.validate()?;
            self.check_token().await?;
            let zone = p
                .desired
                .zone_id
                .as_deref()
                .ok_or(Error("zone_id_required"))?;
            let z = self
                .request(Method::GET, &format!("/zones/{zone}"), None)
                .await?;
            if z["account"]["id"] != p.desired.account_id.as_deref().unwrap_or("")
                || z["status"] != "active"
            {
                return Err(Error("cloudflare_zone_account_mismatch"));
            }
            let name = z["name"]
                .as_str()
                .ok_or(Error("cloudflare_invalid_response"))?;
            let host = p
                .desired
                .hostname
                .as_deref()
                .ok_or(Error("hostname_required"))?;
            if host != name
                && !host
                    .strip_suffix(&format!(".{name}"))
                    .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('.'))
            {
                return Err(Error("hostname_outside_free_edge_certificate_scope"));
            }
            let records = self.records(p).await?;
            if !records.is_empty() && records.iter().any(|r| !Self::record_owned(p, r)) {
                return Err(Error("dns_record_not_owned"));
            }
            Ok(())
        })
    }
    fn tunnel<'a>(&'a self, p: &'a Plan) -> StepFuture<'a, Inventory> {
        Box::pin(async move {
            if p.inventory.tunnel_id.is_some() {
                self.owned_tunnel(p).await?;
                return Ok(p.inventory.clone());
            }
            let account = p
                .desired
                .account_id
                .as_deref()
                .ok_or(Error("account_id_required"))?;
            let name = Self::name(p);
            let found = self
                .request(
                    Method::GET,
                    &format!(
                        "/accounts/{account}/cfd_tunnel?name={name}&is_deleted=false&per_page=100"
                    ),
                    None,
                )
                .await?;
            let found = found
                .as_array()
                .ok_or(Error("cloudflare_invalid_response"))?;
            if !found.is_empty() {
                return Err(Error(
                    "tunnel_create_outcome_unknown_requires_ownership_review",
                ));
            }
            let created = self
                .request(
                    Method::POST,
                    &format!("/accounts/{account}/cfd_tunnel"),
                    Some(json!({"name":name,"config_src":"cloudflare"})),
                )
                .await?;
            let id = created["id"]
                .as_str()
                .filter(|id| tunnel_id(id))
                .ok_or(Error("cloudflare_invalid_response"))?;
            let mut inventory = p.inventory.clone();
            inventory.tunnel_id = Some(id.into());
            inventory.created_tunnel = true;
            Ok(inventory)
        })
    }
    fn ingress<'a>(&'a self, p: &'a Plan) -> StepFuture<'a, ()> {
        Box::pin(async move {
            self.owned_tunnel(p).await?;
            let path = format!("{}/configurations", Self::tunnel_path(p)?);
            let current = self.request(Method::GET, &path, None).await?;
            let desired = Self::ingress_config(p);
            if Self::same_ingress(&current["config"], p) {
                return Ok(());
            }
            // Refuse drift into an unrelated origin; only our empty new tunnel,
            // the same previously owned routing, or our own older routing can
            // be configured automatically.
            if !Self::unconfigured(&current["config"])
                && !Self::legacy_ingress(&current["config"], p)
            {
                return Err(Error("tunnel_ingress_drift_requires_review"));
            }
            self.request(Method::PUT, &path, Some(json!({"config":desired})))
                .await?;
            Ok(())
        })
    }
    fn dns<'a>(&'a self, p: &'a Plan) -> StepFuture<'a, Inventory> {
        Box::pin(async move {
            let records = self.records(p).await?;
            let mut inventory = p.inventory.clone();
            if records.len() == 1 && Self::record_owned(p, &records[0]) {
                inventory.dns_id = records[0]["id"].as_str().map(str::to_owned);
                if inventory
                    .dns_id
                    .as_deref()
                    .is_none_or(|id| !provider_id(id))
                {
                    return Err(Error("cloudflare_invalid_response"));
                }
                // An owned marker and tunnel binding prove a timed-out creation;
                // never infer ownership from the hostname alone.
                inventory.created_dns = true;
                return Ok(inventory);
            }
            if !records.is_empty() {
                return Err(Error("dns_record_not_owned"));
            }
            let record=self.request(Method::POST,&Self::dns_path(p)?,Some(json!({"type":"CNAME","name":p.desired.hostname,"content":format!("{}.cfargotunnel.com",p.inventory.tunnel_id.as_deref().ok_or(Error("tunnel_id_required"))?),"proxied":true,"ttl":1,"comment":Self::marker(p)}))).await?;
            let id = record["id"]
                .as_str()
                .filter(|id| provider_id(id))
                .ok_or(Error("cloudflare_invalid_response"))?;
            inventory.dns_id = Some(id.into());
            inventory.created_dns = true;
            Ok(inventory)
        })
    }
    fn connector_token<'a>(&'a self, p: &'a Plan) -> StepFuture<'a, Zeroizing<String>> {
        Box::pin(async move {
            self.owned_tunnel(p).await?;
            let token = self
                .request(
                    Method::GET,
                    &format!("{}/token", Self::tunnel_path(p)?),
                    None,
                )
                .await?;
            let token = token
                .as_str()
                .filter(|s| {
                    !s.is_empty() && s.len() <= 16384 && s.bytes().all(|b| b.is_ascii_graphic())
                })
                .ok_or(Error("cloudflare_invalid_connector_token"))?;
            Ok(Zeroizing::new(token.into()))
        })
    }
    fn verify<'a>(&'a self, p: &'a Plan) -> StepFuture<'a, ()> {
        Box::pin(async move {
            let tunnel = self.owned_tunnel(p).await?;
            if tunnel["status"] != "healthy" {
                return Err(Error("cloudflare_connector_not_healthy"));
            }
            let config = self
                .request(
                    Method::GET,
                    &format!("{}/configurations", Self::tunnel_path(p)?),
                    None,
                )
                .await?;
            if !Self::same_ingress(&config["config"], p) {
                if !Self::legacy_ingress(&config["config"], p) {
                    return Err(Error("cloudflare_ingress_drift"));
                }
                // Our own routes from before the user portal: bring them up
                // to date (an active tunnel re-verified with its token).
                self.request(
                    Method::PUT,
                    &format!("{}/configurations", Self::tunnel_path(p)?),
                    Some(json!({"config": Self::ingress_config(p)})),
                )
                .await?;
            }
            let records = self.records(p).await?;
            if records.len() != 1 || !Self::record_owned(p, &records[0]) {
                return Err(Error("cloudflare_dns_drift"));
            }
            Ok(())
        })
    }
    fn cleanup<'a>(&'a self, p: &'a Plan, keep_dns: bool, keep_tunnel: bool) -> StepFuture<'a, ()> {
        Box::pin(async move {
            if !keep_dns && p.inventory.created_dns {
                for record in self.records(p).await? {
                    if Some(record["id"].as_str().unwrap_or("")) == p.inventory.dns_id.as_deref() {
                        if !Self::record_owned(p, &record) {
                            return Err(Error("dns_record_not_owned"));
                        }
                        let id = record["id"]
                            .as_str()
                            .filter(|id| provider_id(id))
                            .ok_or(Error("invalid_dns_id"))?;
                        self.request(
                            Method::DELETE,
                            &format!("{}/{id}", Self::dns_path(p)?),
                            None,
                        )
                        .await?;
                    }
                }
            }
            if !keep_tunnel && p.inventory.created_tunnel {
                // Keeping a DNS record must not strand it pointing at a deleted tunnel.
                if keep_dns {
                    return Err(Error("keep_dns_requires_keep_tunnel"));
                }
                match self.owned_tunnel(p).await {
                    Ok(_) => {
                        self.request(Method::DELETE, &Self::tunnel_path(p)?, None)
                            .await?;
                    }
                    Err(Error("cloudflare_resource_not_found")) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        })
    }
}

/// Private/local mode never makes a provider request.
pub struct NoProvider;
impl InfrastructureProvider for NoProvider {
    fn validate<'a>(&'a self, _: &'a Plan) -> StepFuture<'a, ()> {
        Box::pin(async { Err(Error("provider_not_configured")) })
    }
    fn tunnel<'a>(&'a self, _: &'a Plan) -> StepFuture<'a, Inventory> {
        Box::pin(async { Err(Error("provider_not_configured")) })
    }
    fn ingress<'a>(&'a self, _: &'a Plan) -> StepFuture<'a, ()> {
        Box::pin(async { Err(Error("provider_not_configured")) })
    }
    fn dns<'a>(&'a self, _: &'a Plan) -> StepFuture<'a, Inventory> {
        Box::pin(async { Err(Error("provider_not_configured")) })
    }
    fn connector_token<'a>(&'a self, _: &'a Plan) -> StepFuture<'a, Zeroizing<String>> {
        Box::pin(async { Err(Error("provider_not_configured")) })
    }
    fn verify<'a>(&'a self, _: &'a Plan) -> StepFuture<'a, ()> {
        Box::pin(async { Err(Error("provider_not_configured")) })
    }
    fn cleanup<'a>(&'a self, _: &'a Plan, _: bool, _: bool) -> StepFuture<'a, ()> {
        Box::pin(async { Err(Error("provider_not_configured")) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Request, State},
        response::IntoResponse,
        routing::any,
        Json, Router,
    };
    use std::sync::{Arc, Mutex};
    #[derive(Default)]
    struct StateData {
        tunnel: Option<Value>,
        config: Value,
        records: Vec<Value>,
        creates: usize,
        dns_creates: usize,
        deletes: usize,
        deny: bool,
        timeout_create: bool,
    }
    async fn api(
        State(state): State<Arc<Mutex<StateData>>>,
        request: Request,
    ) -> axum::response::Response {
        assert_eq!(
            request.headers()["authorization"],
            "Bearer SECRET_TOKEN_CANARY"
        );
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let bytes = axum::body::to_bytes(request.into_body(), 65536)
            .await
            .expect("bounded mock request");
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let mut state = state.lock().expect("mock");
        if state.deny {
            return (
                http_status(403),
                Json(json!({"success":false,"errors":[{"message":"SECRET_TOKEN_CANARY"}]})),
            )
                .into_response();
        }
        let result = if path == "/user/tokens/verify" {
            json!({"status":"active"})
        } else if path == format!("/zones/{}", "b".repeat(32)) {
            json!({"name":"example.test","status":"active","account":{"id":"a".repeat(32)}})
        } else if path.ends_with("/dns_records") {
            if method == Method::POST {
                state.dns_creates += 1;
                let mut record = body;
                record["id"] = json!("d".repeat(32));
                state.records.push(record.clone());
                record
            } else {
                json!(state.records)
            }
        } else if path.contains("/dns_records/") && method == Method::DELETE {
            state.deletes += 1;
            state.records.clear();
            json!({"id":"d".repeat(32)})
        } else if path.ends_with("/configurations") {
            if method == Method::PUT {
                state.config = body["config"].clone();
            }
            // Like the real API: defaults are added to the stored document.
            let mut config = state.config.clone();
            if let Some(o) = config.as_object_mut() {
                o.insert("warp-routing".into(), json!({"enabled": false}));
                if let Some(first) = o.get_mut("ingress").and_then(|i| i.get_mut(0)) {
                    first["originRequest"] = json!({});
                }
            }
            json!({"config":config})
        } else if path.ends_with("/token") {
            json!("CONNECTOR_TOKEN_CANARY")
        } else if path.ends_with("/cfd_tunnel") {
            if method == Method::POST {
                state.creates += 1;
                let tunnel = json!({"id":"01234567-89ab-4cde-8f01-23456789abcd","name":body["name"],"remote_config":true,"status":"healthy","deleted_at":null});
                state.tunnel = Some(tunnel.clone());
                if state.timeout_create {
                    return (
                        http_status(503),
                        Json(json!({"success":false,"errors":["SECRET_TOKEN_CANARY"]})),
                    )
                        .into_response();
                }
                tunnel
            } else {
                json!(state.tunnel.iter().collect::<Vec<_>>())
            }
        } else if path.contains("/cfd_tunnel/") {
            if method == Method::DELETE {
                state.deletes += 1;
                state.tunnel = None;
                json!({})
            } else {
                state.tunnel.clone().unwrap_or(Value::Null)
            }
        } else {
            return (http_status(404), Json(json!({"success":false,"errors":[]}))).into_response();
        };
        Json(json!({"success":true,"errors":[],"messages":[],"result":result})).into_response()
    }
    fn http_status(code: u16) -> axum::http::StatusCode {
        axum::http::StatusCode::from_u16(code).expect("status")
    }
    async fn mock() -> (Cloudflare, Arc<Mutex<StateData>>) {
        let state = Arc::new(Mutex::new(StateData::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let address = listener.local_addr().expect("address");
        let app = Router::new()
            .fallback(any(api))
            .with_state(Arc::clone(&state));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock server");
        });
        let provider = Cloudflare {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .expect("mock client"),
            base: format!("http://{address}"),
            token: Zeroizing::new("SECRET_TOKEN_CANARY".into()),
        };
        (provider, state)
    }
    fn plan() -> Plan {
        let desired = DesiredDeployment {
            schema_version: 1,
            deployment_id: "b8279db0-b592-42f0-b264-234567890abc".into(),
            mode: Mode::CloudflareTunnel,
            host: HostKind::Compose,
            origin_service: None,
            node_id: "gateway".into(),
            inner_server_name: "gateway.aegis.internal".into(),
            hostname: Some("edge.example.test".into()),
            account_id: Some("a".repeat(32)),
            zone_id: Some("b".repeat(32)),
            gateway_image: format!("example.invalid/aegis:0.1@sha256:{}", "a".repeat(64)),
            connector_image: Some(format!(
                "cloudflare/cloudflared:2026.10.0@sha256:{}",
                "c".repeat(64)
            )),
            nameservers: vec!["1.1.1.1:53".into()],
            verification_http_url: "http://example.test/".into(),
            verification_https_url: "https://example.test/".into(),
            acme: None,
            outer_trust_ca: None,
            nginx_image: None,
        };
        Controller::new(Arc::new(
            aegis_storage::Store::open_in_memory().expect("db"),
        ))
        .plan(desired, "owner", None)
        .expect("plan")
    }
    #[tokio::test]
    async fn real_adapter_contract_create_ingress_dns_token_verify_reapply_cleanup() {
        let (cf, state) = mock().await;
        let mut p = plan();
        cf.validate(&p).await.expect("discovery");
        p.inventory = cf.tunnel(&p).await.expect("tunnel");
        cf.ingress(&p).await.expect("ingress");
        p.inventory = cf.dns(&p).await.expect("dns");
        assert_eq!(
            cf.connector_token(&p)
                .await
                .expect("protected connector token")
                .as_str(),
            "CONNECTOR_TOKEN_CANARY"
        );
        cf.verify(&p)
            .await
            .expect("provider objects only, not data-path evidence");
        cf.validate(&p).await.expect("revalidate");
        p.inventory = cf.tunnel(&p).await.expect("reuse");
        cf.ingress(&p).await.expect("unchanged config");
        p.inventory = cf.dns(&p).await.expect("reuse dns");
        assert_eq!(state.lock().expect("mock").creates, 1);
        assert_eq!(state.lock().expect("mock").dns_creates, 1);
        let preview = serde_json::to_string(&p).expect("preview");
        assert!(
            !preview.contains("SECRET_TOKEN_CANARY") && !preview.contains("CONNECTOR_TOKEN_CANARY")
        );
        assert!(!format!("{cf:?}").contains("SECRET_TOKEN_CANARY"));
        cf.cleanup(&p, false, false).await.expect("owned cleanup");
        assert_eq!(state.lock().expect("mock").deletes, 2);
    }
    #[test]
    fn routing_comparison_ignores_server_defaults_but_not_foreign_rules() {
        let p = plan();
        let mut stored = Cloudflare::ingress_config(&p);
        stored["warp-routing"] = json!({"enabled": false});
        stored["ingress"][0]["originRequest"] = json!({});
        assert!(Cloudflare::same_ingress(&stored, &p));
        let mut other = stored.clone();
        other["ingress"][0]["service"] = json!("http://192.0.2.1:80");
        assert!(!Cloudflare::same_ingress(&other, &p));
        let mut warp = stored.clone();
        warp["warp-routing"] = json!({"enabled": true});
        assert!(!Cloudflare::same_ingress(&warp, &p) && !Cloudflare::unconfigured(&warp));
        let mut options = stored;
        options["ingress"][0]["originRequest"] = json!({"noTLSVerify": true});
        assert!(!Cloudflare::same_ingress(&options, &p));
        assert!(Cloudflare::unconfigured(
            &json!({"ingress": [], "warp-routing": {"enabled": false}})
        ));
    }

    #[tokio::test]
    async fn own_pre_portal_routes_are_updated_not_reported_as_drift() {
        let (cf, state) = mock().await;
        let mut p = plan();
        cf.validate(&p).await.expect("discovery");
        p.inventory = cf.tunnel(&p).await.expect("tunnel");
        p.inventory = cf.dns(&p).await.expect("dns");
        // A tunnel set up before the user portal existed.
        state.lock().expect("mock").config =
            Cloudflare::ingress_with(&p, Cloudflare::LEGACY_ROUTES);
        cf.verify(&p)
            .await
            .expect("active tunnel re-verified: routes updated");
        let stored = state.lock().expect("mock").config.clone();
        assert!(Cloudflare::same_ingress(&stored, &p), "{stored}");
        assert!(stored.to_string().contains("portal"));
        // Setup also accepts and updates them.
        state.lock().expect("mock").config =
            Cloudflare::ingress_with(&p, Cloudflare::LEGACY_ROUTES);
        cf.ingress(&p)
            .await
            .expect("ingress updates our own older routes");
        // Anything else is still drift.
        state.lock().expect("mock").config = Cloudflare::ingress_with(&p, "^/(agp|admin)$");
        assert_eq!(
            cf.verify(&p).await.expect_err("drift").0,
            "cloudflare_ingress_drift"
        );
        assert_eq!(
            cf.ingress(&p).await.expect_err("drift").0,
            "tunnel_ingress_drift_requires_review"
        );
    }

    #[tokio::test]
    async fn foreign_dns_and_credential_failures_are_nonsecret_and_never_deleted() {
        let (cf, state) = mock().await;
        let p = plan();
        state.lock().expect("mock").records.push(json!({"id":"d".repeat(32),"name":"edge.example.test","type":"A","content":"192.0.2.1"}));
        assert_eq!(
            cf.validate(&p).await.expect_err("conflict").0,
            "dns_record_not_owned"
        );
        assert_eq!(state.lock().expect("mock").deletes, 0);
        state.lock().expect("mock").deny = true;
        let error = cf.check_token().await.expect_err("denied");
        assert_eq!(error.0, "cloudflare_insufficient_permissions");
        assert!(!format!("{error:?}").contains("SECRET_TOKEN_CANARY"));
    }
    #[tokio::test]
    async fn ambiguous_creation_blocks_adoption_instead_of_duplicating_or_deleting() {
        let (cf, state) = mock().await;
        let p = plan();
        state.lock().expect("mock").timeout_create = true;
        assert!(cf.tunnel(&p).await.is_err());
        assert_eq!(
            cf.tunnel(&p).await.expect_err("unknown ownership").0,
            "tunnel_create_outcome_unknown_requires_ownership_review"
        );
        assert_eq!(state.lock().expect("mock").creates, 1);
        assert_eq!(state.lock().expect("mock").deletes, 0);
    }
}
