//! Authentication, sessions, CSRF and RBAC (04 §4).

use crate::http_util::ApiError;
use crate::ManagementContext;
use aegis_storage::{self as db, AuditInsert};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::Engine;
use http::{header, HeaderMap, Method, StatusCode};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

pub const ROLE_OWNER: &str = "owner";
pub const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);
pub const BOOTSTRAP_TTL_SECONDS: i64 = 15 * 60;
const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(15 * 60);
const COOKIE: &str = "aegis_session";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    NodesRead,
    NodesWrite,
    ProfilesRead,
    ProfilesWrite,
    ProfilesActivate,
    IdentityRevoke,
    TelemetryRead,
    TelemetryConfigure,
    DiagnosticsExplain,
    AuditRead,
    NetworkRead,
    NetworkAppsRead,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::NodesRead => "nodes:read",
            Permission::NodesWrite => "nodes:write",
            Permission::ProfilesRead => "profiles:read",
            Permission::ProfilesWrite => "profiles:write",
            Permission::ProfilesActivate => "profiles:activate",
            Permission::IdentityRevoke => "identity:revoke",
            Permission::TelemetryRead => "telemetry:read",
            Permission::TelemetryConfigure => "telemetry:configure",
            Permission::DiagnosticsExplain => "diagnostics:explain",
            Permission::AuditRead => "audit:read",
            Permission::NetworkRead => "network:read",
            Permission::NetworkAppsRead => "network:apps:read",
        }
    }

    pub const ALL: [Permission; 12] = [
        Permission::NodesRead,
        Permission::NodesWrite,
        Permission::ProfilesRead,
        Permission::ProfilesWrite,
        Permission::ProfilesActivate,
        Permission::IdentityRevoke,
        Permission::TelemetryRead,
        Permission::TelemetryConfigure,
        Permission::DiagnosticsExplain,
        Permission::AuditRead,
        Permission::NetworkRead,
        Permission::NetworkAppsRead,
    ];
}

/// Default grants (04 §4 table).
pub fn role_permissions(role: &str) -> Vec<Permission> {
    use Permission::*;
    match role {
        ROLE_OWNER => Permission::ALL.to_vec(),
        "operator" => vec![
            NodesRead,
            ProfilesRead,
            ProfilesWrite,
            ProfilesActivate,
            TelemetryRead,
            DiagnosticsExplain,
            AuditRead,
            NetworkRead,
        ],
        "viewer" => vec![NodesRead, ProfilesRead, TelemetryRead, NetworkRead],
        _ => vec![],
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialKind {
    Cookie,
    Bearer,
}

#[derive(Clone, Debug)]
struct AdminSession {
    principal_id: String,
    scopes: Vec<String>,
    csrf_token: String,
    expires_at: i64,
    kind: CredentialKind,
}

/// Authenticated caller of one request.
#[derive(Clone, Debug)]
pub struct Principal {
    pub id: String,
    pub scopes: Vec<String>,
    pub kind: CredentialKind,
    pub expires_at: i64,
    pub csrf_token: Option<String>,
}

impl Principal {
    pub fn has(&self, p: Permission) -> bool {
        self.scopes.iter().any(|s| s == p.as_str())
    }

    pub fn require(&self, p: Permission) -> Result<(), ApiError> {
        if self.has(p) {
            Ok(())
        } else {
            Err(ApiError::forbidden())
        }
    }
}

#[derive(Default)]
struct Limiter {
    failures: HashMap<String, (u32, Instant)>,
    window_start: Option<Instant>,
    window_count: u32,
}

#[derive(Default)]
pub struct AuthState {
    sessions: Mutex<HashMap<String, AdminSession>>,
    limiter: Mutex<Limiter>,
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn token_key(token: &str) -> String {
    db::sha256_hex(token.as_bytes())
}

pub fn hash_password(pw: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "hash_failed"))
}

fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_owned())
}

fn is_mutation(m: &Method) -> bool {
    matches!(
        *m,
        Method::POST | Method::PATCH | Method::DELETE | Method::PUT
    )
}

impl ManagementContext {
    /// Authenticate a request. Cookie-authenticated mutations require a
    /// matching `X-CSRF-Token`; bearer requests never use ambient cookies.
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        method: &Method,
    ) -> Result<Principal, ApiError> {
        let now = db::now_unix();
        let bearer = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned);
        let (token, kind) = match bearer {
            Some(t) => (t, CredentialKind::Bearer),
            None => (
                cookie_token(headers).ok_or_else(ApiError::unauthenticated)?,
                CredentialKind::Cookie,
            ),
        };
        let mut sessions = self.auth.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let key = token_key(&token);
        let s = sessions
            .get(&key)
            .cloned()
            .ok_or_else(ApiError::unauthenticated)?;
        if s.kind != kind {
            return Err(ApiError::unauthenticated());
        }
        if s.expires_at <= now {
            sessions.remove(&key);
            return Err(ApiError::unauthenticated());
        }
        drop(sessions);
        if kind == CredentialKind::Cookie && is_mutation(method) {
            let sent = headers
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let ok = sent.len() == s.csrf_token.len()
                && bool::from(sent.as_bytes().ct_eq(s.csrf_token.as_bytes()));
            if !ok {
                return Err(ApiError::forbidden().detail("missing or invalid CSRF token"));
            }
        }
        Ok(Principal {
            id: s.principal_id,
            scopes: s.scopes,
            csrf_token: (kind == CredentialKind::Cookie).then_some(s.csrf_token),
            kind,
            expires_at: s.expires_at,
        })
    }

    fn scopes_for(roles: &[String]) -> Vec<String> {
        let mut scopes: Vec<String> = roles
            .iter()
            .flat_map(|r| role_permissions(r))
            .map(|p| p.as_str().to_owned())
            .collect();
        scopes.sort();
        scopes.dedup();
        scopes
    }

    fn rate_limited(&self, username: &str) -> bool {
        let mut l = self.auth.limiter.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        // Global bucket: 30 attempts per minute.
        match l.window_start {
            Some(t) if now.duration_since(t) < Duration::from_secs(60) => l.window_count += 1,
            _ => {
                l.window_start = Some(now);
                l.window_count = 1;
            }
        }
        if l.window_count > 30 {
            return true;
        }
        matches!(l.failures.get(username), Some((n, t)) if *n >= MAX_FAILURES && now.duration_since(*t) < LOCKOUT)
    }

    fn record_failure(&self, username: &str) {
        let mut l = self.auth.limiter.lock().unwrap_or_else(|e| e.into_inner());
        let e = l
            .failures
            .entry(username.to_owned())
            .or_insert((0, Instant::now()));
        if e.1.elapsed() >= LOCKOUT {
            *e = (0, Instant::now());
        }
        e.0 += 1;
        e.1 = Instant::now();
    }

    /// Password login → cookie session + CSRF token.
    pub fn login(&self, username: &str, password: &str) -> Result<(String, Principal), ApiError> {
        if self.rate_limited(username) {
            return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
        }
        let principal = self
            .coord
            .store()
            .read(|c| db::get_principal_by_username(c, username))
            .map_err(ApiError::from)?;
        // Verify against a dummy hash for unknown users to equalize timing.
        const DUMMY: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$7GmV7oV3yJ0mE3T5R3o2b0f3cX3H6l1o0vQ1o3Wq3gE";
        let ok = match &principal {
            Some(p) if p.status == "active" => verify_password(password, &p.password_hash),
            _ => {
                let _ = verify_password(password, DUMMY);
                false
            }
        };
        let audit_actor = principal.as_ref().map(|p| p.id.clone());
        if !ok {
            self.record_failure(username);
            let _ = self.coord.store().tx(|c| {
                db::append_audit(
                    c,
                    AuditInsert {
                        actor_id: audit_actor.as_deref(),
                        action: "auth.login",
                        target_type: "session",
                        target_id: None,
                        decision: "denied",
                        revision_digest: None,
                        metadata: serde_json::json!({}),
                    },
                )
            });
            return Err(ApiError::unauthenticated().detail("invalid credentials"));
        }
        let p = principal.ok_or_else(ApiError::unauthenticated)?;
        let token = random_token();
        let csrf = random_token();
        let expires_at = db::now_unix() + SESSION_TTL.as_secs() as i64;
        let scopes = Self::scopes_for(&p.roles);
        self.auth
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                token_key(&token),
                AdminSession {
                    principal_id: p.id.clone(),
                    scopes: scopes.clone(),
                    csrf_token: csrf.clone(),
                    expires_at,
                    kind: CredentialKind::Cookie,
                },
            );
        let _ = self.coord.store().tx(|c| {
            db::append_audit(
                c,
                AuditInsert {
                    actor_id: Some(&p.id),
                    action: "auth.login",
                    target_type: "session",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata: serde_json::json!({}),
                },
            )
        });
        Ok((
            token,
            Principal {
                id: p.id,
                scopes,
                kind: CredentialKind::Cookie,
                expires_at,
                csrf_token: Some(csrf),
            },
        ))
    }

    pub fn session_cookie(token: &str, max_age: u64) -> String {
        format!("{COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}")
    }

    pub fn logout(&self, headers: &HeaderMap) {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned)
            .or_else(|| cookie_token(headers));
        if let Some(t) = token {
            self.auth
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&token_key(&t));
        }
    }

    /// Mint a local one-use bootstrap token (only via local IPC, only
    /// while no owner exists). Only its verifier is stored.
    pub fn create_bootstrap_token(&self) -> Result<(String, i64), String> {
        let store = self.coord.store();
        if store.read(db::owner_exists).map_err(|e| e.to_string())? {
            return Err("an owner already exists; bootstrap is permanently disabled".into());
        }
        let token = random_token();
        let expires = db::now_unix() + BOOTSTRAP_TTL_SECONDS;
        store
            .tx(|c| {
                db::insert_bootstrap_token(c, &token_key(&token), expires)?;
                db::append_audit(
                    c,
                    AuditInsert {
                        actor_id: None,
                        action: "bootstrap.token_created",
                        target_type: "system",
                        target_id: None,
                        decision: "allowed",
                        revision_digest: None,
                        metadata: serde_json::json!({"source": "local_ipc"}),
                    },
                )
            })
            .map_err(|e| e.to_string())?;
        Ok((token, expires))
    }

    /// Atomically consume the bootstrap token and create the owner.
    pub fn claim_bootstrap(
        &self,
        token: &str,
        username: &str,
        password: &str,
    ) -> Result<String, ApiError> {
        if username.is_empty()
            || username.len() > 100
            || !username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b))
        {
            return Err(ApiError::bad_request("invalid_username"));
        }
        if password.chars().count() < 12 || password.len() > 1024 {
            return Err(ApiError::bad_request("weak_password")
                .detail("owner password must be at least 12 characters"));
        }
        let hash = hash_password(password)?;
        let id = db::new_id();
        let verifier = token_key(token);
        let res = self.coord.store().tx(|c| {
            if db::owner_exists(c)? {
                return Err(db::StoreError::Conflict("owner exists".into()));
            }
            if !db::consume_bootstrap_token(c, &verifier, db::now_unix())? {
                return Err(db::StoreError::NotFound);
            }
            db::insert_principal(
                c,
                &db::PrincipalRow {
                    id: id.clone(),
                    username: username.to_owned(),
                    password_hash: hash.clone(),
                    status: "active".into(),
                    roles: vec![ROLE_OWNER.into()],
                },
            )?;
            db::append_audit(
                c,
                AuditInsert {
                    actor_id: Some(&id),
                    action: "bootstrap.claim",
                    target_type: "principal",
                    target_id: Some(&id),
                    decision: "allowed",
                    revision_digest: None,
                    metadata: serde_json::json!({}),
                },
            )?;
            Ok(())
        });
        match res {
            Ok(()) => Ok(id),
            Err(db::StoreError::Conflict(_)) => Err(ApiError::conflict("bootstrap_disabled")),
            Err(db::StoreError::NotFound) => {
                Err(ApiError::unauthenticated().detail("invalid, used or expired bootstrap token"))
            }
            Err(_) => Err(ApiError::unavailable()),
        }
    }

    /// Short-lived scoped bearer token for the local owner (IPC only).
    pub fn mint_bearer(
        &self,
        scopes: Option<Vec<String>>,
        ttl: Duration,
    ) -> Result<(String, i64), String> {
        let ttl = ttl.min(Duration::from_secs(3600));
        let owner = self
            .coord
            .store()
            .read(|c| {
                let id: Option<String> = c
                    .query_row(
                        "SELECT principal_id FROM principal_roles WHERE role = 'owner' LIMIT 1",
                        [],
                        |r| r.get(0),
                    )
                    .ok();
                Ok(id)
            })
            .map_err(|e| e.to_string())?
            .ok_or("no owner exists; run bootstrap first")?;
        let all = Self::scopes_for(&[ROLE_OWNER.to_owned()]);
        let scopes = match scopes {
            Some(s) => {
                if s.iter().any(|x| !all.contains(x)) {
                    return Err("unknown scope requested".into());
                }
                s
            }
            None => all,
        };
        let token = random_token();
        let expires_at = db::now_unix() + ttl.as_secs() as i64;
        self.auth
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                token_key(&token),
                AdminSession {
                    principal_id: owner,
                    scopes,
                    csrf_token: random_token(),
                    expires_at,
                    kind: CredentialKind::Bearer,
                },
            );
        Ok((token, expires_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_table_matches_spec() {
        let owner = role_permissions("owner");
        assert_eq!(owner.len(), Permission::ALL.len());
        let viewer = role_permissions("viewer");
        assert!(
            !viewer.contains(&Permission::TelemetryConfigure),
            "viewer cannot change export"
        );
        assert!(!viewer.contains(&Permission::ProfilesActivate));
        let op = role_permissions("operator");
        assert!(!op.contains(&Permission::IdentityRevoke));
        assert!(!op.contains(&Permission::NodesWrite));
        assert!(role_permissions("unknown").is_empty());
    }

    #[test]
    fn password_hashing_roundtrip() {
        let h = hash_password("correct horse battery").expect("hash");
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong", &h));
    }
}
