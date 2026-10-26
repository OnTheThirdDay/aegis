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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const ROLE_OWNER: &str = "owner";
pub const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);
pub const BOOTSTRAP_TTL_SECONDS: i64 = 15 * 60;
const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(15 * 60);
const COOKIE: &str = "aegis_session";
const BOOTSTRAP_ATTEMPTS_PER_MINUTE: u32 = 30;

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
    ProvisionRead,
    ProvisionWrite,
    ProviderConfigure,
    UsersManage,
    DevicesSelf,
    SystemConfigure,
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
            Permission::ProvisionRead => "provision:read",
            Permission::ProvisionWrite => "provision:write",
            Permission::ProviderConfigure => "providers:configure",
            Permission::UsersManage => "users:manage",
            Permission::DevicesSelf => "devices:self",
            Permission::SystemConfigure => "system:configure",
        }
    }

    pub const ALL: [Permission; 18] = [
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
        Permission::ProvisionRead,
        Permission::ProvisionWrite,
        Permission::ProviderConfigure,
        Permission::UsersManage,
        Permission::DevicesSelf,
        Permission::SystemConfigure,
    ];
}

/// The only scope of a session whose password must be changed first.
pub const SCOPE_PASSWORD_ONLY: &str = "self:password";
pub const ROLES: [&str; 4] = [ROLE_OWNER, "operator", "viewer", "user"];

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
            DevicesSelf,
        ],
        "viewer" => vec![NodesRead, ProfilesRead, TelemetryRead, NetworkRead],
        // End users: enroll, list and revoke their own devices only.
        "user" => vec![DevicesSelf],
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
        } else if self.password_change_required() {
            Err(ApiError::forbidden().detail("password change required"))
        } else {
            Err(ApiError::forbidden())
        }
    }

    pub fn password_change_required(&self) -> bool {
        self.scopes.len() == 1 && self.scopes[0] == SCOPE_PASSWORD_ONLY
    }
}

#[derive(Default)]
struct Limiter {
    failures: HashMap<String, (u32, Instant)>,
    window_start: Option<Instant>,
    window_count: u32,
}

pub struct AuthState {
    sessions: Mutex<HashMap<String, AdminSession>>,
    limiter: Mutex<Limiter>,
    bootstrap_limiter: Mutex<Limiter>,
    bootstrap_slots: Arc<Semaphore>,
    enrollment_limiter: Mutex<Limiter>,
    enrollment_slots: Arc<Semaphore>,
}

impl Default for AuthState {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            limiter: Mutex::new(Limiter::default()),
            bootstrap_limiter: Mutex::new(Limiter::default()),
            // Only one owner can be created. Bound both queued blocking jobs
            // and Argon2 memory, even when a caller abandons its HTTP request.
            bootstrap_slots: Arc::new(Semaphore::new(1)),
            enrollment_limiter: Mutex::new(Limiter::default()),
            enrollment_slots: Arc::new(Semaphore::new(2)),
        }
    }
}

impl AuthState {
    pub(crate) fn enrollment_permit(&self) -> Result<OwnedSemaphorePermit, ApiError> {
        let mut limit = self
            .enrollment_limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if limit
            .window_start
            .is_none_or(|start| now.duration_since(start) >= Duration::from_secs(60))
        {
            limit.window_start = Some(now);
            limit.window_count = 0;
        }
        if limit.window_count >= 30 {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "enrollment_rate_limited",
            ));
        }
        limit.window_count += 1;
        Arc::clone(&self.enrollment_slots)
            .try_acquire_owned()
            .map_err(|_| ApiError::new(StatusCode::TOO_MANY_REQUESTS, "enrollment_busy"))
    }
}

pub(crate) struct BootstrapClaimPermit {
    _permit: OwnedSemaphorePermit,
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

fn check_password_policy(pw: &str) -> Result<(), ApiError> {
    if pw.chars().count() < 12 || pw.len() > 1024 {
        return Err(ApiError::bad_request("weak_password")
            .detail("passwords must be at least 12 characters"));
    }
    Ok(())
}

fn check_username(username: &str) -> Result<(), ApiError> {
    if username.is_empty()
        || username.len() > 100
        || !username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b))
    {
        return Err(ApiError::bad_request("invalid_username"));
    }
    Ok(())
}

fn check_roles(roles: &[String]) -> Result<(), ApiError> {
    if roles.is_empty()
        || roles.len() > ROLES.len()
        || roles.iter().any(|r| !ROLES.contains(&r.as_str()))
    {
        return Err(ApiError::bad_request("invalid_roles"));
    }
    Ok(())
}

/// One-time password handed to a new or reset user (~95 bits).
fn temporary_password() -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut out = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(char::from(ALPHABET[usize::from(*b) % ALPHABET.len()]));
    }
    out
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
        let must_change = self
            .coord
            .store()
            .read(|c| db::must_change_password(c, &p.id))
            .map_err(ApiError::from)?;
        let scopes = if must_change {
            vec![SCOPE_PASSWORD_ONLY.to_owned()]
        } else {
            Self::scopes_for(&p.roles)
        };
        let (token, principal) = self.open_session(&p.id, scopes);
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
                    metadata: serde_json::json!({"password_change_required": must_change}),
                },
            )
        });
        Ok((token, principal))
    }

    fn open_session(&self, principal_id: &str, scopes: Vec<String>) -> (String, Principal) {
        let token = random_token();
        let csrf = random_token();
        let expires_at = db::now_unix() + SESSION_TTL.as_secs() as i64;
        self.auth
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                token_key(&token),
                AdminSession {
                    principal_id: principal_id.to_owned(),
                    scopes: scopes.clone(),
                    csrf_token: csrf.clone(),
                    expires_at,
                    kind: CredentialKind::Cookie,
                },
            );
        (
            token,
            Principal {
                id: principal_id.to_owned(),
                scopes,
                kind: CredentialKind::Cookie,
                expires_at,
                csrf_token: Some(csrf),
            },
        )
    }

    /// Drop every session (cookie and bearer) of a principal.
    pub(crate) fn purge_sessions(&self, principal_id: &str) {
        self.auth
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, s| s.principal_id != principal_id);
    }

    /// Self-service password change. Verifies the current password, ends
    /// all other sessions and returns a fresh, fully scoped session.
    /// Re-check the signed-in principal's password before a sensitive
    /// action (rate limited like sign-in). Blocking.
    pub fn confirm_password(&self, principal_id: &str, password: &str) -> Result<(), ApiError> {
        let p = self
            .coord
            .store()
            .read(|c| db::get_principal(c, principal_id))
            .map_err(ApiError::from)?;
        if self.rate_limited(&p.username) {
            return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
        }
        if p.status != "active"
            || password.len() > 1024
            || !verify_password(password, &p.password_hash)
        {
            self.record_failure(&p.username);
            return Err(ApiError::forbidden().detail("password is incorrect"));
        }
        Ok(())
    }

    pub fn change_password(
        &self,
        principal_id: &str,
        current: &str,
        new: &str,
    ) -> Result<(String, Principal), ApiError> {
        check_password_policy(new)?;
        if current == new {
            return Err(ApiError::bad_request("weak_password")
                .detail("the new password must differ from the current one"));
        }
        let store = self.coord.store();
        let p = store
            .read(|c| db::get_principal(c, principal_id))
            .map_err(ApiError::from)?;
        if self.rate_limited(&p.username) {
            return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
        }
        if p.status != "active" || !verify_password(current, &p.password_hash) {
            self.record_failure(&p.username);
            return Err(ApiError::forbidden().detail("current password is incorrect"));
        }
        let hash = hash_password(new)?;
        store.tx(|c| {
            db::set_password(c, &p.id, &hash, false)?;
            db::append_audit(
                c,
                AuditInsert {
                    actor_id: Some(&p.id),
                    action: "auth.password_changed",
                    target_type: "principal",
                    target_id: Some(&p.id),
                    decision: "allowed",
                    revision_digest: None,
                    metadata: serde_json::json!({}),
                },
            )
        })?;
        self.purge_sessions(&p.id);
        if p.roles.iter().any(|r| r == ROLE_OWNER) {
            // The installer's one-time copy is no longer valid.
            if let Some(dir) = self.data_dir() {
                let _ = std::fs::remove_file(dir.join("initial-admin-password"));
            }
        }
        Ok(self.open_session(&p.id, Self::scopes_for(&p.roles)))
    }

    /// Owner-created account with a one-time temporary password that must
    /// be changed at first sign-in. Returns `(principal_id, password)`.
    pub fn create_user(
        &self,
        actor: &str,
        username: &str,
        roles: &[String],
    ) -> Result<(String, String), ApiError> {
        check_username(username)?;
        check_roles(roles)?;
        let password = temporary_password();
        let hash = hash_password(&password)?;
        let id = db::new_id();
        let res = self.coord.store().tx(|c| {
            if db::get_principal_by_username(c, username)?.is_some() {
                return Err(db::StoreError::Conflict("username exists".into()));
            }
            db::insert_principal(
                c,
                &db::PrincipalRow {
                    id: id.clone(),
                    username: username.to_owned(),
                    password_hash: hash.clone(),
                    status: "active".into(),
                    roles: roles.to_vec(),
                },
            )?;
            db::set_password(c, &id, &hash, true)?;
            db::append_audit(
                c,
                AuditInsert {
                    actor_id: Some(actor),
                    action: "user.created",
                    target_type: "principal",
                    target_id: Some(&id),
                    decision: "allowed",
                    revision_digest: None,
                    metadata: serde_json::json!({"roles": roles}),
                },
            )
        });
        match res {
            Ok(_) => Ok((id, password)),
            Err(db::StoreError::Conflict(_)) => Err(ApiError::conflict("username_exists")),
            Err(e) => Err(e.into()),
        }
    }

    /// Owner reset: new temporary password, forced change, sessions ended.
    pub fn reset_password(&self, actor: &str, id: &str) -> Result<String, ApiError> {
        let password = temporary_password();
        let hash = hash_password(&password)?;
        self.coord.store().tx(|c| {
            db::set_password(c, id, &hash, true)?;
            db::append_audit(
                c,
                AuditInsert {
                    actor_id: Some(actor),
                    action: "user.password_reset",
                    target_type: "principal",
                    target_id: Some(id),
                    decision: "allowed",
                    revision_digest: None,
                    metadata: serde_json::json!({}),
                },
            )
        })?;
        self.purge_sessions(id);
        Ok(password)
    }

    /// Change roles and/or status. The last active owner can be neither
    /// demoted nor disabled, and nobody can disable themselves.
    pub fn update_user(
        &self,
        actor: &str,
        id: &str,
        roles: Option<&[String]>,
        status: Option<&str>,
    ) -> Result<(), ApiError> {
        if let Some(r) = roles {
            check_roles(r)?;
        }
        if let Some(s) = status {
            if s != "active" && s != "disabled" {
                return Err(ApiError::bad_request("invalid_status"));
            }
            if s == "disabled" && id == actor {
                return Err(ApiError::conflict("cannot_disable_self"));
            }
        }
        let res = self.coord.store().tx(|c| {
            let before = db::get_principal(c, id)?;
            if let Some(r) = roles {
                db::set_principal_roles(c, id, r)?;
            }
            if let Some(s) = status {
                db::set_principal_status(c, id, s)?;
            }
            if before.roles.iter().any(|r| r == ROLE_OWNER) && db::count_active_owners(c)? == 0 {
                return Err(db::StoreError::Conflict("last owner".into()));
            }
            db::append_audit(
                c,
                AuditInsert {
                    actor_id: Some(actor),
                    action: "user.updated",
                    target_type: "principal",
                    target_id: Some(id),
                    decision: "allowed",
                    revision_digest: None,
                    metadata: serde_json::json!({"roles": roles, "status": status}),
                },
            )
        });
        match res {
            Ok(_) => {
                self.purge_sessions(id);
                Ok(())
            }
            Err(db::StoreError::Conflict(_)) => Err(ApiError::conflict("last_owner_required")),
            Err(e) => Err(e.into()),
        }
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
        let permit = self.begin_bootstrap_claim()?;
        self.claim_bootstrap_admitted(token, username, password, permit)
    }

    /// Acquire before scheduling blocking work: excess attempts never queue
    /// a task or allocate Argon2's working memory.
    pub(crate) fn begin_bootstrap_claim(&self) -> Result<BootstrapClaimPermit, ApiError> {
        let limited = || ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        let mut l = self
            .auth
            .bootstrap_limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match l.window_start {
            Some(t) if now.duration_since(t) < Duration::from_secs(60) => {
                l.window_count = l.window_count.saturating_add(1);
            }
            _ => {
                l.window_start = Some(now);
                l.window_count = 1;
            }
        }
        if l.window_count > BOOTSTRAP_ATTEMPTS_PER_MINUTE {
            return Err(limited());
        }
        drop(l);
        let permit = Arc::clone(&self.auth.bootstrap_slots)
            .try_acquire_owned()
            .map_err(|_| limited())?;
        Ok(BootstrapClaimPermit { _permit: permit })
    }

    pub(crate) fn claim_bootstrap_admitted(
        &self,
        token: &str,
        username: &str,
        password: &str,
        permit: BootstrapClaimPermit,
    ) -> Result<String, ApiError> {
        self.claim_bootstrap_with_hasher(token, username, password, permit, hash_password)
    }

    fn claim_bootstrap_with_hasher(
        &self,
        token: &str,
        username: &str,
        password: &str,
        _permit: BootstrapClaimPermit,
        hash: impl FnOnce(&str) -> Result<String, ApiError>,
    ) -> Result<String, ApiError> {
        if token.is_empty() || token.len() > 256 {
            return Err(ApiError::bad_request("invalid_body"));
        }
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
        let verifier = token_key(token);
        // This is an inexpensive preflight only. The transaction below must
        // recheck owner existence and atomically consume the token after the
        // hash, because the token may expire or another context may claim it.
        self.coord.store().read_as(|c| -> Result<(), ApiError> {
            if db::owner_exists(c)? {
                return Err(ApiError::conflict("bootstrap_disabled"));
            }
            let valid: bool = c
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM bootstrap_tokens WHERE verifier_hash = ?1 AND used_at IS NULL AND expires_at > ?2)",
                    (&verifier, db::now_unix()),
                    |r| r.get(0),
                )
                .map_err(db::StoreError::from)?;
            if !valid {
                return Err(ApiError::unauthenticated()
                    .detail("invalid, used or expired bootstrap token"));
            }
            Ok(())
        })?;
        let hash = hash(password)?;
        let id = db::new_id();
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
    use crate::test_support::{context, insert_owner};
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    #[test]
    fn bootstrap_rejects_invalid_tokens_and_existing_owner_without_hashing() {
        let store = Arc::new(db::Store::open_in_memory().expect("store"));
        let ctx = context(Arc::clone(&store));
        store
            .tx(|c| {
                db::insert_bootstrap_token(c, &token_key("expired"), db::now_unix() - 1)?;
                db::insert_bootstrap_token(c, &token_key("used"), db::now_unix() + 60)?;
                assert!(db::consume_bootstrap_token(
                    c,
                    &token_key("used"),
                    db::now_unix()
                )?);
                Ok(())
            })
            .expect("tokens");
        let hashes = AtomicUsize::new(0);
        let claim = |token: &str| {
            ctx.claim_bootstrap_with_hasher(
                token,
                "owner",
                "long enough password",
                ctx.begin_bootstrap_claim().expect("permit"),
                |_| {
                    hashes.fetch_add(1, Ordering::SeqCst);
                    Ok("unused".into())
                },
            )
        };
        for token in ["unknown", "expired", "used"] {
            assert_eq!(
                claim(token).expect_err("invalid token").status,
                StatusCode::UNAUTHORIZED
            );
        }
        let (token, _) = ctx.create_bootstrap_token().expect("token");
        insert_owner(&store);
        assert_eq!(
            claim(&token).expect_err("already initialized").status,
            StatusCode::CONFLICT
        );
        assert_eq!(hashes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn bootstrap_rechecks_token_after_hash_without_creating_owner() {
        let store = Arc::new(db::Store::open_in_memory().expect("store"));
        let ctx = context(Arc::clone(&store));
        let (token, _) = ctx.create_bootstrap_token().expect("token");
        let err = ctx
            .claim_bootstrap_with_hasher(
                &token,
                "owner",
                "long enough password",
                ctx.begin_bootstrap_claim().expect("permit"),
                |_| {
                    // Simulate a separate context consuming the token between
                    // preflight and the final transaction.
                    store.tx(|c| {
                        db::consume_bootstrap_token(c, &token_key(&token), db::now_unix())
                    })?;
                    Ok("unused".into())
                },
            )
            .expect_err("consumption must be checked atomically");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(!store.read(db::owner_exists).expect("owner"));
    }

    #[test]
    fn bootstrap_allows_only_one_in_flight_hash_and_one_owner() {
        let store = Arc::new(db::Store::open_in_memory().expect("store"));
        let ctx = context(Arc::clone(&store));
        let (token, _) = ctx.create_bootstrap_token().expect("token");
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let worker = {
            let ctx = Arc::clone(&ctx);
            let token = token.clone();
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            std::thread::spawn(move || {
                ctx.claim_bootstrap_with_hasher(
                    &token,
                    "owner",
                    "long enough password",
                    ctx.begin_bootstrap_claim().expect("permit"),
                    |_| {
                        entered.wait();
                        release.wait();
                        Ok("unused".into())
                    },
                )
            })
        };
        entered.wait();
        let err = ctx
            .claim_bootstrap(&token, "another", "another long password")
            .expect_err("concurrent hashing must be rejected");
        assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(!store.read(db::owner_exists).expect("owner"));
        release.wait();
        worker.join().expect("worker").expect("first claim");
        assert_eq!(
            ctx.claim_bootstrap(&token, "another", "another long password")
                .expect_err("owner exists")
                .status,
            StatusCode::CONFLICT
        );
        let owners: i64 = store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM principal_roles WHERE role = 'owner'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .expect("owners");
        assert_eq!(owners, 1);
    }

    #[test]
    fn bootstrap_attempts_are_rate_limited_even_after_setup() {
        let store = Arc::new(db::Store::open_in_memory().expect("store"));
        let ctx = context(Arc::clone(&store));
        insert_owner(&store);
        for _ in 0..BOOTSTRAP_ATTEMPTS_PER_MINUTE {
            let err = ctx
                .claim_bootstrap("invalid", "owner", "long enough password")
                .expect_err("bootstrap disabled");
            assert_eq!(err.status, StatusCode::CONFLICT);
        }
        assert_eq!(
            ctx.claim_bootstrap("invalid", "owner", "long enough password")
                .expect_err("rate limited")
                .status,
            StatusCode::TOO_MANY_REQUESTS
        );
        ctx.auth
            .bootstrap_limiter
            .lock()
            .expect("limiter")
            .window_start = Some(Instant::now() - Duration::from_secs(61));
        assert_eq!(
            ctx.claim_bootstrap("invalid", "owner", "long enough password")
                .expect_err("bootstrap disabled")
                .status,
            StatusCode::CONFLICT
        );
    }
}
