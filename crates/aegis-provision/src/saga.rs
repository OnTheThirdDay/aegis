use crate::*;
use aegis_storage::{self as db, Store};
use serde_json::json;
use std::{future::Future, pin::Pin, sync::Arc};

pub type StepFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[cfg(not(test))]
const VERIFY_RETRIES: u32 = 12;
#[cfg(test)]
const VERIFY_RETRIES: u32 = 1;
const VERIFY_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);

/// Implementations are control-plane adapters, never arbitrary scripts.
pub trait InfrastructureProvider: Send + Sync {
    fn validate<'a>(&'a self, plan: &'a Plan) -> StepFuture<'a, ()>;
    fn tunnel<'a>(&'a self, plan: &'a Plan) -> StepFuture<'a, Inventory>;
    fn ingress<'a>(&'a self, plan: &'a Plan) -> StepFuture<'a, ()>;
    fn dns<'a>(&'a self, plan: &'a Plan) -> StepFuture<'a, Inventory>;
    fn connector_token<'a>(&'a self, plan: &'a Plan) -> StepFuture<'a, zeroize::Zeroizing<String>>;
    fn verify<'a>(&'a self, plan: &'a Plan) -> StepFuture<'a, ()>;
    fn cleanup<'a>(
        &'a self,
        plan: &'a Plan,
        keep_dns: bool,
        keep_tunnel: bool,
    ) -> StepFuture<'a, ()>;
}
pub trait HostProvisioner: Send + Sync {
    fn apply<'a>(&'a self, plan: &'a Plan, connector_token: Option<&'a str>) -> StepFuture<'a, ()>;
    fn verify<'a>(&'a self, plan: &'a Plan) -> StepFuture<'a, String>;
    fn remove<'a>(&'a self, plan: &'a Plan) -> StepFuture<'a, ()>;
}
pub trait Probe: Send + Sync {
    fn verify<'a>(&'a self, plan: &'a Plan) -> StepFuture<'a, Verification>;
}

/// Installed only in the explicitly started local host controller. Ordinary
/// gateway management has no host executor and cannot acquire host privilege.
pub trait Executor: Send + Sync {
    fn apply<'a>(
        &'a self,
        controller: &'a Controller,
        id: &'a str,
        actor: &'a str,
        etag: &'a str,
    ) -> StepFuture<'a, Plan>;
}

/// No in-memory-only lock: the unique SQLite active-operation index serializes
/// independent CLI/API processes. An abandoned effect is RECOVERY_REQUIRED;
/// recovery is explicit and cannot blindly repeat an unknown remote creation.
pub struct Controller {
    pub store: Arc<Store>,
}
impl Controller {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    pub fn plan(
        &self,
        desired: DesiredDeployment,
        actor: &str,
        expected_revision: Option<String>,
    ) -> Result<Plan> {
        desired.validate()?;
        if actor.is_empty() || actor.len() > 128 {
            return Err(Error("invalid_actor"));
        }
        let digest = aegis_config::digest_value(
            &json!({"desired":desired,"expected_revision":expected_revision,"actor":actor}),
        );
        let id = digest[..32].to_owned();
        let desired_json =
            serde_json::to_string(&desired).map_err(|_| Error("invalid_deployment"))?;
        self.store.tx(|c| {
            c.execute("INSERT OR IGNORE INTO provision_plans(id,digest,actor_id,desired_json,expected_revision,state,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,'validated',?6,?6)",
                (&id,&digest,actor,&desired_json,&expected_revision,db::now_unix()))?;
            Ok(())
        })?;
        self.get(&id, actor)
    }

    pub fn get(&self, id: &str, actor: &str) -> Result<Plan> {
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error("plan_not_found"));
        }
        let row = self.store.read(|c| Ok(c.query_row("SELECT digest,actor_id,desired_json,expected_revision,state,generation,step,inventory_json,error_code FROM provision_plans WHERE id=?1 AND actor_id=?2", (id,actor), |r| {
            Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,String>(4)?,r.get::<_,i64>(5)?,r.get::<_,String>(6)?,r.get::<_,String>(7)?,r.get::<_,Option<String>>(8)?))
        })?))?;
        let state = serde_json::from_value(json!(row.4)).map_err(|_| Error("corrupt_plan"))?;
        Ok(Plan {
            id: id.into(),
            digest: row.0,
            actor_id: row.1,
            desired: serde_json::from_str(&row.2).map_err(|_| Error("corrupt_plan"))?,
            expected_revision: row.3,
            state,
            generation: row.5,
            step: row.6,
            inventory: serde_json::from_str(&row.7).map_err(|_| Error("corrupt_inventory"))?,
            error_code: row.8,
        })
    }

    pub fn list(&self, actor: &str) -> Result<Vec<Plan>> {
        let ids: Vec<String> = self.store.read(|c| {
            let mut s=c.prepare("SELECT id FROM provision_plans WHERE actor_id=?1 ORDER BY updated_at DESC,id LIMIT 100")?;
            let rows=s.query_map([actor],|r| r.get(0))?;
            Ok(rows.collect::<std::result::Result<_,_>>()?)
        })?;
        ids.iter().map(|id| self.get(id, actor)).collect()
    }

    fn transition(
        &self,
        p: &mut Plan,
        state: PlanState,
        step: &str,
        error: Option<&'static str>,
    ) -> Result<()> {
        let inventory =
            serde_json::to_string(&p.inventory).map_err(|_| Error("invalid_inventory"))?;
        self.store.tx(|c| {
            let n=c.execute("UPDATE provision_plans SET state=?1,step=?2,inventory_json=?3,error_code=?4,generation=generation+1,updated_at=?5 WHERE id=?6 AND generation=?7",
                (state.as_str(),step,&inventory,error,db::now_unix(),&p.id,p.generation))?;
            if n!=1 { return Err(db::StoreError::Conflict("stale_provision_plan".into())); }
            c.execute("INSERT INTO provision_events(plan_id,state,step,occurred_at,code) VALUES (?1,?2,?3,?4,?5)",(&p.id,state.as_str(),step,db::now_unix(),error))?;
            db::append_audit(c,db::AuditInsert {actor_id:Some(&p.actor_id),action:"provision.transition",target_type:"deployment",target_id:Some(&p.id),decision:state.as_str(),revision_digest:Some(&p.digest),metadata:json!({"step":step,"code":error})})?;
            Ok(())
        }).map_err(|e| match e { db::StoreError::Conflict(_)=>Error("stale_provision_plan"), _=>Error("provision_busy_or_storage_unavailable") })?;
        p.generation += 1;
        p.state = state;
        p.step = step.into();
        p.error_code = error.map(str::to_owned);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn apply<P: InfrastructureProvider, H: HostProvisioner, V: Probe>(
        &self,
        id: &str,
        actor: &str,
        etag: &str,
        current_revision: Option<&str>,
        provider: &P,
        host: &H,
        probe: &V,
    ) -> Result<Plan> {
        let mut p = self.get(id, actor)?;
        if etag != p.etag() {
            return Err(Error("stale_provision_plan"));
        }
        if p.state == PlanState::Active {
            self.verify(&p, provider, host, probe).await?;
            return Ok(p);
        }
        if p.expected_revision.as_deref() != current_revision {
            return Err(Error("stale_config_revision"));
        }
        if !matches!(
            p.state,
            PlanState::Validated | PlanState::Failed | PlanState::RecoveryRequired
        ) {
            return Err(Error("provision_apply_conflict"));
        }
        self.transition(&mut p, PlanState::Applying, "validate", None)?;
        let result = self.run(&mut p, provider, host, probe).await;
        if let Err(e) = result {
            // Never automatically tear down a possibly healthy gateway or
            // delete resources after an ambiguous timeout. Reconcile or use
            // the explicit ownership-checked uninstall/compensation workflow.
            self.transition(
                &mut p,
                PlanState::RecoveryRequired,
                "interrupted",
                Some(e.0),
            )?;
            return Err(e);
        }
        Ok(p)
    }

    async fn run<P: InfrastructureProvider, H: HostProvisioner, V: Probe>(
        &self,
        p: &mut Plan,
        provider: &P,
        host: &H,
        probe: &V,
    ) -> Result<()> {
        p.desired.validate()?;
        let token = if p.desired.mode == Mode::CloudflareTunnel {
            provider.validate(p).await?;
            self.transition(p, PlanState::Applying, "tunnel_intent", None)?;
            p.inventory = provider.tunnel(p).await?;
            self.transition(p, PlanState::Applying, "ingress_intent", None)?;
            provider.ingress(p).await?;
            self.transition(p, PlanState::Applying, "dns_intent", None)?;
            p.inventory = provider.dns(p).await?;
            self.transition(p, PlanState::Applying, "connector_token", None)?;
            Some(provider.connector_token(p).await?)
        } else {
            None
        };
        self.transition(p, PlanState::Applying, "host_intent", None)?;
        host.apply(p, token.as_deref().map(String::as_str)).await?;
        p.inventory.host_applied = true;
        self.transition(p, PlanState::Verifying, "data_path", None)?;
        let (revision, verified) = match self.verify(p, provider, host, probe).await {
            Ok(revision) => (revision, true),
            // Everything the provider and host can confirm is healthy; only
            // this host's own route to the public endpoint failed. Commit,
            // flagged unverified, rather than strand a working setup.
            Err(Error(code)) if code == crate::DATA_PATH_UNVERIFIED_FROM_HOST => {
                (host.verify(p).await?, false)
            }
            Err(e) => return Err(e),
        };
        p.inventory.config_revision = Some(revision);
        p.inventory.verified = verified;
        if verified {
            self.transition(p, PlanState::Active, "committed", None)
        } else {
            self.transition(
                p,
                PlanState::Active,
                "committed_unverified",
                Some(crate::DATA_PATH_UNVERIFIED_FROM_HOST),
            )
        }
    }

    pub async fn verify<P: InfrastructureProvider, H: HostProvisioner, V: Probe>(
        &self,
        p: &Plan,
        provider: &P,
        host: &H,
        probe: &V,
    ) -> Result<String> {
        if p.desired.mode == Mode::CloudflareTunnel {
            // A connector that just started takes a few seconds to register
            // with the edge; only that specific condition is retried.
            let mut attempt = 0;
            loop {
                match provider.verify(p).await {
                    Err(Error("cloudflare_connector_not_healthy")) if attempt < VERIFY_RETRIES => {
                        attempt += 1;
                        tokio::time::sleep(VERIFY_BACKOFF).await;
                    }
                    other => break other?,
                }
            }
        }
        let revision = host.verify(p).await?;
        if !probe.verify(p).await?.complete() {
            return Err(Error("data_path_not_verified"));
        }
        Ok(revision)
    }

    /// Explicit crash recovery, guarded by ETag. It only releases a stranded
    /// controller reservation; the next apply observes every external object.
    pub fn recover(&self, id: &str, actor: &str, etag: &str) -> Result<Plan> {
        let mut p = self.get(id, actor)?;
        if p.etag() != etag {
            return Err(Error("stale_provision_plan"));
        }
        if !matches!(
            p.state,
            PlanState::Applying | PlanState::Verifying | PlanState::Compensating
        ) {
            return Err(Error("plan_not_interrupted"));
        }
        self.transition(
            &mut p,
            PlanState::RecoveryRequired,
            "reconcile_required",
            Some("operator_recovery"),
        )?;
        Ok(p)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn uninstall<P: InfrastructureProvider, H: HostProvisioner>(
        &self,
        id: &str,
        actor: &str,
        etag: &str,
        provider: &P,
        host: &H,
        keep_dns: bool,
        keep_tunnel: bool,
    ) -> Result<Plan> {
        let mut p = self.get(id, actor)?;
        if p.etag() != etag {
            return Err(Error("stale_provision_plan"));
        }
        self.transition(&mut p, PlanState::Compensating, "remove_owned_host", None)?;
        let result: Result<()> = async {
            host.remove(&p).await?;
            if p.desired.mode == Mode::CloudflareTunnel {
                provider.cleanup(&p, keep_dns, keep_tunnel).await?;
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            self.transition(
                &mut p,
                PlanState::RecoveryRequired,
                "cleanup_interrupted",
                Some(e.0),
            )?;
            return Err(e);
        }
        self.transition(&mut p, PlanState::Removed, "removed", None)?;
        Ok(p)
    }
}
