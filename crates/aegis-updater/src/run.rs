//! The updater: checks for newer releases, upgrades the gateway container
//! on request (or automatically), rolls back when the new one isn't
//! healthy, and finally replaces itself with the new image too.

use crate::docker::{Docker, DockerError};
use crate::files::{self, Request};
use crate::version::Version;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const VERSION_LABEL: &str = "org.opencontainers.image.version";
/// How long a new gateway has to report healthy (its health check starts
/// after 20 s and runs every 30 s).
const HEALTHY_WITHIN: Duration = Duration::from_secs(180);
const PULL_TIMEOUT: Duration = Duration::from_secs(600);
const HEARTBEAT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_secs(3);

/// Where newer releases come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Pull `latest` from the registry, and use releases already here.
    Registry,
    /// Only releases already on this machine (copied from another server).
    Local,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Registry => "registry",
            Source::Local => "local",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    /// The gateway container's name.
    pub container: String,
    /// `ghcr.io/owner/name`: the only repository whose releases are run.
    pub repository: String,
    pub data: PathBuf,
    pub socket: PathBuf,
    pub source: Source,
    /// Time between automatic checks.
    pub interval: Duration,
}

/// The Docker operations the updater uses (a fake in tests).
pub(crate) trait Engine {
    fn inspect_container(&self, name: &str) -> Result<Option<Value>, DockerError>;
    fn inspect_image(&self, reference: &str) -> Result<Option<Value>, DockerError>;
    fn images(&self, repository: &str) -> Result<Vec<Value>, DockerError>;
    fn pull(&self, repository: &str, tag: &str) -> Result<(), DockerError>;
    fn tag(&self, image: &str, repository: &str, tag: &str) -> Result<(), DockerError>;
    fn create(&self, name: &str, config: &Value) -> Result<String, DockerError>;
    fn start(&self, name: &str) -> Result<(), DockerError>;
    fn stop(&self, name: &str) -> Result<(), DockerError>;
    fn rename(&self, name: &str, to: &str) -> Result<(), DockerError>;
    fn remove(&self, name: &str) -> Result<(), DockerError>;
    fn sleep(&self, d: Duration);
}

impl Engine for Docker {
    fn inspect_container(&self, name: &str) -> Result<Option<Value>, DockerError> {
        Docker::inspect_container(self, name)
    }
    fn inspect_image(&self, reference: &str) -> Result<Option<Value>, DockerError> {
        Docker::inspect_image(self, reference)
    }
    fn images(&self, repository: &str) -> Result<Vec<Value>, DockerError> {
        Docker::images(self, repository)
    }
    fn pull(&self, repository: &str, tag: &str) -> Result<(), DockerError> {
        Docker::pull(self, repository, tag, PULL_TIMEOUT)
    }
    fn tag(&self, image: &str, repository: &str, tag: &str) -> Result<(), DockerError> {
        Docker::tag(self, image, repository, tag)
    }
    fn create(&self, name: &str, config: &Value) -> Result<String, DockerError> {
        Docker::create(self, name, config)
    }
    fn start(&self, name: &str) -> Result<(), DockerError> {
        Docker::start(self, name)
    }
    fn stop(&self, name: &str) -> Result<(), DockerError> {
        Docker::stop(self, name, 20)
    }
    fn rename(&self, name: &str, to: &str) -> Result<(), DockerError> {
        Docker::rename(self, name, to)
    }
    fn remove(&self, name: &str) -> Result<(), DockerError> {
        Docker::remove(self, name)
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run until the process is stopped.
pub fn run(o: Options) -> Result<(), String> {
    let docker = Docker::new(&o.socket);
    prepare(&o.data);
    take_over(&docker)?;
    let mut u = Updater::new(&o, &docker);
    let mut next_check = Instant::now();
    let mut beat = Instant::now() - HEARTBEAT;
    loop {
        let request = files::take_request(&o.data);
        if request == Some(Request::Check) || Instant::now() >= next_check {
            next_check = Instant::now() + o.interval;
            u.check();
            if request != Some(Request::Check) && files::auto(&o.data) && u.available.is_some() {
                u.upgrade(None);
            }
        }
        if let Some(Request::Upgrade(v)) = request {
            u.upgrade(v);
        }
        if beat.elapsed() >= HEARTBEAT {
            beat = Instant::now();
            u.write();
        }
        std::thread::sleep(POLL);
    }
}

/// The exchange folder belongs to the gateway's user (the data volume's
/// owner), so the console can write requests into it even when this
/// process, running as root, created it.
fn prepare(data: &std::path::Path) {
    use std::os::unix::fs::MetadataExt;
    let dir = files::dir(data);
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(m) = std::fs::metadata(data) {
        let _ = std::os::unix::fs::chown(&dir, Some(m.uid()), Some(m.gid()));
    }
}

/// A new updater container (`<name>-next`, started by the previous one
/// after an upgrade) removes its predecessor and takes its name.
fn take_over(d: &Docker) -> Result<(), String> {
    let Ok(me) = std::env::var("HOSTNAME") else {
        return Ok(());
    };
    let Ok(Some(c)) = d.inspect_container(&me) else {
        return Ok(());
    };
    let name = c["Name"].as_str().unwrap_or("").trim_start_matches('/');
    if let Some(base) = name.strip_suffix("-next") {
        d.remove(base).map_err(|e| e.to_string())?;
        d.rename(name, base).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub(crate) struct Updater<'a, E: Engine> {
    o: &'a Options,
    e: &'a E,
    running: Option<Version>,
    pub(crate) available: Option<Version>,
    checked_at: Option<u64>,
    state: &'static str,
    message: Option<String>,
    finished_at: Option<u64>,
}

impl<'a, E: Engine> Updater<'a, E> {
    pub(crate) fn new(o: &'a Options, e: &'a E) -> Self {
        // Keep the outcome of the last attempt across restarts (the
        // updater replaces itself after every upgrade).
        let last = files::status(&o.data).unwrap_or(Value::Null);
        Updater {
            o,
            e,
            running: None,
            available: None,
            checked_at: None,
            state: match last["state"].as_str() {
                Some("upgraded") => "upgraded",
                Some("rolled_back") => "rolled_back",
                Some("failed") => "failed",
                _ => "idle",
            },
            message: last["message"].as_str().map(str::to_owned),
            finished_at: last["finished_at"].as_u64(),
        }
    }

    fn write(&self) {
        let _ = files::write_status(
            &self.o.data,
            &json!({
                "updater_version": env!("CARGO_PKG_VERSION"),
                "heartbeat": now(),
                "source": self.o.source.as_str(),
                "running": self.running.map(|v| v.to_string()),
                "available": self.available.map(|v| v.to_string()),
                "checked_at": self.checked_at,
                "state": self.state,
                "message": self.message,
                "finished_at": self.finished_at,
            }),
        );
    }

    fn set(&mut self, state: &'static str, message: Option<String>) {
        self.state = state;
        self.message = message;
        if !matches!(state, "checking" | "upgrading") {
            self.finished_at = Some(now());
        }
        self.write();
    }

    fn image_version(&self, reference: &str) -> Option<Version> {
        let img = self.e.inspect_image(reference).ok()??;
        img["Config"]["Labels"][VERSION_LABEL]
            .as_str()
            .and_then(Version::parse)
    }

    fn running_version(&self, name: &str) -> Option<Version> {
        let c = self.e.inspect_container(name).ok()??;
        self.image_version(c["Image"].as_str()?)
    }

    /// Release versions of the repository present on this machine.
    fn local_releases(&self) -> Vec<Version> {
        let prefix = format!("{}:", self.o.repository);
        let mut out: Vec<Version> = self
            .e
            .images(&self.o.repository)
            .unwrap_or_default()
            .iter()
            .flat_map(|img| img["RepoTags"].as_array().cloned().unwrap_or_default())
            .filter_map(|t| t.as_str()?.strip_prefix(&prefix).and_then(Version::parse))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Look for a newer release: pull `latest` (registry source) and tag it
    /// with its version, then take the newest release on this machine.
    pub(crate) fn check(&mut self) {
        self.state = "checking";
        self.write();
        let mut problem = None;
        if self.o.source == Source::Registry {
            match self.e.pull(&self.o.repository, "latest") {
                Ok(()) => {
                    let latest = format!("{}:latest", self.o.repository);
                    if let Some(v) = self.image_version(&latest) {
                        let _ = self.e.tag(&latest, &self.o.repository, &v.to_string());
                    }
                }
                Err(e) => problem = Some(format!("Could not reach the registry ({e}); only releases already on this server are offered.")),
            }
        }
        self.running = self.running_version(&self.o.container);
        self.available = self
            .local_releases()
            .into_iter()
            .next_back()
            .filter(|v| self.running.is_none_or(|r| *v > r));
        self.checked_at = Some(now());
        self.state = "idle";
        self.message = problem.or_else(|| self.message.take());
        self.write();
    }

    /// Upgrade the gateway to `target` (or the newest available release).
    pub(crate) fn upgrade(&mut self, target: Option<Version>) {
        let Some(target) = target.or(self.available) else {
            self.set("failed", Some("No newer release is available.".into()));
            return;
        };
        self.set("upgrading", Some(format!("Upgrading to {target}…")));
        match self.replace_gateway(target) {
            Ok(()) => {
                self.running = Some(target);
                self.available = None;
                self.set("upgraded", Some(format!("Upgraded to {target}.")));
                if let Err(e) = self.replace_self(target) {
                    // The gateway is upgraded; the updater stays as it was.
                    self.message = Some(format!(
                        "Upgraded to {target}; the updater itself was not replaced ({e})."
                    ));
                    self.write();
                }
            }
            Err(Failure::Refused(why)) => self.set("failed", Some(why)),
            Err(Failure::RolledBack(why)) => self.set(
                "rolled_back",
                Some(format!(
                    "{target} didn't start ({why}); the previous version is running again."
                )),
            ),
        }
    }

    fn replace_gateway(&mut self, target: Version) -> Result<(), Failure> {
        let reference = format!("{}:{target}", self.o.repository);
        if self.e.inspect_image(&reference).ok().flatten().is_none() {
            if self.o.source == Source::Local {
                return Err(Failure::Refused(format!("{target} is not on this server.")));
            }
            self.e
                .pull(&self.o.repository, &target.to_string())
                .map_err(|e| Failure::Refused(format!("Could not download {target}: {e}")))?;
        }
        // The image must really be that release.
        if self.image_version(&reference) != Some(target) {
            return Err(Failure::Refused(format!(
                "The image tagged {target} is not release {target}."
            )));
        }
        let name = self.o.container.clone();
        let current = self
            .e
            .inspect_container(&name)
            .ok()
            .flatten()
            .ok_or_else(|| Failure::Refused(format!("No container named {name}.")))?;
        if let Some(r) = self.running_version(&name) {
            if target <= r {
                return Err(Failure::Refused(format!("{name} already runs {r}.")));
            }
        }
        let config = clone_config(&current, &reference);
        let previous = format!("{name}-previous");
        let fail = |e: DockerError| Failure::Refused(e.to_string());
        self.e.remove(&previous).map_err(fail)?;
        self.e.stop(&name).map_err(fail)?;
        self.e.rename(&name, &previous).map_err(fail)?;
        let started = self
            .e
            .create(&name, &config)
            .and_then(|_| self.e.start(&name))
            .map_err(|e| e.to_string())
            .and_then(|()| self.wait_healthy(&name));
        match started {
            Ok(()) => {
                let _ = self.e.remove(&previous);
                Ok(())
            }
            Err(why) => {
                let _ = self.e.remove(&name);
                let back = self
                    .e
                    .rename(&previous, &name)
                    .and_then(|()| self.e.start(&name));
                match back {
                    Ok(()) => Err(Failure::RolledBack(why)),
                    Err(e) => Err(Failure::Refused(format!(
                        "{why}; restoring the previous container failed too ({e}): it is kept as {previous}"
                    ))),
                }
            }
        }
    }

    fn wait_healthy(&self, name: &str) -> Result<(), String> {
        let deadline = Instant::now() + HEALTHY_WITHIN;
        loop {
            let c = self
                .e
                .inspect_container(name)
                .map_err(|e| e.to_string())?
                .ok_or("the new container disappeared")?;
            let state = &c["State"];
            if state["Running"] != json!(true) {
                return Err(format!(
                    "it exited with code {}",
                    state["ExitCode"].as_i64().unwrap_or(-1)
                ));
            }
            match state["Health"]["Status"].as_str() {
                Some("healthy") => return Ok(()),
                Some("unhealthy") => return Err("its health check failed".into()),
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err("it didn't report healthy in time".into());
            }
            self.e.sleep(POLL);
        }
    }

    /// Start `<self>-next` from the new image; it removes this container
    /// and takes its name when it starts.
    fn replace_self(&self, target: Version) -> Result<(), String> {
        let Ok(me) = std::env::var("HOSTNAME") else {
            return Ok(());
        };
        let Some(c) = self.e.inspect_container(&me).map_err(|e| e.to_string())? else {
            return Ok(());
        };
        let name = c["Name"]
            .as_str()
            .unwrap_or("")
            .trim_start_matches('/')
            .to_owned();
        if self.image_version(c["Image"].as_str().unwrap_or("")) >= Some(target) {
            return Ok(());
        }
        let next = format!("{name}-next");
        let reference = format!("{}:{target}", self.o.repository);
        self.e.remove(&next).map_err(|e| e.to_string())?;
        self.e
            .create(&next, &clone_config(&c, &reference))
            .and_then(|_| self.e.start(&next))
            .map_err(|e| e.to_string())
    }
}

enum Failure {
    /// Nothing was changed (or a rollback itself failed).
    Refused(String),
    /// The new version didn't start; the previous one runs again.
    RolledBack(String),
}

/// The configuration to recreate container `current` from `image`: its
/// host settings (ports, volumes, limits, restart policy, security options)
/// and command unchanged, its `AEGIS_*` environment, the new image's
/// defaults for everything else.
pub(crate) fn clone_config(current: &Value, image: &str) -> Value {
    let cfg = &current["Config"];
    let env: Vec<Value> = cfg["Env"]
        .as_array()
        .map(|e| {
            e.iter()
                .filter(|v| v.as_str().is_some_and(|s| s.starts_with("AEGIS_")))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    json!({
        "Image": image,
        "Env": env,
        "Entrypoint": cfg["Entrypoint"],
        "Cmd": cfg["Cmd"],
        "User": cfg["User"],
        "HostConfig": current["HostConfig"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const REPO: &str = "ghcr.io/owner/aegis";

    /// Containers and images in memory; a container started from an image
    /// in `unhealthy` never becomes healthy.
    #[derive(Default)]
    struct Fake {
        images: RefCell<HashMap<String, String>>, // reference -> version
        containers: RefCell<HashMap<String, (String, bool)>>, // name -> (image, running)
        unhealthy: Vec<String>,
        registry: Option<String>, // version `latest` pulls
        log: RefCell<Vec<String>>,
    }

    impl Fake {
        fn image(&self, reference: &str, version: &str) {
            self.images
                .borrow_mut()
                .insert(reference.into(), version.into());
        }
        fn container(&self, name: &str, image: &str) {
            self.containers
                .borrow_mut()
                .insert(name.into(), (image.into(), true));
        }
        fn running_image(&self, name: &str) -> Option<String> {
            self.containers.borrow().get(name).map(|c| c.0.clone())
        }
    }

    impl Engine for Fake {
        fn inspect_container(&self, name: &str) -> Result<Option<Value>, DockerError> {
            Ok(self.containers.borrow().get(name).map(|(image, running)| {
                let health = if self.unhealthy.contains(image) { "unhealthy" } else { "healthy" };
                json!({
                    "Name": format!("/{name}"),
                    "Image": image,
                    "Config": {"Env": ["AEGIS_PUBLIC_PORT=443", "PATH=/usr/bin"], "Entrypoint": ["/usr/local/bin/aegisd"], "Cmd": null, "User": "10001:10001"},
                    "HostConfig": {"PortBindings": {"8444/tcp": [{"HostPort": "443"}]}, "ReadonlyRootfs": true},
                    "State": {"Running": running, "ExitCode": 0, "Health": {"Status": health}},
                })
            }))
        }
        fn inspect_image(&self, reference: &str) -> Result<Option<Value>, DockerError> {
            Ok(self
                .images
                .borrow()
                .get(reference)
                .map(|v| json!({"Config": {"Labels": {VERSION_LABEL: v}}})))
        }
        fn images(&self, _repository: &str) -> Result<Vec<Value>, DockerError> {
            Ok(self
                .images
                .borrow()
                .keys()
                .map(|r| json!({"RepoTags": [r]}))
                .collect())
        }
        fn pull(&self, repository: &str, tag: &str) -> Result<(), DockerError> {
            match (&self.registry, tag) {
                (Some(v), "latest") => {
                    self.image(&format!("{repository}:latest"), v);
                    Ok(())
                }
                (Some(_), t) if Version::parse(t).is_some() => {
                    self.image(&format!("{repository}:{t}"), t);
                    Ok(())
                }
                _ => Err(DockerError("unreachable".into())),
            }
        }
        fn tag(&self, image: &str, repository: &str, tag: &str) -> Result<(), DockerError> {
            let v = self.images.borrow().get(image).cloned().unwrap_or_default();
            self.image(&format!("{repository}:{tag}"), &v);
            Ok(())
        }
        fn create(&self, name: &str, config: &Value) -> Result<String, DockerError> {
            self.log
                .borrow_mut()
                .push(format!("create {name} {}", config["Image"]));
            assert_eq!(
                config["Env"],
                json!(["AEGIS_PUBLIC_PORT=443"]),
                "only AEGIS_ env is carried"
            );
            assert_eq!(config["HostConfig"]["ReadonlyRootfs"], true);
            let image = config["Image"].as_str().unwrap_or("").to_owned();
            self.containers
                .borrow_mut()
                .insert(name.into(), (image, false));
            Ok(name.into())
        }
        fn start(&self, name: &str) -> Result<(), DockerError> {
            self.log.borrow_mut().push(format!("start {name}"));
            match self.containers.borrow_mut().get_mut(name) {
                Some(c) => {
                    c.1 = true;
                    Ok(())
                }
                None => Err(DockerError("no such container".into())),
            }
        }
        fn stop(&self, name: &str) -> Result<(), DockerError> {
            if let Some(c) = self.containers.borrow_mut().get_mut(name) {
                c.1 = false;
            }
            Ok(())
        }
        fn rename(&self, name: &str, to: &str) -> Result<(), DockerError> {
            let c = self
                .containers
                .borrow_mut()
                .remove(name)
                .ok_or(DockerError("missing".into()))?;
            self.containers.borrow_mut().insert(to.into(), c);
            Ok(())
        }
        fn remove(&self, name: &str) -> Result<(), DockerError> {
            self.containers.borrow_mut().remove(name);
            Ok(())
        }
        fn sleep(&self, _d: Duration) {}
    }

    fn options(data: &std::path::Path, source: Source) -> Options {
        Options {
            container: "aegis".into(),
            repository: REPO.into(),
            data: data.into(),
            socket: "/nonexistent".into(),
            source,
            interval: Duration::from_secs(3600),
        }
    }

    #[test]
    fn a_newer_local_release_is_found_and_installed() {
        let tmp = tempfile::tempdir().expect("tmp");
        let fake = Fake::default();
        fake.image("sha256:old", "0.7.0");
        fake.image(&format!("{REPO}:0.7.0"), "0.7.0");
        fake.image(&format!("{REPO}:0.8.0"), "0.8.0");
        fake.container("aegis", "sha256:old");
        let o = options(tmp.path(), Source::Local);
        let mut u = Updater::new(&o, &fake);
        u.check();
        assert_eq!(u.available, Some(Version(0, 8, 0)));
        u.upgrade(None);
        assert_eq!(
            fake.running_image("aegis").as_deref(),
            Some(&*format!("{REPO}:0.8.0"))
        );
        assert!(
            fake.running_image("aegis-previous").is_none(),
            "old container removed"
        );
        let status = files::status(tmp.path()).expect("status");
        assert_eq!(status["state"], "upgraded");
        assert_eq!(status["running"], "0.8.0");
        assert_eq!(status["source"], "local");
    }

    #[test]
    fn an_unhealthy_release_is_rolled_back() {
        let tmp = tempfile::tempdir().expect("tmp");
        let fake = Fake {
            unhealthy: vec![format!("{REPO}:0.8.0")],
            ..Fake::default()
        };
        fake.image("sha256:old", "0.7.0");
        fake.image(&format!("{REPO}:0.8.0"), "0.8.0");
        fake.container("aegis", "sha256:old");
        let o = options(tmp.path(), Source::Local);
        let mut u = Updater::new(&o, &fake);
        u.check();
        u.upgrade(None);
        assert_eq!(fake.running_image("aegis").as_deref(), Some("sha256:old"));
        assert!(
            fake.containers.borrow()["aegis"].1,
            "the previous one runs again"
        );
        let status = files::status(tmp.path()).expect("status");
        assert_eq!(status["state"], "rolled_back");
        assert!(status["message"]
            .as_str()
            .unwrap_or("")
            .contains("health check"));
    }

    #[test]
    fn registry_latest_is_tagged_with_its_version_and_offline_falls_back() {
        let tmp = tempfile::tempdir().expect("tmp");
        let fake = Fake {
            registry: Some("0.9.0".into()),
            ..Fake::default()
        };
        fake.image("sha256:old", "0.7.0");
        fake.container("aegis", "sha256:old");
        let o = options(tmp.path(), Source::Registry);
        let mut u = Updater::new(&o, &fake);
        u.check();
        assert_eq!(u.available, Some(Version(0, 9, 0)));
        assert!(fake.images.borrow().contains_key(&format!("{REPO}:0.9.0")));
        // Without the registry: what is on the machine, and a note.
        let offline = Fake::default();
        offline.image("sha256:old", "0.7.0");
        offline.container("aegis", "sha256:old");
        let mut u = Updater::new(&o, &offline);
        u.check();
        assert_eq!(u.available, None);
        let status = files::status(tmp.path()).expect("status");
        assert!(status["message"]
            .as_str()
            .unwrap_or("")
            .contains("registry"));
    }

    #[test]
    fn nothing_changes_for_a_missing_wrong_or_older_release() {
        let tmp = tempfile::tempdir().expect("tmp");
        let fake = Fake::default();
        fake.image("sha256:old", "0.7.0");
        // Tagged 0.8.0 but labelled otherwise: refused.
        fake.image(&format!("{REPO}:0.8.0"), "0.6.0");
        fake.image(&format!("{REPO}:0.6.0"), "0.6.0");
        fake.container("aegis", "sha256:old");
        let o = options(tmp.path(), Source::Local);
        let mut u = Updater::new(&o, &fake);
        for target in [Version(0, 9, 0), Version(0, 8, 0), Version(0, 6, 0)] {
            u.upgrade(Some(target));
            assert_eq!(
                fake.running_image("aegis").as_deref(),
                Some("sha256:old"),
                "{target}"
            );
            assert_eq!(
                files::status(tmp.path()).expect("status")["state"],
                "failed"
            );
        }
        assert!(fake.log.borrow().is_empty(), "no container was touched");
    }
}
