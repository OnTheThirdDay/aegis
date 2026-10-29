//! Management state store (04 §6).
//!
//! SQLite in WAL mode with `synchronous=FULL` so a returned commit is
//! durable. This store holds management state only — never session payloads
//! — and is never consulted on the data path: the runtime admits streams from
//! an immutable in-memory snapshot.
//!
//! Secrets never enter this database: revisions store `secret://`
//! references, tokens/passwords are stored as verifier hashes, and audit
//! metadata is sanitized by callers.
#![forbid(unsafe_code)]

mod migrations;
pub mod model;

pub use model::*;
pub use rusqlite::{Connection, OptionalExtension, Transaction};

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Sqlite(String),
    NotFound,
    Conflict(String),
    Corrupt(String),
    /// Injected/test failure or an I/O condition such as disk full.
    Unavailable(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Sqlite(e) => write!(f, "storage error: {e}"),
            StoreError::NotFound => f.write_str("not found"),
            StoreError::Conflict(e) => write!(f, "conflict: {e}"),
            StoreError::Corrupt(e) => write!(f, "corrupt state: {e}"),
            StoreError::Unavailable(e) => write!(f, "storage unavailable: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
            other => StoreError::Sqlite(other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Run blocking database work (waiting for the connection, a query, a busy
/// database) without holding up the async runtime. On a worker of a
/// multi-threaded runtime the worker first hands its queued tasks (tunnel
/// traffic among them) to another thread; anywhere else (no runtime, a
/// blocking thread, a single-threaded runtime) `f` just runs.
fn off_runtime<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

pub struct Store {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("path", &self.path).finish()
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for p in [
        path.to_path_buf(),
        path.with_extension("db-wal"),
        path.with_extension("db-shm"),
    ] {
        if p.exists() {
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        }
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

impl Store {
    /// Open (creating if needed) and migrate. Files are restricted to the
    /// owning user on Unix.
    pub fn open(path: impl AsRef<Path>) -> Result<Store> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| StoreError::Unavailable(e.to_string()))?;
            }
        }
        let conn = Connection::open(&path)?;
        Self::configure(&conn)?;
        migrations::run(&conn)?;
        restrict_permissions(&path);
        Ok(Store {
            conn: Mutex::new(conn),
            path,
        })
    }

    /// In-memory store for tests.
    pub fn open_in_memory() -> Result<Store> {
        let conn = Connection::open_in_memory()?;
        Self::configure(&conn)?;
        migrations::run(&conn)?;
        Ok(Store {
            conn: Mutex::new(conn),
            path: PathBuf::from(":memory:"),
        })
    }

    fn configure(conn: &Connection) -> Result<()> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Run `f` inside one IMMEDIATE transaction: all of its writes commit
    /// atomically and durably, or none do.
    pub fn tx<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        off_runtime(|| {
            let mut conn = self.lock();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let out = f(&tx)?;
            tx.commit()?;
            Ok(out)
        })
    }

    /// Read-only access.
    pub fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        off_runtime(|| f(&self.lock()))
    }

    /// Read-only access with a caller-defined error type.
    pub fn read_as<T, E>(
        &self,
        f: impl FnOnce(&Connection) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        off_runtime(|| f(&self.lock()))
    }

    /// Integrity check (TC-C04 corruption detection).
    pub fn integrity_check(&self) -> Result<()> {
        let r: String = off_runtime(|| {
            self.lock()
                .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        })?;
        if r == "ok" {
            Ok(())
        } else {
            Err(StoreError::Corrupt(r))
        }
    }
}
