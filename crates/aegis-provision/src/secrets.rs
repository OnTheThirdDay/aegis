//! Restricted file-backed secret store. Values never implement Debug/Serialize.
use crate::{Error, Result};
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct SecretStore {
    root: PathBuf,
}
impl SecretStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        if root.exists()
            && std::fs::symlink_metadata(root)
                .map_err(|_| Error("secret_store_unavailable"))?
                .file_type()
                .is_symlink()
        {
            return Err(Error("secret_store_symlink"));
        }
        std::fs::create_dir_all(root).map_err(|_| Error("secret_store_unavailable"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| Error("secret_store_permissions"))?;
        }
        #[cfg(not(unix))]
        return Err(Error("protected_secret_store_requires_unix_in_this_build"));
        #[cfg(unix)]
        Ok(Self {
            root: std::fs::canonicalize(root).map_err(|_| Error("secret_store_unavailable"))?,
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn read(&self, name: &str) -> Result<Zeroizing<String>> {
        aegis_config::secret::read(&self.root, &format!("secret://{name}"))
            .map(Zeroizing::new)
            .map_err(|_| Error("secret_unavailable_or_insecure_permissions"))
    }
    pub fn put(&self, name: &str, value: &str, replace: bool) -> Result<()> {
        let rel = aegis_config::secret::parse_ref(&format!("secret://{name}"))
            .map_err(|_| Error("invalid_secret_reference"))?
            .to_owned();
        if rel.contains('/') || value.len() > 1024 * 1024 {
            return Err(Error("invalid_secret"));
        }
        let path = self.root.join(rel);
        if path.exists() && !replace {
            return Err(Error("secret_already_exists"));
        }
        if std::fs::symlink_metadata(&path)
            .is_ok_and(|m| m.file_type().is_symlink() || !m.is_file())
        {
            return Err(Error("secret_path_not_owned"));
        }
        let temporary = self
            .root
            .join(format!(".pending-{:032x}", rand::random::<u128>()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let result = (|| {
            let mut file = opts
                .open(&temporary)
                .map_err(|_| Error("secret_write_failed"))?;
            file.write_all(value.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|_| Error("secret_write_failed"))?;
            if !replace {
                // Hard-link publication is atomic and cannot overwrite a race.
                std::fs::hard_link(&temporary, &path)
                    .map_err(|_| Error("secret_already_exists"))?;
                std::fs::remove_file(&temporary).map_err(|_| Error("secret_write_failed"))?;
            } else {
                std::fs::rename(&temporary, &path).map_err(|_| Error("secret_write_failed"))?;
            }
            #[cfg(unix)]
            std::fs::File::open(&self.root)
                .and_then(|d| d.sync_all())
                .map_err(|_| Error("secret_write_failed"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }
}
