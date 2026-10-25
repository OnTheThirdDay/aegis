//! `secret://` references.
//!
//! A reference names a file under the configured secrets directory
//! (e.g. a mounted `/run/secrets/aegisnet`). Values never appear in
//! configuration, revisions, digests, API responses or logs.

use std::path::{Path, PathBuf};

pub const SCHEME: &str = "secret://";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    NotAReference,
    InvalidPath,
    Unreadable(String),
    TooLarge,
    InsecurePermissions,
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::NotAReference => f.write_str("value must be a secret:// reference"),
            SecretError::InvalidPath => f.write_str("secret reference path is invalid"),
            // Only the reference (never the value) is echoed.
            SecretError::Unreadable(r) => write!(f, "secret {r} is not readable"),
            SecretError::TooLarge => f.write_str("secret file too large"),
            SecretError::InsecurePermissions => {
                f.write_str("secret requires a regular, owner-only file without symlinks")
            }
        }
    }
}

impl std::error::Error for SecretError {}

/// Validate the syntax of a reference and return its relative path.
pub fn parse_ref(reference: &str) -> Result<&str, SecretError> {
    let path = reference
        .strip_prefix(SCHEME)
        .ok_or(SecretError::NotAReference)?;
    let ok = !path.is_empty()
        && path.len() <= 256
        && !path.starts_with('/')
        && path.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        });
    if ok {
        Ok(path)
    } else {
        Err(SecretError::InvalidPath)
    }
}

pub fn resolve_path(dir: &Path, reference: &str) -> Result<PathBuf, SecretError> {
    Ok(dir.join(parse_ref(reference)?))
}

/// Read a secret file (bounded at 1 MiB).
pub fn read(dir: &Path, reference: &str) -> Result<String, SecretError> {
    let path = resolve_path(dir, reference)?;
    // Every component beneath the trusted root must be real, never a symlink.
    let mut part = dir.to_path_buf();
    for segment in parse_ref(reference)?.split('/') {
        part.push(segment);
        let m = std::fs::symlink_metadata(&part)
            .map_err(|_| SecretError::Unreadable(reference.into()))?;
        if m.file_type().is_symlink() {
            return Err(SecretError::InsecurePermissions);
        }
    }
    let file = std::fs::File::open(&path).map_err(|_| SecretError::Unreadable(reference.into()))?;
    let meta = file
        .metadata()
        .map_err(|_| SecretError::Unreadable(reference.into()))?;
    if !meta.is_file() {
        return Err(SecretError::InsecurePermissions);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let before = std::fs::symlink_metadata(&path)
            .map_err(|_| SecretError::Unreadable(reference.into()))?;
        if meta.permissions().mode() & 0o077 != 0
            || meta.nlink() != 1
            || meta.ino() != before.ino()
            || meta.dev() != before.dev()
        {
            return Err(SecretError::InsecurePermissions);
        }
    }
    if meta.len() > 1024 * 1024 {
        return Err(SecretError::TooLarge);
    }
    use std::io::Read;
    let mut value = String::new();
    file.take(1024 * 1024 + 1)
        .read_to_string(&mut value)
        .map_err(|_| SecretError::Unreadable(reference.into()))?;
    if value.len() > 1024 * 1024 {
        return Err(SecretError::TooLarge);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_syntax() {
        assert_eq!(
            parse_ref("secret://identity/server-key"),
            Ok("identity/server-key")
        );
        assert_eq!(parse_ref("/etc/shadow"), Err(SecretError::NotAReference));
        assert_eq!(parse_ref("secret://../x"), Err(SecretError::InvalidPath));
        assert_eq!(parse_ref("secret:///abs"), Err(SecretError::InvalidPath));
        assert_eq!(parse_ref("secret://a//b"), Err(SecretError::InvalidPath));
        assert_eq!(parse_ref("secret://a b"), Err(SecretError::InvalidPath));
    }
}
