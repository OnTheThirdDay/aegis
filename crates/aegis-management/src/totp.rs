//! Time-based one-time passwords (RFC 6238: HMAC-SHA1, 6 digits, 30 s) for
//! two-factor sign-in, plus single-use recovery codes.
//!
//! The shared secret is kept in the secret directory (`totp/<principal>`,
//! owner-only), never in the database; the database records only whether
//! 2FA is on, the last time step used (each code works once) and recovery
//! code hashes.

use crate::http_util::ApiError;
use crate::ManagementContext;
use rand::RngCore;
use std::path::PathBuf;

pub const DIGITS: u32 = 6;
pub const PERIOD: u64 = 30;
/// Accepted clock difference, in steps either side.
const WINDOW: i64 = 1;
const SECRET_BYTES: usize = 20;
pub const RECOVERY_CODES: usize = 10;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding (the form authenticator apps expect).
pub fn base32(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for c in text.bytes().filter(|c| !matches!(c, b' ' | b'=' | b'-')) {
        let v = ALPHABET.iter().position(|&a| a == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buffer >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// The code for time step `step`.
pub fn code_at(secret: &[u8], step: u64) -> u32 {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let mac = ring::hmac::sign(&key, &step.to_be_bytes());
    let h = mac.as_ref();
    let offset = (h[h.len() - 1] & 0x0f) as usize;
    let value = u32::from_be_bytes([
        h[offset] & 0x7f,
        h[offset + 1],
        h[offset + 2],
        h[offset + 3],
    ]);
    value % 10u32.pow(DIGITS)
}

pub fn step_of(unix: i64) -> i64 {
    unix.div_euclid(PERIOD as i64)
}

/// The time step `code` matches around `unix`, if any.
pub fn verify(secret: &[u8], code: &str, unix: i64) -> Option<i64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = code.parse().ok()?;
    let now = step_of(unix);
    (now - WINDOW..=now + WINDOW)
        .filter(|s| *s >= 0)
        .find(|s| code_at(secret, *s as u64) == wanted)
}

pub fn new_secret() -> Vec<u8> {
    let mut s = vec![0u8; SECRET_BYTES];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// `otpauth://` URI for authenticator apps.
pub fn uri(username: &str, secret: &[u8]) -> String {
    let label: String = username
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!(
        "otpauth://totp/AegisNet:{label}?secret={}&issuer=AegisNet&algorithm=SHA1&digits={DIGITS}&period={PERIOD}",
        base32(secret)
    )
}

/// QR code of `text` as rows of '1' (dark) and '0', drawn by the console
/// (its content security policy allows no inline images).
pub fn qr_rows(text: &str) -> Vec<String> {
    let Ok(qr) = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium) else {
        return Vec::new();
    };
    (0..qr.size())
        .map(|y| {
            (0..qr.size())
                .map(|x| if qr.get_module(x, y) { '1' } else { '0' })
                .collect()
        })
        .collect()
}

/// Fresh recovery codes, shown once: `xxxxx-xxxxx` (lowercase base32).
pub fn new_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let mut b = [0u8; 7];
            rand::thread_rng().fill_bytes(&mut b);
            let s = base32(&b).to_ascii_lowercase();
            format!("{}-{}", &s[..5], &s[5..10])
        })
        .collect()
}

/// Stored form of a recovery code (normalized, then SHA-256).
pub fn recovery_hash(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    aegis_storage::sha256_hex(normalized.as_bytes())
}

pub fn looks_like_recovery_code(code: &str) -> bool {
    code.chars().filter(char::is_ascii_alphanumeric).count() == 10 && code.contains('-')
}

// ---------------------------------------------------------------- secret files

fn dir(ctx: &ManagementContext) -> PathBuf {
    ctx.secrets_dir.join("totp")
}

fn path(ctx: &ManagementContext, principal: &str, pending: bool) -> Result<PathBuf, ApiError> {
    if principal.is_empty()
        || !principal
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(ApiError::bad_request("invalid_principal"));
    }
    Ok(dir(ctx).join(if pending {
        format!("{principal}.pending")
    } else {
        principal.to_owned()
    }))
}

pub fn store(
    ctx: &ManagementContext,
    principal: &str,
    pending: bool,
    secret: &[u8],
) -> Result<(), ApiError> {
    let p = path(ctx, principal, pending)?;
    let write = || -> std::io::Result<()> {
        std::fs::create_dir_all(dir(ctx))?;
        let tmp = p.with_extension("tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                opts.mode(0o600);
                let _ = std::fs::set_permissions(dir(ctx), std::fs::Permissions::from_mode(0o700));
            }
            use std::io::Write;
            let mut f = opts.open(&tmp)?;
            f.write_all(base32(secret).as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &p)
    };
    write().map_err(|_| ApiError::unavailable().detail("could not store the 2FA secret"))
}

pub fn load(ctx: &ManagementContext, principal: &str, pending: bool) -> Option<Vec<u8>> {
    let text = std::fs::read_to_string(path(ctx, principal, pending).ok()?).ok()?;
    base32_decode(text.trim()).filter(|s| !s.is_empty())
}

pub fn remove(ctx: &ManagementContext, principal: &str, pending: bool) {
    if let Ok(p) = path(ctx, principal, pending) {
        let _ = std::fs::remove_file(p);
    }
}

/// Promote the pending secret (set up but not yet confirmed) to active.
pub fn activate(ctx: &ManagementContext, principal: &str) -> Result<(), ApiError> {
    let from = path(ctx, principal, true)?;
    let to = path(ctx, principal, false)?;
    std::fs::rename(from, to).map_err(|_| ApiError::conflict("two_factor_not_set_up"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vectors() {
        // RFC 6238 appendix B, SHA-1 seed, truncated to 6 digits.
        let secret = b"12345678901234567890";
        for (t, code) in [
            (59u64, 287_082u32),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
        ] {
            assert_eq!(code_at(secret, t / PERIOD), code, "t={t}");
        }
    }

    #[test]
    fn base32_round_trip_and_known_value() {
        assert_eq!(
            base32(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        let s = new_secret();
        assert_eq!(base32_decode(&base32(&s)).as_deref(), Some(&s[..]));
        assert_eq!(
            base32_decode("gezd gnbv").as_deref(),
            base32_decode("GEZDGNBV").as_deref()
        );
        assert!(base32_decode("not base32!").is_none());
    }

    #[test]
    fn verify_accepts_one_step_of_skew_only() {
        let secret = new_secret();
        let now = 1_800_000_000;
        let step = step_of(now);
        let code = |s: i64| format!("{:06}", code_at(&secret, s as u64));
        assert_eq!(verify(&secret, &code(step), now), Some(step));
        assert_eq!(verify(&secret, &code(step - 1), now), Some(step - 1));
        assert_eq!(verify(&secret, &code(step + 1), now), Some(step + 1));
        assert_eq!(verify(&secret, &code(step + 3), now), None);
        assert_eq!(verify(&secret, "12345", now), None);
        assert_eq!(verify(&secret, "abcdef", now), None);
    }

    #[test]
    fn recovery_codes_normalize_and_qr_renders() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert!(codes.iter().all(|c| looks_like_recovery_code(c)));
        assert_eq!(
            recovery_hash(&codes[0]),
            recovery_hash(&codes[0].to_uppercase())
        );
        let rows = qr_rows(&uri("alice", &new_secret()));
        assert!(rows.len() >= 21 && rows.iter().all(|r| r.len() == rows.len()));
    }
}
