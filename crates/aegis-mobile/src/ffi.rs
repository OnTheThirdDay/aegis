//! C entry points for the iOS app and its packet tunnel (Swift, through
//! `apps/aegis-mobile/ios/AegisCore/include/aegis_core.h`). Each takes
//! NUL-terminated UTF-8 strings and returns the JSON of the matching crate
//! function as a string the caller releases with [`aegis_free`].

use serde_json::Value;
use std::ffi::{c_char, CStr, CString};

/// # Safety
/// `p` is null or a NUL-terminated string valid for the duration of the call.
#[allow(unsafe_code)]
unsafe fn arg(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the caller guarantees a valid NUL-terminated string.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn ret(v: Value) -> *mut c_char {
    // JSON text never contains a NUL byte.
    CString::new(v.to_string()).map_or(std::ptr::null_mut(), CString::into_raw)
}

/// Join another server with an invitation and select it. Blocks.
///
/// # Safety
/// `dir` and `code` are NUL-terminated strings (or null).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_enroll(dir: *const c_char, code: *const c_char) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let (dir, code) = unsafe { (arg(dir), arg(code)) };
    ret(crate::enroll(&dir, &code))
}

/// # Safety
/// `dir` is a NUL-terminated string (or null).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_servers(dir: *const c_char) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let dir = unsafe { arg(dir) };
    ret(crate::servers(&dir))
}

/// # Safety
/// `dir` and `id` are NUL-terminated strings (or null).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_select(dir: *const c_char, id: *const c_char) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let (dir, id) = unsafe { (arg(dir), arg(id)) };
    ret(crate::select(&dir, &id))
}

/// Remove a server. Blocks. (On iOS the app stops the tunnel first: the
/// connection runs in the extension, not in the app.)
///
/// # Safety
/// `dir` and `id` are NUL-terminated strings (or null).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_forget(dir: *const c_char, id: *const c_char) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let (dir, id) = unsafe { (arg(dir), arg(id)) };
    ret(crate::forget(&dir, &id))
}

/// How the packet tunnel should set up its interface.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn aegis_vpn_config() -> *mut c_char {
    ret(crate::vpn_config())
}

/// Connect on this process's packet tunnel interface (the extension).
/// Returns at once; progress shows in [`aegis_status`].
///
/// # Safety
/// `dir` is a NUL-terminated string (or null).
#[cfg(target_vendor = "apple")]
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_start_tunnel(dir: *const c_char) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let dir = unsafe { arg(dir) };
    ret(crate::start_tunnel(&dir))
}

/// Disconnect. Blocks until the node stopped.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn aegis_stop() -> *mut c_char {
    ret(crate::stop())
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn aegis_status() -> *mut c_char {
    ret(crate::status())
}

/// Start recording diagnostics for `minutes` (1 to 60); `about` describes
/// the phone.
///
/// # Safety
/// `dir` and `about` are NUL-terminated strings (or null).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_diag_start(
    dir: *const c_char,
    minutes: u32,
    about: *const c_char,
) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let (dir, about) = unsafe { (arg(dir), arg(about)) };
    ret(crate::diag::start(&dir, u64::from(minutes), &about))
}

/// Stop recording; with `send` non-zero, send the report. Blocks.
///
/// # Safety
/// `dir` is a NUL-terminated string (or null).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_diag_stop(dir: *const c_char, send: i32) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let dir = unsafe { arg(dir) };
    ret(crate::diag::stop(&dir, send != 0))
}

/// Send the recorded report to the selected server. Blocks.
///
/// # Safety
/// `dir` is a NUL-terminated string (or null).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_diag_send(dir: *const c_char) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let dir = unsafe { arg(dir) };
    ret(crate::diag::send_now(&dir))
}

/// The tunnel is ending: send a recording that wasn't sent, or save it to
/// a file when that fails. Blocks.
///
/// # Safety
/// `dir` is a NUL-terminated string (or null).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_diag_finish(dir: *const c_char) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let dir = unsafe { arg(dir) };
    ret(crate::diag::finish(&dir))
}

/// Save the recorded report to a file to share; `{"path"}`.
///
/// # Safety
/// `dir` is a NUL-terminated string (or null).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_diag_save(dir: *const c_char) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let dir = unsafe { arg(dir) };
    ret(crate::diag::save(&dir))
}

/// # Safety
/// `dir` is a NUL-terminated string (or null).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_diag_discard(dir: *const c_char) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let dir = unsafe { arg(dir) };
    ret(crate::diag::discard(&dir))
}

/// Record a problem the platform side saw (no-op unless recording).
///
/// # Safety
/// `text` is a NUL-terminated string (or null).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_diag_note(text: *const c_char) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let text = unsafe { arg(text) };
    ret(crate::diag::note(&text))
}

/// The recording's state and the last send's outcome.
///
/// # Safety
/// `dir` is a NUL-terminated string (or null).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_diag_status(dir: *const c_char) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let dir = unsafe { arg(dir) };
    ret(crate::diag::status(&dir))
}

/// Release a string returned by any `aegis_` function.
///
/// # Safety
/// `s` is null or a string returned by this library, released once.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn aegis_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: `s` came from CString::into_raw here and is freed once.
        drop(unsafe { CString::from_raw(s) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(unsafe_code)]
    fn call(p: *mut c_char) -> Value {
        assert!(!p.is_null());
        // SAFETY: a string this library just returned, freed once below.
        let v =
            serde_json::from_str(&unsafe { CStr::from_ptr(p) }.to_string_lossy()).expect("json");
        // SAFETY: as above.
        unsafe { aegis_free(p) };
        v
    }

    #[test]
    #[allow(unsafe_code)]
    fn strings_cross_the_c_interface() {
        let cfg = call(aegis_vpn_config());
        assert_eq!(cfg["ok"], true);
        assert_eq!(cfg["dns"], "198.18.0.1");
        let dir = std::env::temp_dir().join(format!("aegis-ffi-test-{}", std::process::id()));
        let dir = CString::new(dir.to_string_lossy().as_bytes()).expect("dir");
        // SAFETY: valid NUL-terminated strings for the call.
        let servers = call(unsafe { aegis_servers(dir.as_ptr()) });
        assert_eq!(servers["servers"], serde_json::json!([]));
        // SAFETY: a null argument is allowed.
        let bad = call(unsafe { aegis_enroll(dir.as_ptr(), std::ptr::null()) });
        assert_eq!(bad["ok"], false);
        assert_eq!(call(aegis_status())["state"], "disconnected");
        // SAFETY: valid NUL-terminated strings for the calls.
        let diag = call(unsafe { aegis_diag_status(dir.as_ptr()) });
        assert_eq!(diag["state"], "off");
        // SAFETY: as above.
        let nothing = call(unsafe { aegis_diag_save(dir.as_ptr()) });
        assert_eq!(nothing["ok"], false);
        // SAFETY: freeing null is allowed.
        unsafe { aegis_free(std::ptr::null_mut()) };
    }
}
