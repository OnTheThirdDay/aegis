//! The control pipe. Its access list lets LocalSystem, administrators and
//! the user who installed the helper open it; nobody else, and no other
//! computer.

use std::ffi::c_void;
use std::io;
use std::time::Duration;
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

pub const PIPE: &str = r"\\.\pipe\aegisborne-vpn";
const ERROR_PIPE_BUSY: i32 = 231;

/// A security descriptor, kept for the life of the process.
pub struct Descriptor(usize);

impl Descriptor {
    /// Full control for LocalSystem and administrators; read and write for
    /// `sid` (checked by the caller with `valid_sid`).
    #[allow(unsafe_code)]
    pub fn new(sid: &str) -> io::Result<Descriptor> {
        if !super::valid_sid(sid) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid SID"));
        }
        let sddl: Vec<u16> = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{sid})")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut sd: *mut c_void = std::ptr::null_mut();
        // SAFETY: `sddl` is a NUL-terminated UTF-16 string that outlives the
        // call; `sd` receives a newly allocated descriptor (never freed: it
        // is used for every pipe instance until the process exits).
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || sd.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(sd as usize))
    }
}

/// A pipe instance to wait for the next connection on. The first one
/// fails if anyone else already created the pipe.
#[allow(unsafe_code)]
pub fn create(descriptor: &Descriptor, first: bool) -> io::Result<NamedPipeServer> {
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0 as *mut c_void,
        bInheritHandle: 0,
    };
    // SAFETY: `attrs` lives across the call and points to a valid security
    // descriptor that lives for the rest of the process.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(PIPE, std::ptr::from_mut(&mut attrs).cast())
    }
}

/// Open the helper's pipe (NotFound: the helper isn't running).
pub async fn connect() -> io::Result<NamedPipeClient> {
    let mut tries = 0;
    loop {
        match ClientOptions::new().open(PIPE) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && tries < 40 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            other => return other,
        }
    }
}
