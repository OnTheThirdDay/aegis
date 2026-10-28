//! Windows builds embed Wintun (`wintun.dll` from wintun.net, unmodified)
//! when `AEGIS_WINTUN_DIR` names the unpacked release folder (the one with
//! `LICENSE.txt` and `bin/`). The installer writes it next to the helper.
//! Builds without it can't install the system VPN and say so.

use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-env-changed=AEGIS_WINTUN_DIR");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_default()
        .as_str()
    {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "x86",
        _ => "",
    };
    let dir = std::env::var_os("AEGIS_WINTUN_DIR").map(PathBuf::from);
    if let (Some(dir), "windows", false) = (dir, target_os.as_str(), arch.is_empty()) {
        let dll = dir.join("bin").join(arch).join("wintun.dll");
        let license = dir.join("LICENSE.txt");
        println!("cargo::rerun-if-changed={}", dll.display());
        std::fs::copy(&dll, out.join("wintun.dll")).expect("AEGIS_WINTUN_DIR: wintun.dll");
        std::fs::copy(&license, out.join("wintun-LICENSE.txt"))
            .expect("AEGIS_WINTUN_DIR: LICENSE.txt");
        println!("cargo::rustc-cfg=has_wintun");
    }
}
