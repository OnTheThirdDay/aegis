//! `cargo run -p xtask -- arch-check` — enforce the crate dependency rules of
//! 02 §2 / A-002 over the *resolved* (transitive, normal) dependency graph,
//! and the `#![forbid(unsafe_code)]` policy of 06 §1.
//!
//! `arch-check --self-test` proves the checker rejects an injected
//! forbidden edge (TC-U01).
#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::process::{Command, ExitCode};

/// (crate, forbidden dependency prefix, reason)
const RULES: &[(&str, &str, &str)] = &[
    (
        "aegis-contracts",
        "tokio",
        "contracts must not depend on an async runtime",
    ),
    (
        "aegis-contracts",
        "hyper",
        "contracts must not depend on HTTP stacks",
    ),
    (
        "aegis-contracts",
        "axum",
        "contracts must not depend on management",
    ),
    (
        "aegis-contracts",
        "aegis-",
        "contracts import no other first-party module",
    ),
    ("aegis-agp", "tokio", "the wire codec is runtime-free"),
    (
        "aegis-agp",
        "aegis-telemetry",
        "telemetry is not imported in parser core",
    ),
    (
        "aegis-session",
        "aegis-telemetry",
        "data plane uses the Observability trait only",
    ),
    (
        "aegis-session",
        "aegis-management",
        "data plane never depends on management",
    ),
    (
        "aegis-session",
        "aegis-storage",
        "no database in the data hot path",
    ),
    (
        "aegis-transport-ws",
        "aegis-management",
        "transports cannot depend on management",
    ),
    (
        "aegis-transport-ws",
        "aegis-storage",
        "transports cannot depend on storage",
    ),
    (
        "aegis-transport-ws",
        "aegis-core",
        "transports are registered by the composition root",
    ),
    (
        "aegis-transport-quic",
        "aegis-management",
        "transports cannot depend on management",
    ),
    (
        "aegis-transport-quic",
        "aegis-storage",
        "transports cannot depend on storage",
    ),
    (
        "aegis-transport-quic",
        "aegis-core",
        "transports are registered by the composition root",
    ),
    (
        "aegis-transport-quic",
        "aegis-session",
        "the transport carries bytes and datagrams; the node wires sessions",
    ),
    (
        "aegis-updater",
        "aegis-",
        "the updater (root-equivalent through Docker) carries no other first-party code",
    ),
    (
        "aegis-inbound-socks",
        "aegis-management",
        "inbounds cannot depend on management",
    ),
    (
        "aegis-inbound-socks",
        "aegis-storage",
        "inbounds cannot depend on storage",
    ),
    (
        "aegis-inbound-http",
        "aegis-management",
        "inbounds cannot depend on management",
    ),
    (
        "aegis-inbound-http",
        "aegis-storage",
        "inbounds cannot depend on storage",
    ),
    (
        "aegis-outbound-direct",
        "aegis-management",
        "outbounds cannot depend on management",
    ),
    (
        "aegis-outbound-direct",
        "aegis-storage",
        "outbounds cannot depend on storage",
    ),
    (
        "aegis-core",
        "aegis-transport-",
        "core depends on contracts/registry, not concrete transports",
    ),
    (
        "aegis-core",
        "aegis-inbound-",
        "core is transport/inbound agnostic",
    ),
    ("aegis-core", "aegis-outbound-", "core is outbound agnostic"),
    (
        "aegis-core",
        "aegis-session",
        "core is session-engine agnostic",
    ),
    (
        "aegis-core",
        "aegis-management",
        "core does not depend on management",
    ),
    (
        "aegis-core",
        "aegis-telemetry",
        "no feedback loop from telemetry into core",
    ),
    (
        "aegis-management",
        "aegis-node",
        "management uses the config/core facade, not data-plane internals",
    ),
    (
        "aegis-management",
        "aegis-session",
        "management does not touch data-plane structs",
    ),
    (
        "aegis-management",
        "aegis-transport-",
        "management does not touch data-plane structs",
    ),
    (
        "aegis-telemetry",
        "aegis-core",
        "telemetry must not feed back into core",
    ),
    (
        "aegis-telemetry",
        "aegis-node",
        "telemetry must not feed back into the data plane",
    ),
    (
        "aegis-policy",
        "tokio",
        "policy evaluation is synchronous and pure",
    ),
    (
        "aegis-traffic-policy",
        "tokio",
        "policy evaluation is synchronous and pure",
    ),
    ("aegis-config", "tokio", "configuration compilation is pure"),
];

type Graph = BTreeMap<String, BTreeSet<String>>;

/// Build name -> transitive normal dependencies from `cargo metadata`.
fn load_graph() -> Result<Graph, String> {
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["metadata", "--format-version", "1", "--locked"])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for p in v["packages"].as_array().into_iter().flatten() {
        if let (Some(id), Some(name)) = (p["id"].as_str(), p["name"].as_str()) {
            names.insert(id.to_owned(), name.to_owned());
        }
    }
    let mut direct: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for node in v["resolve"]["nodes"].as_array().into_iter().flatten() {
        let Some(id) = node["id"].as_str() else {
            continue;
        };
        let deps = node["deps"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|d| {
                d["dep_kinds"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|k| k["kind"].is_null())
            })
            .filter_map(|d| d["pkg"].as_str().map(str::to_owned))
            .collect();
        direct.insert(id.to_owned(), deps);
    }
    let mut graph = Graph::new();
    for (id, name) in &names {
        let mut seen = BTreeSet::new();
        let mut stack: Vec<String> = direct
            .get(id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        while let Some(d) = stack.pop() {
            if seen.insert(d.clone()) {
                stack.extend(direct.get(&d).cloned().unwrap_or_default());
            }
        }
        graph.insert(
            name.clone(),
            seen.iter().filter_map(|d| names.get(d).cloned()).collect(),
        );
    }
    Ok(graph)
}

fn violations(graph: &Graph) -> Vec<String> {
    let mut out = Vec::new();
    for (krate, forbidden, reason) in RULES {
        let Some(deps) = graph.get(*krate) else {
            continue;
        };
        for d in deps {
            if d.starts_with(forbidden) && d != krate {
                out.push(format!("{krate} -> {d}: {reason}"));
            }
        }
    }
    out
}

/// Crates that must cross a platform boundary (ADR-0011): `deny` instead of
/// `forbid`, so every unsafe item is allowed explicitly where it is.
const UNSAFE_BOUNDARY: &[(&str, &str)] = &[
    (
        "crates/aegis-mobile",
        "JNI exports (#[no_mangle]) and the VPN interface's file descriptor",
    ),
    (
        "crates/aegis-vpn",
        "the Windows control pipe's access list, the service entry point and the WFP DNS filters",
    ),
];

fn unsafe_policy() -> Vec<String> {
    let mut out = Vec::new();
    let roots = ["crates", "apps", "xtask"];
    for root in roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        let dirs: Vec<std::path::PathBuf> = if root == "xtask" {
            vec![std::path::PathBuf::from("xtask")]
        } else {
            entries.flatten().map(|e| e.path()).collect()
        };
        for dir in dirs {
            for file in ["src/lib.rs", "src/main.rs"] {
                let p = dir.join(file);
                if let Ok(text) = std::fs::read_to_string(&p) {
                    let boundary = UNSAFE_BOUNDARY
                        .iter()
                        .any(|(d, _)| dir == std::path::Path::new(d));
                    let required = if boundary {
                        "#![deny(unsafe_code)]"
                    } else {
                        "#![forbid(unsafe_code)]"
                    };
                    if !text.contains(required) {
                        out.push(format!("{}: missing {required}", p.display()));
                    }
                }
            }
        }
    }
    out
}

fn self_test() -> bool {
    let mut g = Graph::new();
    g.insert(
        "aegis-contracts".into(),
        ["serde".to_string(), "tokio".to_string()]
            .into_iter()
            .collect(),
    );
    g.insert(
        "aegis-core".into(),
        ["aegis-transport-ws".to_string()].into_iter().collect(),
    );
    let v = violations(&g);
    let ok = v.iter().any(|s| s.starts_with("aegis-contracts -> tokio"))
        && v.iter()
            .any(|s| s.starts_with("aegis-core -> aegis-transport-ws"));
    println!(
        "self-test: injected forbidden edges {}",
        if ok { "rejected" } else { "NOT rejected" }
    );
    ok
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("arch-check") => {
            if args.iter().any(|a| a == "--self-test") {
                return if self_test() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                };
            }
            let graph = match load_graph() {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("xtask: cargo metadata failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let mut problems = violations(&graph);
            problems.extend(unsafe_policy());
            if problems.is_empty() {
                println!("arch-check: {} rules and unsafe policy hold", RULES.len());
                ExitCode::SUCCESS
            } else {
                for p in &problems {
                    eprintln!("arch-check: {p}");
                }
                ExitCode::FAILURE
            }
        }
        _ => {
            eprintln!("usage: cargo run -p xtask -- arch-check [--self-test]");
            ExitCode::FAILURE
        }
    }
}
