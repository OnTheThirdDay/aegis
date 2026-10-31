#!/usr/bin/env python3
"""Which apps of the previous release can be carried into this one unchanged.

    unchanged-apps.py PREVIOUS_TAG ASSETS

ASSETS lists the previous release's asset names, one per line. Prints one
line per app whose build inputs are the same at PREVIOUS_TAG and HEAD and
whose builds that release has: the app, then the files to carry.

A release offers its apps as updates (ADR-0017); an app that didn't change
is carried instead of rebuilt, so devices aren't offered the same app with a
new number. Build inputs:
  - the app's workspace crates and every workspace crate they depend on,
    and files outside them that their sources include;
  - Cargo.toml, Cargo.lock and rust-toolchain.toml, with the workspace
    version (which every release bumps) left out;
  - the app's job in release.yml, without the lines that only decide whether
    and when it runs, and without comments;
  - the app's other sources and scripts (PATHS below).
Over-counting only rebuilds an app; what isn't listed here must not change
a build.

iOS is always rebuilt: gateways up to 1.1.8 label the iPhone app with the
release's version, not the app's, so a carried one would be offered again
and again.
"""

import hashlib
import re
import subprocess
import sys
import tomllib

APPS = {
    "desktop": {
        "package": "aegis-client",
        "job": "clients",
        "paths": [],
        "files": ["aegis-client-linux-x86_64", "aegis-client-windows-x86_64.exe"],
        "optional": [],
    },
    "macos": {
        "package": "aegis-client",
        "job": "clients-macos",
        "paths": [".github/scripts/macos-dmg.sh"],
        "files": ["aegis-client-macos.dmg"],
        "optional": [],
    },
    "android": {
        "package": "aegis-mobile",
        "job": "android",
        "paths": ["apps/aegis-mobile"],
        "skip": ["apps/aegis-mobile/ios/"],
        "files": ["aegis-client-android-arm64.apk"],
        # Built only when the release key is set.
        "optional": ["aegisnet-update-android-arm64.apk"],
    },
}
COMMON = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
WORKFLOW = ".github/workflows/release.yml"
# Job keys that decide whether and when a job runs, not what it builds.
SCHEDULING = re.compile(r"^    (if|needs|timeout-minutes|continue-on-error):")
INCLUDE = re.compile(r'include_(?:str|bytes)!\(\s*"([^"]+)"')


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def show(rev, path):
    return git("show", f"{rev}:{path}")


def files(rev, paths):
    out = git("ls-tree", "-r", "--name-only", rev, "--", *paths).decode()
    return [f for f in out.splitlines() if f]


def crates(rev, package):
    """Directories of `package` and the workspace crates it depends on."""
    root = tomllib.loads(show(rev, "Cargo.toml").decode())
    shared = root.get("workspace", {}).get("dependencies", {})
    manifests = {}
    for manifest in files(rev, ["Cargo.toml", "apps", "crates"]):
        if manifest.endswith("/Cargo.toml"):
            data = tomllib.loads(show(rev, manifest).decode())
            name = data.get("package", {}).get("name")
            if name:
                manifests[name] = (manifest.rsplit("/", 1)[0], data)

    def path_deps(data):
        tables = [data.get("dependencies", {}), data.get("build-dependencies", {})]
        for target in data.get("target", {}).values():
            tables += [target.get("dependencies", {}), target.get("build-dependencies", {})]
        for table in tables:
            for name, spec in table.items():
                if isinstance(spec, dict):
                    name = spec.get("package", name)
                    if spec.get("workspace") and isinstance(shared.get(name), dict):
                        spec = shared[name]
                    if "path" in spec:
                        yield name

    seen, todo = set(), [package]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        if name not in manifests:
            raise SystemExit(f"{rev}: no workspace crate {name}")
        todo += path_deps(manifests[name][1])
    return sorted(manifests[n][0] for n in seen)


def included(rev, dirs):
    """Files outside `dirs` that their Rust sources include."""
    out = set()
    for path in files(rev, dirs):
        if not path.endswith(".rs"):
            continue
        for target in INCLUDE.findall(show(rev, path).decode(errors="replace")):
            parts = path.split("/")[:-1]
            for part in target.split("/"):
                if part == "..":
                    parts.pop()
                elif part != ".":
                    parts.append(part)
            resolved = "/".join(parts)
            if not any(resolved.startswith(d + "/") for d in dirs):
                out.add(resolved)
    return sorted(out)


def job(rev, name):
    lines, inside = [], False
    for line in show(rev, WORKFLOW).decode().splitlines():
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
            inside = line.strip() == f"{name}:"
        elif inside and line.strip() and not line.lstrip().startswith("#"):
            if not SCHEDULING.match(line):
                lines.append(line.rstrip())
    if not lines:
        raise SystemExit(f"{rev}: no job {name} in {WORKFLOW}")
    return "\n".join(lines).encode()


def fingerprint(rev, app):
    version = tomllib.loads(show(rev, "Cargo.toml").decode())["workspace"]["package"]["version"]
    dirs = crates(rev, app["package"])
    paths = sorted(set(files(rev, COMMON + dirs + included(rev, dirs) + app["paths"])))
    paths = [p for p in paths if not any(p.startswith(s) for s in app.get("skip", []))]
    h = hashlib.sha256()
    for path in paths:
        data = show(rev, path)
        if path.rsplit("/", 1)[-1] in ("Cargo.toml", "Cargo.lock"):
            data = data.replace(f'"{version}"'.encode(), b'"@VERSION@"')
        h.update(path.encode() + b"\0" + hashlib.sha256(data).digest())
    h.update(b"job\0" + hashlib.sha256(job(rev, app["job"])).digest())
    return h.hexdigest()


def main():
    previous, assets_file = sys.argv[1:3]
    with open(assets_file) as f:
        assets = {line.strip() for line in f if line.strip()}
    for name, app in APPS.items():
        if not all(f in assets for f in app["files"]):
            print(f"{name}: {previous} doesn't have its builds", file=sys.stderr)
            continue
        if fingerprint(previous, app) != fingerprint("HEAD", app):
            print(f"{name}: changed since {previous}", file=sys.stderr)
            continue
        carry = app["files"] + [f for f in app["optional"] if f in assets]
        print(f"{name}: unchanged since {previous}", file=sys.stderr)
        print(" ".join([name, *carry]))


if __name__ == "__main__":
    main()
