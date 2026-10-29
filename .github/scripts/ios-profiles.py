#!/usr/bin/env python3
"""Make fresh Ad Hoc provisioning profiles for the iOS app and its packet
tunnel through the App Store Connect API, and install them where Xcode looks
(ADR-0018). Recreated on every build, so each one includes every iPhone
registered on the account.

Environment: APPLE_API_KEY_ID, APPLE_API_ISSUER_ID, APPLE_API_KEY_P8 (the key's
contents). The profiles use the account's newest Apple Distribution
certificate (the one CI signs with, RELEASING.md).

    ios-profiles.py install        # recreate and install both profiles
    ios-profiles.py add-device NAME UDID
"""
import base64
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# Bundle id -> the profile name the project's Release signing names.
PROFILES = {
    "borne.aegis.app": "AegisBorne Ad Hoc App",
    "borne.aegis.app.tunnel": "AegisBorne Ad Hoc Tunnel",
}
API = "https://api.appstoreconnect.apple.com"


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def token() -> str:
    key = serialization.load_pem_private_key(os.environ["APPLE_API_KEY_P8"].encode(), None)
    header = {"alg": "ES256", "kid": os.environ["APPLE_API_KEY_ID"], "typ": "JWT"}
    now = int(time.time())
    claims = {"iss": os.environ["APPLE_API_ISSUER_ID"], "iat": now, "exp": now + 900, "aud": "appstoreconnect-v1"}
    unsigned = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
    r, s = decode_dss_signature(key.sign(unsigned.encode(), ec.ECDSA(hashes.SHA256())))
    return f"{unsigned}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def call(method: str, path: str, body=None):
    req = urllib.request.Request(
        API + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token()}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as r:
            data = r.read()
            return r.status, json.loads(data) if data else {}
    except urllib.error.HTTPError as e:
        data = e.read()
        return e.code, json.loads(data) if data else {}


def need(status, out, ok=(200, 201, 204)):
    if status not in ok:
        sys.exit(f"App Store Connect: {status} {json.dumps(out.get('errors', out))[:600]}")
    return out


def install():
    devices = need(*call("GET", "/v1/devices?filter[status]=ENABLED&filter[platform]=IOS&limit=200"))["data"]
    if not devices:
        sys.exit("No iPhone is registered: Ad Hoc builds need at least one (ios-profiles.py add-device).")
    certs = need(*call("GET", "/v1/certificates?filter[certificateType]=DISTRIBUTION&limit=50"))["data"]
    if not certs:
        sys.exit("No Apple Distribution certificate on the account.")
    cert = max(certs, key=lambda c: c["attributes"].get("expirationDate") or "")["id"]
    folder = pathlib.Path.home() / "Library/MobileDevice/Provisioning Profiles"
    folder.mkdir(parents=True, exist_ok=True)
    for identifier, name in PROFILES.items():
        bundle = need(*call("GET", f"/v1/bundleIds?filter[identifier]={identifier}"))["data"]
        bundle = [b for b in bundle if b["attributes"]["identifier"] == identifier]
        if not bundle:
            sys.exit(f"No App ID {identifier} on the account.")
        # Replace the previous profile of that name: it lists older devices.
        old = need(*call("GET", f"/v1/profiles?filter[name]={urllib.request.quote(name)}"))["data"]
        for p in old:
            need(*call("DELETE", f"/v1/profiles/{p['id']}"))
        body = {
            "data": {
                "type": "profiles",
                "attributes": {"name": name, "profileType": "IOS_APP_ADHOC"},
                "relationships": {
                    "bundleId": {"data": {"type": "bundleIds", "id": bundle[0]["id"]}},
                    "certificates": {"data": [{"type": "certificates", "id": cert}]},
                    "devices": {"data": [{"type": "devices", "id": d["id"]} for d in devices]},
                },
            }
        }
        made = need(*call("POST", "/v1/profiles", body))["data"]
        content = base64.b64decode(made["attributes"]["profileContent"])
        (folder / f"{made['attributes']['uuid']}.mobileprovision").write_bytes(content)
        print(f"{name}: {len(devices)} device(s)")


def add_device(name: str, udid: str):
    out = need(*call("POST", "/v1/devices", {
        "data": {"type": "devices", "attributes": {"name": name, "udid": udid, "platform": "IOS"}}
    }))
    print("registered", out["data"]["attributes"]["name"])


if __name__ == "__main__":
    if sys.argv[1:2] == ["install"]:
        install()
    elif sys.argv[1:2] == ["add-device"] and len(sys.argv) == 4:
        add_device(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
