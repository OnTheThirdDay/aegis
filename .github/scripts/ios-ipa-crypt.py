#!/usr/bin/env python3
"""Encrypt or decrypt the iPhone app for publishing (ADR-0019). An Ad Hoc
build lists every registered iPhone's UDID, so it is published encrypted,
and only gateways given the key can read it.

    ios-ipa-crypt.py encrypt|decrypt IN OUT
    AEGIS_IOS_APP_KEY  32 bytes, base64

Format (apps/aegisd/src/integrations/ios.rs): b"AEGISIPA1", a 12-byte
nonce, then AES-256-GCM ciphertext and tag, with b"aegisborne-ipa/1" as
associated data.
"""
import base64
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"AEGISIPA1"
AAD = b"aegisborne-ipa/1"


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("encrypt", "decrypt"):
        sys.exit(__doc__)
    key = base64.b64decode(os.environ["AEGIS_IOS_APP_KEY"].strip())
    if len(key) != 32:
        sys.exit("AEGIS_IOS_APP_KEY must be 32 bytes, base64")
    data = open(sys.argv[2], "rb").read()
    aead = AESGCM(key)
    if sys.argv[1] == "encrypt":
        nonce = os.urandom(12)
        out = MAGIC + nonce + aead.encrypt(nonce, data, AAD)
    else:
        if not data.startswith(MAGIC):
            sys.exit("not an encrypted iPhone app")
        nonce, sealed = data[len(MAGIC):len(MAGIC) + 12], data[len(MAGIC) + 12:]
        out = aead.decrypt(nonce, sealed, AAD)
    open(sys.argv[3], "wb").write(out)


if __name__ == "__main__":
    main()
