#!/usr/bin/env python3
"""Independent check of the portable suite's known-answer vectors.

Uses only the `cryptography` package (HKDF, AES-GCM, PBKDF2), the same
primitives an iOS or Android port uses. Run from the repository root:

    python3 scripts/check-portable-vectors.py
"""
import base64, hashlib, hmac, json, os, struct, sys, unicodedata
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
v = json.load(open(os.path.join(root, "internal/seclayer/testdata/portable-vectors.json")))
master = bytes.fromhex(v["keyHex"])

def decrypt_object(obj, master):
    assert obj[:4] == b"SPE1"
    chunk = struct.unpack(">I", obj[4:8])[0]
    header, body = obj[:24], obj[24:]
    key = HKDF(hashes.SHA256(), 32, obj[8:24], b"securepail-file-v1").derive(master)
    aes, out, i, pos = AESGCM(key), b"", 0, 0
    while True:
        block = body[pos:pos + chunk + 16]
        last = pos + len(block) >= len(body)
        nonce = struct.pack(">I", i) + b"\0" * 7 + (b"\1" if last else b"\0")
        out += aes.decrypt(nonce, block, header)
        pos += len(block); i += 1
        if last:
            return out

obj = base64.b64decode(v["object"]["objectBase64"])
assert decrypt_object(obj, master).hex() == v["object"]["plaintextHex"], "object mismatch"

kf = json.loads(v["keyFile"]["json"])
kek = hashlib.pbkdf2_hmac("sha256", unicodedata.normalize("NFC", v["keyFile"]["password"]).encode(),
                          base64.b64decode(kf["salt"]), kf["iterations"], 32)
wrapped = base64.b64decode(kf["wrappedKey"])
got = AESGCM(kek).decrypt(wrapped[:12], wrapped[12:], b"securepail-key-v1")
assert got == master, "key file mismatch"
assert hmac.new(master, b"securepail-check", "sha256").digest()[:16] == base64.b64decode(kf["check"])
print("portable vectors OK (independent implementation agrees)")
