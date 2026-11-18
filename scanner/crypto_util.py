"""Password-based encryption shared with the dashboard (docs/app.js).

Format (JSON):
  {"v": 1, "kdf": "PBKDF2-SHA256", "iter": 310000, "salt": b64, "iv": b64, "ct": b64}

AES-256-GCM with a key derived from the shared dashboard password. The browser
uses WebCrypto with exactly the same parameters, so either side can read what
the other wrote.
"""
import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 310_000


class DecryptError(Exception):
    pass


def _key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def encrypt_json(obj, password: str) -> dict:
    salt = os.urandom(16)
    iv = os.urandom(12)
    plaintext = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ct = AESGCM(_key(password, salt, ITERATIONS)).encrypt(iv, plaintext, None)
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return {"v": 1, "kdf": "PBKDF2-SHA256", "iter": ITERATIONS, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}


def decrypt_json(envelope: dict, password: str):
    try:
        salt = base64.b64decode(envelope["salt"])
        iv = base64.b64decode(envelope["iv"])
        ct = base64.b64decode(envelope["ct"])
        key = _key(password, salt, int(envelope.get("iter", ITERATIONS)))
        return json.loads(AESGCM(key).decrypt(iv, ct, None).decode("utf-8"))
    except Exception as exc:  # wrong password or corrupted file
        raise DecryptError(str(exc)) from exc
