from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(txt: str) -> bytes:
    return base64.b64decode(txt.encode("ascii"))


@dataclass
class Identity:
    name: str
    shared_secret: str

    @classmethod
    def create(cls, name: str, shared_secret: str) -> "Identity":
        return cls(name=name, shared_secret=shared_secret)


def _expand_keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha512).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _derive_keys(shared_secret: str, salt: bytes, aad: bytes) -> tuple[bytes, bytes]:
    master = hashlib.scrypt(
        password=shared_secret.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        maxmem=64 * 1024 * 1024,
        dklen=64,
    )
    enc_key = hmac.new(master[:32], aad + b"|enc", hashlib.sha512).digest()
    mac_key = hmac.new(master[32:], aad + b"|mac", hashlib.sha512).digest()
    return enc_key, mac_key


def encrypt_for_recipient(sender: Identity, plaintext: str, aad_fields: dict) -> dict:
    aad = json.dumps(aad_fields, sort_keys=True).encode("utf-8")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(24)

    enc_key, mac_key = _derive_keys(sender.shared_secret, salt, aad)
    keystream = _expand_keystream(enc_key, nonce, len(plaintext.encode("utf-8")))
    ciphertext = _xor(plaintext.encode("utf-8"), keystream)

    tag = hmac.new(mac_key, aad + nonce + ciphertext, hashlib.sha512).digest()
    return {
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "tag": b64e(tag),
    }


def decrypt_from_sender(recipient: Identity, envelope: dict, aad_fields: dict) -> str:
    aad = json.dumps(aad_fields, sort_keys=True).encode("utf-8")
    salt = b64d(envelope["salt"])
    nonce = b64d(envelope["nonce"])
    ciphertext = b64d(envelope["ciphertext"])
    tag = b64d(envelope["tag"])

    enc_key, mac_key = _derive_keys(recipient.shared_secret, salt, aad)
    expected = hmac.new(mac_key, aad + nonce + ciphertext, hashlib.sha512).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("message authentication failed")

    keystream = _expand_keystream(enc_key, nonce, len(ciphertext))
    plaintext = _xor(ciphertext, keystream)
    return plaintext.decode("utf-8")
