"""Regenerate the disposable v1 vector using Python cryptography, not RustCrypto."""

import base64
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


def rotate_left(value, distance):
    return ((value << distance) | (value >> (32 - distance))) & 0xFFFFFFFF


def quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotate_left(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotate_left(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotate_left(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotate_left(state[b] ^ state[c], 7)


def hchacha20(key, nonce16):
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        for indices in [
            (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
            (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14),
        ]:
            quarter_round(state, *indices)
    return struct.pack("<8I", *(state[index] for index in [0, 1, 2, 3, 12, 13, 14, 15]))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def encode(value):
    return base64.b64encode(value).decode("ascii")


salt = bytes([0x12] * 16)
nonce = bytes([0x34] * 24)
header = {
    "kdf": {
        "algorithm": "argon2id",
        "memory_kib": 32,
        "parallelism": 1,
        "time_cost": 1,
        "version": 19,
    },
    "nonce": encode(nonce),
    "salt": encode(salt),
    "version": 1,
}
key = Argon2id(salt=salt, length=32, iterations=1, lanes=1, memory_cost=32).derive(
    b"envelope interoperability fixture"
)
subkey = hchacha20(key, nonce[:16])
associated_data = b"aukora:aumlok-envelope:v1\0" + canonical(header).encode("ascii")
ciphertext = ChaCha20Poly1305(subkey).encrypt(
    b"\0\0\0\0" + nonce[16:], bytes([0x5A] * 32), associated_data
)
envelope = {"ciphertext": encode(ciphertext), **header}
Path(__file__).with_name("envelope-v1.json").write_text(canonical(envelope) + "\n")
