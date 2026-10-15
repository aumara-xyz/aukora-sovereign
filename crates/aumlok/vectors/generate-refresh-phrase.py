"""Pin the disposable pending-phrase cipher with Python cryptography."""

import ast
import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# Reuse only the independent HChaCha implementation, without regenerating envelopes.
source = Path(__file__).with_name("generate-envelope.py")
functions = [
    node for node in ast.parse(source.read_text()).body
    if isinstance(node, ast.FunctionDef)
    and node.name in {"rotate_left", "quarter_round", "hchacha20"}
]
namespace = {"struct": struct}
exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), namespace)

root = bytes([42] * 32)
nonce = bytes([12] * 24)
ceremony_id = "00112233445566778899aabbccddeeff"
plaintext = b"refresh phrase fixture"
key = hashlib.sha256(b"aukora:aumlok-refresh-phrase-key:v1\0" + root).digest()
subkey = namespace["hchacha20"](key, nonce[:16])
ciphertext = ChaCha20Poly1305(subkey).encrypt(
    b"\0\0\0\0" + nonce[16:], plaintext, ceremony_id.encode("ascii")
)
vector = {
    "ceremony_id": ceremony_id,
    "ciphertext_hex": ciphertext.hex(),
    "nonce_hex": nonce.hex(),
    "plaintext_hex": plaintext.hex(),
    "root_hex": root.hex(),
}
Path(__file__).with_name("refresh-phrase-v1.json").write_text(
    json.dumps(vector, sort_keys=True, separators=(",", ":")) + "\n"
)
