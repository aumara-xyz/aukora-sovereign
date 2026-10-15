#!/usr/bin/env python3
"""Rehearse the owner flow against a live sovereign node with a software passkey (P-256).

Usage: rehearse.py OWNER_HOST CHAT_HOST [PORT]  (the claim token arrives on stdin, never argv)
Talks to 127.0.0.1:PORT the way the host's Caddy would (Host + X-Forwarded-*), and sends the
Origin and Sec-Fetch-Site a browser sends. Prints only step results, never tokens, cookies or words.
"""
import base64
import hashlib
import http.client
import json
import os
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

OWNER, CHAT = sys.argv[1], sys.argv[2]
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 28755
CLAIM = sys.stdin.read().strip().split("#claim=")[-1]
COOKIES = {}


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def step(name, ok, detail=""):
    print(f"{'OK ' if ok else 'FAIL'} {name}{(' — ' + detail) if detail else ''}", flush=True)
    if not ok:
        sys.exit(1)


def call(method, host, path, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=90)
    headers = {"Host": host, "X-Forwarded-Proto": "https", "X-Forwarded-Host": host,
               "X-Forwarded-For": "203.0.113.9", "Sec-Fetch-Site": "same-origin"}
    if method != "GET":
        headers["Origin"] = f"https://{host}"
        headers["Content-Type"] = "application/json"
    jar = COOKIES.get(host, {})
    if jar:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
    data = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers=headers)
    response = conn.getresponse()
    raw = response.read()
    for key, value in response.getheaders():
        if key.lower() == "set-cookie":
            name, _, rest = value.partition("=")
            COOKIES.setdefault(host, {})[name] = rest.split(";")[0]
    try:
        payload = json.loads(raw) if raw else None
    except ValueError:
        payload = raw
    return response.status, payload


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    if n < 65536:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    return bytes([major << 5 | 26]) + n.to_bytes(4, "big")


def cbor(value):
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return head(3, len(encoded)) + encoded
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(type(value))


KEY = ec.generate_private_key(ec.SECP256R1())
CRED = os.urandom(16)
RP_HASH = hashlib.sha256(OWNER.encode()).digest()
USER_HANDLE = None


def client_data(kind, challenge):
    return json.dumps({"type": kind, "challenge": challenge, "origin": f"https://{OWNER}",
                       "crossOrigin": False}, separators=(",", ":")).encode()


def assertion(challenge):
    data = client_data("webauthn.get", challenge)
    auth = RP_HASH + bytes([0x05]) + (0).to_bytes(4, "big")
    signature = KEY.sign(auth + hashlib.sha256(data).digest(), ec.ECDSA(hashes.SHA256()))
    return {"kind": "passkey", "credential_id": b64u(CRED), "client_data_json": b64u(data),
            "authenticator_data": b64u(auth), "signature": b64u(signature), "user_handle": USER_HANDLE}


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


status, state = call("GET", OWNER, "/api/state")
step("state before claim", status == 200 and state.get("session") is False, f"state={state.get('state')}")
status, body = call("POST", OWNER, "/api/claim", {"token": CLAIM})
step("claim opens an owner session", status == 200 and body.get("state") == "claim-open", f"http {status}")
status, body = call("POST", OWNER, "/api/claim", {"token": CLAIM})
step("the same claim is refused twice", status in (403, 409, 410), f"http {status} {body.get('error') if isinstance(body, dict) else ''}")

status, started = call("POST", OWNER, "/api/enrol/start", {})
step("enrol start", status == 200 and "public_key" in started, f"http {status}")
options = started["public_key"]
USER_HANDLE = options["user"]["id"]
x = KEY.public_key().public_numbers().x.to_bytes(32, "big")
y = KEY.public_key().public_numbers().y.to_bytes(32, "big")
auth_data = (RP_HASH + bytes([0x45]) + (0).to_bytes(4, "big") + bytes(16) + len(CRED).to_bytes(2, "big")
             + CRED + cbor({1: 2, 3: -7, -1: 1, -2: x, -3: y}))
attestation = {"kind": "passkey-registration", "id": b64u(CRED), "raw_id": b64u(CRED),
               "client_data_json": b64u(client_data("webauthn.create", options["challenge"])),
               "attestation_object": b64u(cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})),
               "client_extension_results": {}}
status, staged = call("POST", OWNER, "/api/enrol/finish", {"enrolment_id": started["enrolment_id"], "attestation": attestation})
step("registration verified, possession asked", status == 200 and staged.get("state") == "possession-required", f"http {status} {staged.get('error') if isinstance(staged, dict) else ''}")
status, body = call("POST", OWNER, "/api/enrol/finish", {"enrolment_id": started["enrolment_id"],
                                                          "assertion": assertion(staged["public_key"]["challenge"])})
step("possession proven, enrolment closed", status == 200 and body.get("state") == "enrolled", f"http {status} {body.get('error') if isinstance(body, dict) else ''}")
status, body = call("POST", OWNER, "/api/enrol/start", {})
step("a second enrolment is refused", status == 409, f"http {status}")

status, prepared = call("POST", OWNER, "/api/binding/prepare", {})
step("binding phrase drawn", status == 200 and len(prepared.get("words", [])) == 7, f"entropy_bits={prepared.get('entropy_bits')}")
words = prepared["words"]
anchor_ok = len(words[0]) == 6 and all(words[i + 1][0].lower() == words[0][i].lower() for i in range(6))
step("acrostic: six-letter anchor, words 2-7 start with its letters", anchor_ok)
wrong = list(words)
wrong[3] = wrong[3] + "x"
status, body = call("POST", OWNER, "/api/binding/confirm", {"ceremony_id": prepared["ceremony_id"], "words": wrong})
step("a wrong word is refused at its position", status == 422 and body.get("position") == 4, f"http {status} position={body.get('position') if isinstance(body, dict) else None}")
status, body = call("POST", OWNER, "/api/binding/confirm", {"ceremony_id": prepared["ceremony_id"], "words": words})
step("phrase bound, identity created", status == 200 and body.get("state") == "bound" and str(body.get("subject", "")).startswith("aukora:1:"), f"http {status}")

release = None
for _ in range(60):
    status, approvals = call("GET", OWNER, "/api/approvals")
    pending = approvals.get("pending", []) if status == 200 else []
    release = next((p for p in pending if p["card"].get("risk") == "critical"), None)
    if release:
        break
    time.sleep(2)
step("the supervisor proposed the release", release is not None, (release or {}).get("card", {}).get("says", ""))
status, challenge = call("POST", OWNER, "/api/approvals/challenge", {"id": release["id"]})
step("approval challenge issued", status == 200, f"http {status} {challenge.get('error') if isinstance(challenge, dict) else ''}")
expected = b64u(hashlib.sha256(b"aukora:owner-authorization:v1\0" + canon(challenge["auth"])).digest())
step("the passkey challenge is the C5 digest of the shown authorization", expected == challenge["public_key"]["challenge"], f"op={challenge['auth'].get('op')}")
status, decided = call("POST", OWNER, "/api/approvals/decide", {"id": release["id"], "approve": True,
                                                                 "assertion": assertion(challenge["public_key"]["challenge"])})
step("release approved with the passkey", status == 200 and decided.get("state") == "applied", f"http {status} state={decided.get('state')} seq={decided.get('seq')}")

agent = None
for _ in range(90):
    status, agent = call("GET", OWNER, "/api/release")
    if status == 200 and agent.get("agent") in ("running", "exited"):
        break
    time.sleep(2)
step("the agent is running under the approved release", status == 200 and agent.get("agent") == "running", f"agent={agent.get('agent') if isinstance(agent, dict) else agent}")

status, opened = call("POST", OWNER, "/api/chat-session", {})
step("chat handoff issued", status == 200 and opened["url"].startswith(f"https://{CHAT}/__aukora/chat#ticket="))
ticket = opened["url"].split("#ticket=")[1]
status, body = call("POST", CHAT, "/api/chat/session", {"ticket": ticket})
step("chat origin redeemed the ticket", status == 200, f"http {status}")
status, body = call("POST", CHAT, "/api/chat/session", {"ticket": ticket})
step("the ticket is single use", status == 403, f"http {status}")
page = None
for _ in range(30):
    status, page = call("GET", CHAT, "/")
    if status == 200:
        break
    time.sleep(2)
text = page.decode(errors="replace") if isinstance(page, bytes) else str(page)
step("the chat page loads from the sandboxed agent", status == 200 and "<html" in text.lower(), f"http {status}, {len(text)} bytes")
status, body = call("GET", OWNER, "/api/aura/recent?limit=100")
kinds = sorted({row["kind"] for row in body.get("rows", [])}) if status == 200 else []
step("Aura recorded the flow", status == 200 and len(kinds) > 2, ", ".join(kinds))
status, broker = call("GET", OWNER, "/api/broker")
step("broker answers (no key yet)", status == 200, json.dumps({"key": broker.get("key"), "grant": broker.get("grant"), "models": broker.get("models")}))
print("REHEARSAL PASS")
