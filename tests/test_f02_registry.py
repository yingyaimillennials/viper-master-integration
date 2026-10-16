import base64, json
from pathlib import Path
from security.ed25519_sign import generate_keypair, sign, export_public_pem, fingerprint
from security.key_registry import KeyRegistry

def make(tmp_path, priv, pub):
    pem = export_public_pem(pub)
    reg = {"keys": [{"fingerprint": fingerprint(pem), "public_key_pem": pem.decode(),
                     "owner": "alice", "role": "requester",
                     "issued_at": "2026-01-01T00:00:00+00:00"}]}
    p = tmp_path / "t.json"
    p.write_text(json.dumps(reg))
    return KeyRegistry(p), pem

def test_trusted(tmp_path):
    priv, pub = generate_keypair()
    reg, pem = make(tmp_path, priv, pub)
    assert reg.is_trusted(pem)
    assert reg.verify_signature(pem, base64.b64decode(sign(priv, b"x")), b"x")

def test_unknown(tmp_path):
    priv, pub = generate_keypair()
    reg, _ = make(tmp_path, priv, pub)
    _, pub2 = generate_keypair()
    assert not reg.is_trusted(export_public_pem(pub2))
