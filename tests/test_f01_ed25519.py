from security.ed25519_sign import *

def test_roundtrip():
    priv, pub = generate_keypair()
    pem = export_public_pem(pub)
    sig = sign(priv, b"p")
    assert verify(pem, sig, b"p") and not verify(pem, sig, b"o")

def test_malformed():
    assert not verify(b"nope", "AAAA", b"x")

def test_fp():
    priv, pub = generate_keypair()
    pem = export_public_pem(pub)
    assert fingerprint(pem) == fingerprint(pem)
