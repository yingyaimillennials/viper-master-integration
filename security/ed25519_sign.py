"""F-02: Ed25519 sign/verify."""
import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def generate_keypair():
    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub


def sign(payload, private_pem):
    key = serialization.load_pem_private_key(private_pem, password=None)
    return base64.b64encode(key.sign(_canonical(payload))).decode()


def verify(payload, signature_b64, public_pem):
    pub = serialization.load_pem_public_key(public_pem)
    try:
        pub.verify(base64.b64decode(signature_b64), _canonical(payload))
        return True
    except InvalidSignature:
        return False
