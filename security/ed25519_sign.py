"""F-01: Ed25519 sign/verify - fail-closed crypto primitives."""
from __future__ import annotations
import base64, hashlib
from typing import Optional
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def sign(priv, payload: bytes) -> str:
    if not isinstance(priv, ed25519.Ed25519PrivateKey):
        raise TypeError("priv must be Ed25519PrivateKey")
    if not isinstance(payload, bytes):
        raise ValueError("payload must be bytes")
    return base64.b64encode(priv.sign(payload)).decode("ascii")


def _load_pem_safe(pub_pem) -> Optional[ed25519.Ed25519PublicKey]:
    if not isinstance(pub_pem, (bytes, bytearray)):
        return None
    try:
        pub = serialization.load_pem_public_key(pub_pem)
        return pub if isinstance(pub, ed25519.Ed25519PublicKey) else None
    except Exception:
        return None


def verify(pub_pem, signature_b64: str, payload: bytes) -> bool:
    pub = _load_pem_safe(pub_pem)
    if pub is None:
        return False
    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return False
    try:
        pub.verify(sig, payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def export_public_pem(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def export_private_pem(priv, passphrase: bytes) -> bytes:
    if not isinstance(passphrase, bytes) or len(passphrase) < 16:
        raise ValueError("passphrase must be bytes >= 16 chars")
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def _canonical_fingerprint_raw(pub) -> str:
    return "sha256:" + hashlib.sha256(pub.public_bytes_raw()).hexdigest()


def fingerprint(pub_pem: bytes) -> str:
    pub = _load_pem_safe(pub_pem)
    if pub is None:
        raise ValueError("Cannot parse PEM as Ed25519 public key")
    return _canonical_fingerprint_raw(pub)


def public_key_hex(pub) -> str:
    import binascii
    return binascii.hexlify(pub.public_bytes_raw()).decode()
