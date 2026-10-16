from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from identity_audit import TrustedKeyRegistry

def generate_keypair():
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub

def sign(priv, msg):
    sk = Ed25519PrivateKey.from_private_bytes(priv)
    return sk.sign(msg if isinstance(msg, bytes) else msg.encode())

def verify(reg, key_id, msg, sig):
    if not reg.is_trusted(key_id):
        return False
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(reg.keys[key_id]))
        pk.verify(sig, msg if isinstance(msg, bytes) else msg.encode())
        return True
    except Exception:
        return False
