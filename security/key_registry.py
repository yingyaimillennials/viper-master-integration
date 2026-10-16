"""F-02: Trusted Key Registry - fail-closed."""
from __future__ import annotations
import datetime, json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from security.ed25519_sign import _load_pem_safe, _canonical_fingerprint_raw, fingerprint as strict_fp

DEFAULT_REGISTRY_PATH = Path("docs/trusted_keys.json")

class RegistryError(Exception): ...
class NotTrusted(Exception): ...

def _is_expired(expires_at):
    if not expires_at:
        return False
    try:
        exp = datetime.datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as e:
        raise RegistryError(f"Invalid expires_at: {expires_at}") from e
    return datetime.datetime.now(datetime.timezone.utc) > exp

@dataclass(frozen=True)
class TrustedKey:
    fingerprint: str
    public_key_pem: bytes
    owner: str
    role: str
    issued_at: str
    expires_at: Optional[str] = None

class KeyRegistry:
    def __init__(self, path=DEFAULT_REGISTRY_PATH):
        self.path = Path(path)
        self._keys = {}
        self._load()

    def _load(self):
        if not self.path.exists():
            raise RegistryError(f"Registry not found: {self.path}")
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        keys = raw.get("keys", [])
        if not keys:
            raise RegistryError("Registry is empty")
        for e in keys:
            k = TrustedKey(e["fingerprint"], e["public_key_pem"].encode(),
                           e["owner"], e["role"], e["issued_at"], e.get("expires_at"))
            _is_expired(k.expires_at)
            if strict_fp(k.public_key_pem) != k.fingerprint:
                raise RegistryError(f"Fingerprint mismatch for {k.owner}")
            self._keys[k.fingerprint] = k

    def lookup(self, pub_pem):
        pub = _load_pem_safe(pub_pem)
        if pub is None:
            raise NotTrusted("Malformed PEM")
        fp = _canonical_fingerprint_raw(pub)
        k = self._keys.get(fp)
        if k is None:
            raise NotTrusted(f"Key not in registry: {fp}")
        if _is_expired(k.expires_at):
            raise NotTrusted(f"Key expired: {fp}")
        return k

    def is_trusted(self, pub_pem):
        try:
            self.lookup(pub_pem)
            return True
        except (NotTrusted, RegistryError):
            return False

    def verify_signature(self, pub_pem, sig, payload):
        pub = _load_pem_safe(pub_pem)
        if pub is None:
            return False
        fp = _canonical_fingerprint_raw(pub)
        if fp not in self._keys:
            return False
        try:
            if _is_expired(self._keys[fp].expires_at):
                return False
        except RegistryError:
            return False
        try:
            pub.verify(sig, payload)
            return True
        except Exception:
            return False
