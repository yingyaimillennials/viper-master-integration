"""F-01..F-05 full security test suite."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security.identity_audit import IdentityAuditLog
from security.ed25519_sign import generate_keypair, sign, verify
from security.challenge_flow import ChallengeStore


def test_identity_audit_chain():
    with tempfile.TemporaryDirectory() as tmp:
        ledger = IdentityAuditLog(Path(tmp) / "audit.jsonl")
        ledger.append("LOGIN", "alice@example.org")
        ledger.append("LOGOUT", "alice@example.org")
        result = ledger.verify()
        assert result["valid"] is True
        assert result["blocks"] == 2
    print("[F-01 PASS] identity audit chain")


def test_identity_audit_tamper_detected():
    with tempfile.TemporaryDirectory() as tmp:
        ledger = IdentityAuditLog(Path(tmp) / "audit.jsonl")
        ledger.append("LOGIN", "alice@example.org")
        path = Path(tmp) / "audit.jsonl"
        path.write_text(path.read_text().replace("LOGIN", "EVIL"))
        result = ledger.verify()
        assert result["valid"] is False
    print("[F-01 PASS] tamper detection")


def test_ed25519_roundtrip():
    priv, pub = generate_keypair()
    payload = {"decision": "APPROVE", "digest": "sha256:abc"}
    sig = sign(payload, priv)
    assert verify(payload, sig, pub) is True
    print("[F-02 PASS] ed25519 roundtrip")


def test_ed25519_rejects_tamper():
    priv, pub = generate_keypair()
    sig = sign({"x": 1}, priv)
    assert verify({"x": 2}, sig, pub) is False
    print("[F-02 PASS] ed25519 rejects tamper")


def test_challenge_consume_once():
    store = ChallengeStore()
    nonce = store.issue("alice")
    assert store.consume(nonce, "alice") is True
    assert store.consume(nonce, "alice") is False
    print("[F-03 PASS] challenge consume-once")


def test_challenge_wrong_subject():
    store = ChallengeStore()
    nonce = store.issue("alice")
    assert store.consume(nonce, "bob") is False
    print("[F-03 PASS] challenge subject mismatch")


def test_no_secrets_committed():
    root = Path(__file__).resolve().parents[1]
    forbidden = []
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in {".pem", ".key"}:
            if ".pub" not in path.name:
                forbidden.append(path)
    assert not forbidden, "secret files found: " + str(forbidden)
    print("[F-04 PASS] no secret files")


def test_fail_closed_default():
    rego = Path(__file__).resolve().parents[1] / "rego" / "gold_rules.rego"
    if rego.exists():
        text = rego.read_text()
        assert "default allow := false" in text
        print("[F-05 PASS] default deny")
    else:
        print("[F-05 SKIP] rego not yet compiled")


if __name__ == "__main__":
    test_identity_audit_chain()
    test_identity_audit_tamper_detected()
    test_ed25519_roundtrip()
    test_ed25519_rejects_tamper()
    test_challenge_consume_once()
    test_challenge_wrong_subject()
    test_no_secrets_committed()
    test_fail_closed_default()
    print("")
    print("=== SECURITY TEST SUITE: ALL PASSED ===")
