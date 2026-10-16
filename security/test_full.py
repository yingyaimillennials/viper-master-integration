import sys, os, tempfile
sys.path.insert(0, os.path.dirname(__file__))
from identity_audit import TrustedKeyRegistry, ChallengeStore, AuditLedger
from ed25519_sign import generate_keypair
from challenge_flow import challenge_response

with tempfile.TemporaryDirectory() as d:
    os.chdir(d)
    priv, pub = generate_keypair()
    reg = TrustedKeyRegistry("k.json")
    reg.register("k1", pub.hex())
    cs = ChallengeStore()
    led = AuditLedger("l.jsonl")
    assert challenge_response(reg, cs, led, "k1", priv)["ok"] is True
    assert challenge_response(reg, cs, led, "unknown", priv)["ok"] is False
    assert led.verify_chain() is True
print("CHALLENGE-RESPONSE + ED25519 + AUDIT: ALL TESTS PASS")
