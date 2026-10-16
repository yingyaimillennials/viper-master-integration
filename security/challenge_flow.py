from identity_audit import ChallengeStore, AuditLedger
from ed25519_sign import sign, verify

def challenge_response(reg, cs, ledger, key_id, priv, action="link"):
    challenge = cs.create()
    sig = sign(priv, challenge.encode())
    ok = cs.verify(challenge) and verify(reg, key_id, challenge, sig)
    ledger.append({"action": action, "key_id": key_id, "ok": ok})
    return {"challenge": challenge, "ok": ok}
