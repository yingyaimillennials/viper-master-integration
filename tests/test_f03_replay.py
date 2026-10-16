import time
from security.ed25519_sign import generate_keypair, export_public_pem
from security.challenge_flow import ChallengeStore

def test_single_use(tmp_path):
    s = ChallengeStore(tmp_path / "c.db", ttl_seconds=300)
    priv, pub = generate_keypair()
    cid = s.issue("a@x.com", export_public_pem(pub))
    sig = priv.sign(f"VIPER_IDENTITY_CHALLENGE:{cid}:a@x.com".encode())
    assert s.redeem(cid, sig)["verified"]
    r = s.redeem(cid, sig)
    assert not r["verified"] and r["reason"] == "challenge_already_used"

def test_expired(tmp_path):
    s = ChallengeStore(tmp_path / "c.db", ttl_seconds=0)
    priv, pub = generate_keypair()
    cid = s.issue("a@x.com", export_public_pem(pub))
    time.sleep(0.01)
    sig = priv.sign(f"VIPER_IDENTITY_CHALLENGE:{cid}:a@x.com".encode())
    r = s.redeem(cid, sig)
    assert not r["verified"] and "expired" in r["reason"]
