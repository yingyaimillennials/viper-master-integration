"""F-03: Persistent challenge store - single-use, expiring, atomic."""
from __future__ import annotations
import hashlib, json, secrets, sqlite3, time
from pathlib import Path
from security.ed25519_sign import _load_pem_safe

DEFAULT_DB_PATH = Path("docs/challenges.db")


def _boot_id():
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except (FileNotFoundError, OSError):
        return "unknown"


class ChallengeStore:
    def __init__(self, db_path=DEFAULT_DB_PATH, ttl_seconds=300, monotonic_clock=time.monotonic):
        self.db_path = Path(db_path)
        self.ttl = ttl_seconds
        self._mono = monotonic_clock
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("""CREATE TABLE IF NOT EXISTS challenges (
                challenge_id TEXT PRIMARY KEY, email TEXT NOT NULL,
                pub_key_pem BLOB NOT NULL, issued_monotonic REAL NOT NULL,
                issued_wallclock REAL NOT NULL, issued_boot_id TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0, used_at_wallclock REAL)""")
            c.commit()

    def issue(self, email, pub_pem):
        cid = secrets.token_hex(16)
        with sqlite3.connect(self.db_path) as c:
            c.execute("INSERT INTO challenges VALUES (?,?,?,?,?,?,0,NULL)",
                      (cid, email, pub_pem, self._mono(), time.time(), _boot_id()))
            c.commit()
        return cid

    def redeem(self, cid, signature):
        conn = sqlite3.connect(self.db_path, timeout=5.0, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM challenges WHERE challenge_id=?", (cid,)).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return {"verified": False, "reason": "unknown_challenge"}
            if row["used"]:
                conn.execute("ROLLBACK")
                return {"verified": False, "reason": "challenge_already_used"}
            boot = _boot_id()
            if row["issued_boot_id"] != boot:
                if time.time() - row["issued_wallclock"] > self.ttl:
                    conn.execute("ROLLBACK")
                    return {"verified": False, "reason": "challenge_expired_after_reboot"}
            else:
                if self._mono() - row["issued_monotonic"] > self.ttl:
                    conn.execute("ROLLBACK")
                    return {"verified": False, "reason": "challenge_expired"}
            payload = f"VIPER_IDENTITY_CHALLENGE:{cid}:{row['email']}".encode()
            pub = _load_pem_safe(row["pub_key_pem"])
            if pub is None:
                conn.execute("ROLLBACK")
                return {"verified": False, "reason": "invalid_signature"}
            try:
                pub.verify(signature, payload)
            except Exception:
                conn.execute("ROLLBACK")
                return {"verified": False, "reason": "invalid_signature"}
            cur = conn.execute(
                "UPDATE challenges SET used=1, used_at_wallclock=? WHERE challenge_id=? AND used=0",
                (time.time(), cid))
            if cur.rowcount != 1:
                conn.execute("ROLLBACK")
                return {"verified": False, "reason": "challenge_already_used"}
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()
        att = {"email": row["email"],
               "public_key_fingerprint": "sha256:" + hashlib.sha256(row["pub_key_pem"]).hexdigest(),
               "challenge_id": cid, "verified_at_wallclock": time.time()}
        att["evidence_sha256"] = hashlib.sha256(json.dumps(att, sort_keys=True).encode()).hexdigest()
        return {"verified": True, "attestation": att}
