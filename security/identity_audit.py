"""F-01: Identity audit log - append-only hash chain."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "sha256:" + "0" * 64


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _hash(record):
    return "sha256:" + hashlib.sha256(_canonical(record)).hexdigest()


class IdentityAuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self):
        if not self.path.exists():
            return GENESIS
        lines = [l for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]
        if not lines:
            return GENESIS
        return json.loads(lines[-1])["event_hash"]

    def append(self, event_type, subject, detail=None):
        record = {
            "schema_version": "viper.identity-audit/v1",
            "event_type": event_type,
            "subject": subject,
            "occurred_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "prev_hash": self._last_hash(),
            "detail": detail or {},
        }
        record["event_hash"] = _hash(record)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return record

    def verify(self):
        if not self.path.exists():
            return {"valid": False, "reason": "missing"}
        prev = GENESIS
        lines = [l for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]
        for i, line in enumerate(lines):
            rec = json.loads(line)
            claimed = rec.pop("event_hash")
            if rec.get("prev_hash") != prev:
                return {"valid": False, "reason": "chain_broken_at_" + str(i)}
            if _hash(rec) != claimed:
                return {"valid": False, "reason": "hash_mismatch_at_" + str(i)}
            prev = claimed
        return {"valid": True, "blocks": len(lines), "head": prev}
