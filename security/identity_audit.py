"""F-04: Append-only hash-chained audit ledger (Linux/Mac, flock)."""
from __future__ import annotations
import fcntl, hashlib, json, os
from dataclasses import dataclass
from pathlib import Path

GENESIS = "sha256:" + "0" * 64


@dataclass
class VerifyResult:
    valid: bool
    blocks: int
    head: str
    error: str = ""


class IdentityAuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("")

    def append(self, event_type: str, subject: str, detail: dict) -> dict:
        with open(self.path, "a+b") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.seek(0)
            lines = [l for l in f.read().decode().splitlines() if l.strip()]
            prev = json.loads(lines[-1])["block_hash"] if lines else GENESIS
            block = {"seq": len(lines) + 1, "event_type": event_type,
                     "subject": subject, "detail": detail, "prev_hash": prev}
            block["block_hash"] = "sha256:" + hashlib.sha256(
                json.dumps(block, sort_keys=True).encode()).hexdigest()
            data = (json.dumps(block, sort_keys=True) + "\n").encode()
            f.seek(0, os.SEEK_END)
            w = 0
            while w < len(data):
                w += f.write(data[w:])
            f.flush()
            os.fsync(f.fileno())
        return block

    def verify(self) -> VerifyResult:
        try:
            lines = [l for l in self.path.read_text().splitlines() if l.strip()]
            prev = GENESIS
            for i, line in enumerate(lines):
                b = json.loads(line)
                if b.get("prev_hash") != prev:
                    return VerifyResult(False, i, prev, f"chain break at block {i+1}")
                expected = "sha256:" + hashlib.sha256(json.dumps(
                    {k: v for k, v in b.items() if k != "block_hash"},
                    sort_keys=True).encode()).hexdigest()
                if b.get("block_hash") != expected:
                    return VerifyResult(False, i + 1, prev, f"hash mismatch at block {i+1}")
                prev = b["block_hash"]
            return VerifyResult(True, len(lines), prev)
        except Exception as e:
            return VerifyResult(False, 0, GENESIS, str(e))

    def verify_against_anchor(self, expected_head) -> VerifyResult:
        r = self.verify()
        if not r.valid:
            return r
        if r.head != expected_head:
            return VerifyResult(False, r.blocks, r.head, "truncation or anchor mismatch")
        return r
