import json, time, hashlib, os, secrets
class TrustedKeyRegistry:
    def __init__(self, path="trusted_keys.json"):
        self.path = path
        self.keys = json.load(open(path)) if os.path.exists(path) else {}
    def register(self, k, p):
        self.keys[k] = p
        json.dump(self.keys, open(self.path, "w"))
    def is_trusted(self, k):
        return k in self.keys

class ChallengeStore:
    def __init__(self, ttl=300):
        self.store = {}
        self.ttl = ttl
    def create(self):
        c = secrets.token_hex(32)
        self.store[c] = {"exp": time.time() + self.ttl, "used": False}
        return c
    def verify(self, c):
        e = self.store.get(c)
        if not e or e["used"] or time.time() > e["exp"]:
            return False
        e["used"] = True
        return True

class AuditLedger:
    def __init__(self, path="audit_ledger.jsonl"):
        self.path = path
        self.prev = "0" * 64
    def append(self, event):
        r = {"ts": time.time(), "event": event, "prev": self.prev}
        r["hash"] = hashlib.sha256(json.dumps(r, sort_keys=True).encode()).hexdigest()
        with open(self.path, "a") as f:
            f.write(json.dumps(r) + "
")
        self.prev = r["hash"]
        return r["hash"]
    def verify_chain(self):
        prev = "0" * 64
        for line in open(self.path):
            r = json.loads(line)
            if r["prev"] != prev:
                return False
            h = r.pop("hash")
            if hashlib.sha256(json.dumps(r, sort_keys=True).encode()).hexdigest() != h:
                return False
            prev = h
        return True
