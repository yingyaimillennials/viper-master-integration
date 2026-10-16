import json, threading
from security.identity_audit import IdentityAuditLog

def test_append_and_verify(tmp_path):
    log = IdentityAuditLog(tmp_path / "l.jsonl")
    log.append("link.success", "alice", {"key": "a"})
    log.append("link.failure", "bob", {"reason": "bad"})
    r = log.verify()
    assert r.valid and r.blocks == 2

def test_tamper(tmp_path):
    log = IdentityAuditLog(tmp_path / "l.jsonl")
    log.append("e", "s", {})
    lines = log.path.read_text().splitlines()
    b = json.loads(lines[0])
    b["detail"]["x"] = 1
    log.path.write_text(json.dumps(b, sort_keys=True) + "\n")
    assert not log.verify().valid

def test_concurrent(tmp_path):
    log = IdentityAuditLog(tmp_path / "l.jsonl")
    def w(i):
        for j in range(5):
            log.append("event", f"s-{i}", {"n": j})
    ts = [threading.Thread(target=w, args=(i,)) for i in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    r = log.verify()
    assert r.valid and r.blocks == 20

def test_truncation(tmp_path):
    log = IdentityAuditLog(tmp_path / "l.jsonl")
    log.append("e", "s", {})
    head = log.verify().head
    log.path.write_text("")
    assert not log.verify_against_anchor(head).valid
