# Decisions D-001..D-012

- D-001 TTL แยก 2 reason (monotonic / after-reboot) — Accepted
- D-002 Used challenge retention 30 วัน — Accepted
- D-003 Fingerprint = sha256 ของ raw bytes — Accepted
- D-004 verify/is_trusted ห้าม raise — Accepted
- D-005 Commit ordering ตาม plan — Accepted
- D-006 SQLite WAL — Accepted
- D-007 SQLite timeout 5s — Accepted
- D-008 PEM + Base64 — Accepted
- D-009 Truncation detection ด้วย head anchor — Accepted
- D-010 JSONL + flock — Accepted
- D-011 fsync ทุก append — Accepted
- D-012 Linux/Mac only (Windows ใช้ WSL2) — Accepted
