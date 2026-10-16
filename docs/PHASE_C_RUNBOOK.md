# Phase C Runbook — Multi-Machine Setup

## Config ที่ locked
- Transfer: Email
- Identity: Fingerprint (device + PM unlock)
- Private Key: Password Manager
- RELEASE_AUTHORIZATION: DENY (fail-closed)

## Machine Roles
- Machine 1: Requester (เครื่องตัวเอง)
- Machine 2: Approver (แทปเลต)
- Machine 3: Independent Witness (เครื่องแม่) — optional

## Steps
### Machine 1 (Requester)
1. สร้าง Ed25519 keypair
2. เข้ารหัส private key (passphrase ใน PM)
3. เก็บ private key ใน Password Manager
4. ลบไฟล์ plaintext ทิ้ง
5. Issue challenge → redeem → attestation
6. Commit docs/attestations/requester.json
7. ส่ง signature ไป Machine 2 ผ่าน Email

### Machine 2 (Approver)
1-6. เหมือน M1 (role=approver)
7. รับ requester signature จาก M1
8. รวม dual-signature → opa_input.json
9. Commit + push

### CI Verification
verify_multi_sig ตรวจ:
- Requester signature verified
- Approver signature verified
- Keys & emails distinct
- Requester attested
- Approver attested

ผ่านครบ → INDEPENDENT_VERIFICATION=TESTED_PASS

## Cautions
- Private key: Password Manager / Hardware Key เท่านั้น ห้าม commit
- 2 เครื่องห้ามใช้ PM account เดียวกัน
- Signature transfer ห้ามผ่าน Git
- เปิด NTP time sync ทุกเครื่อง (สำคัญต่อ TTL)
- Reboot ระหว่าง challenge → TTL ใช้ wallclock fallback
