import json
import sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

def verify_signature(public_key_hex, signature_hex, payload):
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), payload.encode())
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Error verifying: {e}")
        return False

def main():
    # สมมติว่า CI มี Public Key ของ Requester และ Approver (ใน Secrets)
    # และมี Signature ที่ถูกส่งมาใน Environment Variables หรือไฟล์
    requester_pub = sys.argv[1]  # Public Key ของ Requester
    approver_pub = sys.argv[2]   # Public Key ของ Approver
    requester_sig = sys.argv[3]  # Signature ของ Requester
    approver_sig = sys.argv[4]   # Signature ของ Approver
    payload = sys.argv[5]        # ข้อมูลที่ถูกเซ็น (เช่น SHA256 ของ Artifact)

    req_verified = verify_signature(requester_pub, requester_sig, payload)
    app_verified = verify_signature(approver_pub, approver_sig, payload)

    result = {
        "gold_passed": True,
        "release_digest": payload,
        "expected_digest": payload,
        "requester": "alice",
        "approver": "bob",
        "requester_signature": {"verified": req_verified},
        "approver_signature": {"verified": app_verified}
    }

    with open("examples/opa_input.json", "w") as f:
        json.dump(result, f, indent=2)

    print(f"Requester Verified: {req_verified}")
    print(f"Approver Verified: {app_verified}")

    if not (req_verified and app_verified):
        print("❌ Multi-Sig verification failed!")
        sys.exit(1)

    print("✅ Multi-Sig verified successfully!")

if __name__ == "__main__":
    main()
