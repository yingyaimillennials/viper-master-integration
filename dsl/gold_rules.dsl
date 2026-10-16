# VIPER Gold Rules DSL v1.0
gold_gate when input.gold_passed == true
digest_bound when input.release_digest == input.expected_digest
four_eyes when input.requester != input.approver
signature_valid when input.signature.verified == true
