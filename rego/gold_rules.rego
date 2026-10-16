package gold

import rego.v1

default allow := false

allow if {
    input.gold_passed == true
    input.release_digest == input.expected_digest
    input.requester != input.approver
    input.signature.verified == true
}
