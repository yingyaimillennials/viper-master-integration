package gold

default allow := false

allow if {
    input.gold_passed == true
}

allow if {
    input.release_digest == input.expected_digest
}

allow if {
    input.requester != input.approver
}

allow if {
    input.signature.verified == true
}
