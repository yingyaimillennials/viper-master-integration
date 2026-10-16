package staging

import rego.v1

default allow_staging := false

allow_staging if {
    input.health == "ok"
    input.integration_check == "pass"
    input.artifact_sha256 != ""
    input.deploy_id != ""
}
