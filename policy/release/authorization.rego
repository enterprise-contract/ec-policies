package policy.release.authorization

import data.lib


# METADATA
# title: Authorization does not exist
# description: |-
#   Enterprise Contract verifies if the build was authorized
# custom:
#   short_name: disallowed_no_authorization
#   failure_msg: Commit does not contain authorization
deny[result] {
	data.authorization
	not data.authorization.authorizers
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Authorized commit does not match
# description: |-
#   Enterprise Contract verifies if an authorized commit was used as the source of a build
# custom:
#   short_name: disallowed_commit_does_not_match
#   failure_msg: Commit %s does not match authorized commit %s
deny[result] {
	data.authorization
	att := lib.pipelinerun_attestations[_]
	material := att.predicate.materials[_]
	data.authorization.changeId != material.digest.sha1
	result := lib.result_helper(rego.metadata.chain(), [material.digest.sha1, data.authorization.changeId])
}

# METADATA
# title: Authorized repo url does not match
# description: |-
#   Enterprise Contract verifies if an authorized repo url was used to build an image
# custom:
#   short_name: disallowed_repo_url_does_not_match
#   failure_msg: Repo url %s does not match authorized repo url %s
deny[result] {
	data.authorization
	att := lib.pipelinerun_attestations[_]
	material := att.predicate.materials[_]
	data.authorization.repository != material.uri
	result := lib.result_helper(rego.metadata.chain(), [material.uri, data.authorization.repository])
}
