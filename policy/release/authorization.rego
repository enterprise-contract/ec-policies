#
# METADATA
# description: |-
#   This package contains rules to check that the image is signed-off
#   for release. There are different ways of providing that sign-off
#   authorization.
#
#   TODO: Document the ways that release authorization can be provided.
#
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
	count(data.authorization) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Authorized commit does not match
# description: |-
#   Enterprise Contract verifies if an authorized commit was used as the source of a build
# custom:
#   short_name: disallowed_commit_does_not_match
#   failure_msg: Commit %s does not match authorized commits
deny[result] {
	data.authorization
	count(data.authorization) > 0
	att := lib.pipelinerun_attestations[_]
	material := att.predicate.materials[_]
	auths := data.authorization[_]
	not sha_in_auth(material.digest.sha1, data.authorization)
	result := lib.result_helper(rego.metadata.chain(), [material.digest.sha1])
}

# METADATA
# title: Authorized repo url does not match
# description: |-
#   Enterprise Contract verifies if an authorized repo url was used to build an image
# custom:
#   short_name: disallowed_repo_url_does_not_match
#   failure_msg: Repo url %s does not match authorized repo urls
deny[result] {
	data.authorization
	count(data.authorization) > 0
	att := lib.pipelinerun_attestations[_]
	material := att.predicate.materials[_]
	not repo_in_auth(material.uri, data.authorization)
	result := lib.result_helper(rego.metadata.chain(), [material.uri])
}

sha_in_auth(changeid, authorizations) {
	auths := authorizations[_]
	auths.changeId == changeid
}

repo_in_auth(repo, authorizations) {
	auths := authorizations[_]
	auths.repoUrl == repo
}
