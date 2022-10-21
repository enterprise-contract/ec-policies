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

import future.keywords.contains
import future.keywords.if

import data.lib

# METADATA
# title: Authorization does not exist
# description: |-
#   Enterprise Contract verifies if the build was authorized
# custom:
#   short_name: disallowed_no_authorization
#   failure_msg: No authorization data found
deny contains result if {
	count(data.authorization) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Authorized commit does not match
# description: |-
#   Enterprise Contract verifies if an authorized commit was used as the source of a build
# custom:
#   short_name: disallowed_commit_does_not_match
#   failure_msg: Commit %s does not match authorized commit %s
deny contains result if {
	count(data.authorization) > 0
	att := lib.pipelinerun_attestations[_]
	material := att.predicate.materials[_]
	not sha_in_auth(material.digest.sha1, data.authorization)
	result := lib.result_helper(rego.metadata.chain(), [material.digest.sha1, data.authorization[_].changeId])
}

# METADATA
# title: Authorized repo url does not match
# description: |-
#   Enterprise Contract verifies if an authorized repo url was used to build an image
# custom:
#   short_name: disallowed_repo_url_does_not_match
#   failure_msg: Repo url %s does not match authorized repo url %s
deny contains result if {
	count(data.authorization) > 0
	att := lib.pipelinerun_attestations[_]
	material := att.predicate.materials[_]
	not repo_in_auth(material.uri, data.authorization)
	result := lib.result_helper(rego.metadata.chain(), [material.uri, data.authorization[_].repoUrl])
}

sha_in_auth(changeid, authorizations) if {
	auths := authorizations[_]
	auths.changeId == changeid
}

repo_in_auth(repo, authorizations) if {
	auths := authorizations[_]
	auths.repoUrl == repo
}
