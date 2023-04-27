#
# METADATA
# title: Buildah build task
# description: >-
#   This package is responsible for verifying the buildah build task
#
package policy.release.buildah_build_task

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Buildah task has Dockerfile param defined
# description: >-
#   This policy verifies that a DOCKERFILE parameter was provided to
#   the buildah task.
# custom:
#   short_name: buildah_task_has_dockerfile_param
#   failure_msg: The DOCKERFILE param was not included in the buildah task
#   solution: >-
#     Make sure the buildah task has a parameter named 'DOCKERFILE'.
deny contains result if {
	# Skip this rule if the buildah task is not present
	buildah_task
	not dockerfile_param
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Buildah task uses a local Dockerfile
# description: >-
#   This policy verifies that the Dockerfile used in the buildah task is not
#   fetched from an external source
# custom:
#   short_name: buildah_uses_local_dockerfile
#   failure_msg: DOCKERFILE param value (%s) is an external source
#   solution: >-
#     Make sure the 'DOCKERFILE' parameter does not come from an external source.
deny contains result if {
	_not_allowed_prefix(dockerfile_param)
	result := lib.result_helper(rego.metadata.chain(), [dockerfile_param])
}

_not_allowed_prefix(search) if {
	not_allowed := ["http://", "https://"]
	startswith(search, not_allowed[_])
}

buildah_task := task if {
	some att in lib.pipelinerun_attestations
	some task in lib.tkn.tasks(att)
	"buildah" in lib.tkn.task_names(task)
}

dockerfile_param := param if {
	param := lib.tkn.task_param(buildah_task, "DOCKERFILE")
}
