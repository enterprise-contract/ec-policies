#
# METADATA
# title: Builah build task
# description: |-
#   This package is responsible for verifying the buildah build task
#
package policy.release.buildah_build_task

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Dockerfile param not included
# description: |-
#   This policy verifies that there is a dockerfile parameter
# custom:
#   short_name: dockerfile_param_not_included
#   failure_msg: DOCKERFILE param is not included in the task
deny contains result if {
	not dockerfile_param
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Dockerfile param external source
# description: |-
#   This policy verifies that the dockerfile is not an external source
# custom:
#   short_name: dockerfile_param_external_source
#   failure_msg: DOCKERFILE param value (%s) is an external source
deny contains result if {
	dockerfile_param
	_not_allowed_prefix(dockerfile_param)
	result := lib.result_helper(rego.metadata.chain(), [dockerfile_param])
}

_not_allowed_prefix(search) if {
	not_allowed := ["http://", "https://"]
	startswith(search, not_allowed[_])
}

buildah_task := task if {
	some task in lib.tasks_from_pipelinerun
	task.name == "buildah"
}

dockerfile_param := param if {
	param := lib.tkn.task_param(buildah_task, "DOCKERFILE")
}
