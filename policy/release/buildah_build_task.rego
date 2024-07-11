#
# METADATA
# title: Buildah build task
# description: >-
#   This package is responsible for verifying the buildah build task
#
package policy.release.buildah_build_task

import rego.v1

import data.lib
import data.lib.tkn

# METADATA
# title: Buildah task uses a local Dockerfile
# description: >-
#   Verify the Dockerfile used in the buildah task was not
#   fetched from an external source.
# custom:
#   short_name: buildah_uses_local_dockerfile
#   failure_msg: DOCKERFILE param value (%s) is an external source
#   solution: >-
#     Make sure the 'DOCKERFILE' parameter does not come from an external source.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some dockerfile_param in _dockerfile_params
	_not_allowed_prefix(dockerfile_param)
	result := lib.result_helper(rego.metadata.chain(), [dockerfile_param])
}

_not_allowed_prefix(search) if {
	not_allowed_prefixes := ["http://", "https://"]
	some not_allowed_prefix in not_allowed_prefixes
	startswith(search, not_allowed_prefix)
}

_buildah_tasks contains task if {
	some att in lib.pipelinerun_attestations
	some task in tkn.build_tasks(att)
}

_dockerfile_params contains param if {
	some buildah_task in _buildah_tasks
	param := lib.tkn.task_param(buildah_task, "DOCKERFILE")
}
