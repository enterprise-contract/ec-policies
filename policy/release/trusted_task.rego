#
# METADATA
# title: Trusted Task checks
# description: >-
#   This package is used to verify all the Tekton Tasks involved in building the image are trusted.
#   Trust is established by comparing the Task references found in the SLSA Provenance with the
#   pre-defined list of trusted Tasks. The list is customized via the `trusted_tasks` rule data key.
#
package policy.release.trusted_task

import rego.v1

import data.lib
import data.lib.refs
import data.lib.tkn

# METADATA
# title: Pinned
# description: >-
#   Check if all Tekton Tasks use a Task definition by a pinned reference. When using the git
#   resolver, a commit ID is expected for the revision parameter. When using the bundles resolver,
#   the bundle parameter is expected to include an image reference with a digest.
# custom:
#   short_name: pinned
#   failure_msg: Pipeline task %q uses an unpinned task reference, %s
#   solution: >-
#     Update the Pipeline definition so that all Task references have a pinned value as mentioned
#     in the description.
#   collections:
#   - redhat
#   effective_on: 2024-05-07T00:00:00Z
#
warn contains result if {
	some task in tkn.unpinned_task_references(lib.tasks_from_pipelinerun)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[tkn.pipeline_task_name(task), _task_info(task)],
		tkn.task_name(task),
	)
}

# METADATA
# title: Current
# description: >-
#   Check if all Tekton Tasks use the latest known Task reference.
# custom:
#   short_name: current
#   failure_msg: Pipeline task %q uses an out of date task reference, %s
#   solution: >-
#     Update the Task reference to a newer version.
#   collections:
#   - redhat
#   effective_on: 2024-05-07T00:00:00Z
#
warn contains result if {
	some task in tkn.out_of_date_task_refs(lib.tasks_from_pipelinerun)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[tkn.pipeline_task_name(task), _task_info(task)],
		tkn.task_name(task),
	)
}

# METADATA
# title: Trusted
# description: >-
#   Check if all Tekton Tasks use a trusted Task reference.
# custom:
#   short_name: trusted
#   failure_msg: Pipeline task %q uses an untrusted task reference, %s
#   solution: >-
#     For each Task in the SLSA Provenance attestation, check if the Tekton Bundle used is
#     a trusted task.
#   collections:
#   - redhat
#   effective_on: 2024-05-07T00:00:00Z
#
deny contains result if {
	some task in tkn.untrusted_task_refs(lib.tasks_from_pipelinerun)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[tkn.pipeline_task_name(task), _task_info(task)],
		tkn.task_name(task),
	)
}

# METADATA
# title: Data
# description: >-
#   Confirm the `trusted_tasks` rule data was provided, since it's required by the policy rules in
#   this package.
# custom:
#   short_name: data
#   failure_msg: Missing required trusted_tasks data
#   solution: >-
#     Create a, or use an existing, trusted tasks list as a data source.
#   collections:
#   - redhat
#   effective_on: 2024-05-07T00:00:00Z
#
deny contains result if {
	tkn.missing_trusted_tasks_data
	result := lib.result_helper(rego.metadata.chain(), [])
}

_task_info(task) := info if {
	ref := refs.task_ref(task)
	info := sprintf("%s@%s", [object.get(ref, "key", ""), object.get(ref, "pinned_ref", "")])
}
