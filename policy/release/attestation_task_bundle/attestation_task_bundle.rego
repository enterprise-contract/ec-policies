#
# METADATA
# title: Task bundle checks
# description: >-
#   To be able to reproduce and audit builds accurately it's important
#   to know exactly what happened during the build. To do this
#   Conforma requires that all tasks are defined in a set of
#   known and trusted task bundles. This package includes rules to
#   confirm that the tasks that built the image were defined in task
#   bundles, and that the task bundles used are from the list of known
#   and trusted bundles.
#
package attestation_task_bundle

import rego.v1

import data.lib
import data.lib.tekton

# METADATA
# title: Task bundle references pinned to digest
# description: >-
#   Check if the Tekton Bundle used for the Tasks in the Pipeline definition
#   is pinned to a digest.
# custom:
#   short_name: task_ref_bundles_pinned
#   failure_msg: Pipeline task '%s' uses an unpinned task bundle reference '%s'
#   solution: >-
#     Specify the task bundle reference with a full digest rather than a tag.
#   depends_on:
#   - attestation_type.known_attestation_type
#
warn contains result if {
	some task in tekton.unpinned_task_bundle(lib.tasks_from_pipelinerun)
	result := lib.result_helper(rego.metadata.chain(), [tekton.pipeline_task_name(task), tekton.bundle(task)])
}

# METADATA
# title: Task bundles are latest versions
# description: >-
#   For each Task in the SLSA Provenance attestation, check if the Tekton Bundle used is
#   the most recent.
# custom:
#   short_name: task_ref_bundles_current
#   failure_msg: Pipeline task '%s' uses an out of date task bundle '%s', new version of the
#     Task must be used before %s
#   solution: >-
#     A task bundle used is not the most recent. The most recent task bundles are defined
#     in the data source of your policy config.
#   depends_on:
#   - attestation_type.known_attestation_type
#
warn contains result if {
	some task in lib.tasks_from_pipelinerun
	expiry := tekton.expiry_of(task)
	bundle := tekton.bundle(task)
	result := lib.result_helper(rego.metadata.chain(), [tekton.pipeline_task_name(task), bundle, time.format(expiry)])
}

# METADATA
# title: Tasks defined using bundle references
# description: >-
#   Check for the existence of a task bundle. This rule will
#   fail if the task is not called from a bundle.
# custom:
#   short_name: tasks_defined_in_bundle
#   failure_msg: Pipeline task '%s' does not contain a bundle reference
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some task in tekton.disallowed_task_reference(lib.tasks_from_pipelinerun)
	result := lib.result_helper(rego.metadata.chain(), [tekton.pipeline_task_name(task)])
}

# METADATA
# title: Task bundle references not empty
# description: >-
#   Check that a valid task bundle reference is being used.
# custom:
#   short_name: task_ref_bundles_not_empty
#   failure_msg: Pipeline task '%s' uses an empty bundle image reference
#   solution: >-
#     Specify a task bundle with a reference as the full digest.
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some task in tekton.empty_task_bundle_reference(lib.tasks_from_pipelinerun)
	result := lib.result_helper(rego.metadata.chain(), [tekton.pipeline_task_name(task)])
}

# METADATA
# title: Task bundles are in trusted tasks list
# description: >-
#   For each Task in the SLSA Provenance attestation, check if the Tekton Bundle used is
#   a trusted task.
# custom:
#   short_name: task_ref_bundles_trusted
#   failure_msg: Pipeline task '%s' uses an untrusted task bundle '%s'
#   solution: >-
#     For each Task in the SLSA Provenance attestation, check if the Tekton Bundle used is
#     a trusted task.
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some task in tekton.untrusted_task_refs(lib.tasks_from_pipelinerun)
	bundle := tekton.bundle(task)
	bundle != ""
	result := lib.result_helper(rego.metadata.chain(), [tekton.pipeline_task_name(task), bundle])
}

# METADATA
# title: A trusted Tekton bundles list was provided
# description: >-
#   Confirm the `trusted_tasks` rule data was provided, since it's
#   required by the policy rules in this package.
# custom:
#   short_name: trusted_bundles_provided
#   failure_msg: Missing required trusted_tasks data
#   solution: >-
#     Create a lsit of trusted tasks. This is a list of task bundles with a top-level key
#     of 'trusted_tasks'.
#
deny contains result if {
	tekton.missing_trusted_tasks_data
	result := lib.result_helper(rego.metadata.chain(), [])
}
