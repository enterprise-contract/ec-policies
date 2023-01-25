#
# METADATA
# title: Task bundle checks
# description: |-
#   To be able to reproduce and audit builds accurately it's important
#   to know exactly what happened during the build. To do this
#   Enterprise Contract requires that all tasks are defined in a set of
#   known and trusted task bundles. This package includes rules to
#   confirm that the tasks that built the image were defined in task
#   bundles, and that the task bundles used are from the list of known
#   and trusted bundles.
#
package policy.release.attestation_task_bundle

import data.lib
import data.lib.bundles

# METADATA
# title: Task bundle was not used or is not defined
# description: |-
#   Check for existence of a task bundle. Enforcing this rule will
#   fail the contract if the task is not called from a bundle.
# custom:
#   short_name: disallowed_task_reference
#   failure_msg: Pipeline task '%s' does not contain a bundle reference
#   collections:
#   - minimal
#
deny[result] {
	name := bundles.disallowed_task_reference(lib.tasks_from_pipelinerun)[_].name
	result := lib.result_helper(rego.metadata.chain(), [name])
}

# METADATA
# title: Task bundle reference is empty
# description: |-
#   Check for a valid task bundle reference being used.
# custom:
#   short_name: empty_task_bundle_reference
#   failure_msg: Pipeline task '%s' uses an empty bundle image reference
#   collections:
#   - minimal
#
deny[result] {
	name := bundles.empty_task_bundle_reference(lib.tasks_from_pipelinerun)[_].name
	result := lib.result_helper(rego.metadata.chain(), [name])
}

# METADATA
# title: Unpinned task bundle reference
# description: |-
#   Check if the Tekton Bundle used for the Tasks in the Pipeline definition
#   is pinned to a digest.
# custom:
#   short_name: unpinned_task_bundle
#   failure_msg: Pipeline task '%s' uses an unpinned task bundle reference '%s'
#
warn[result] {
	task := bundles.unpinned_task_bundle(lib.tasks_from_pipelinerun)[_]
	result := lib.result_helper(rego.metadata.chain(), [task.name, bundles.bundle(task)])
}

# METADATA
# title: Task bundle is out of date
# description: |-
#   Check if the Tekton Bundle used for the Tasks in the attestation
#   is the most recent acceptable one. See the list of acceptable
#   task bundles at xref:acceptable_bundles.adoc#_task_bundles[Acceptable Bundles] or look at
#   xref:attachment$acceptable_tekton_bundles.yml[data/acceptable_tekton_bundles.yml]
#   in this git repository. The meaning of an acceptable bundle is explained in
#   xref:acceptable_bundles.adoc#_task_bundles[Acceptable Bundles]
# custom:
#   short_name: out_of_date_task_bundle
#   failure_msg: Pipeline task '%s' uses an out of date task bundle '%s'
#
warn[result] {
	task := bundles.out_of_date_task_bundle(lib.tasks_from_pipelinerun)[_]
	result := lib.result_helper(rego.metadata.chain(), [task.name, bundles.bundle(task)])
}

# METADATA
# title: Task bundle is not acceptable
# description: |-
#   Check if the Tekton Bundle used for the Tasks in the attestation
#   are acceptable given the tracked effective_on date. See the list of acceptable
#   task bundles at xref:acceptable_bundles.adoc#_task_bundles[Acceptable Bundles] or look at
#   xref:attachment$acceptable_tekton_bundles.yml[data/acceptable_tekton_bundles.yml]
#   in this git repository. The meaning of an acceptable bundle is explained in
#   xref:acceptable_bundles.adoc#_task_bundles[Acceptable Bundles]
# custom:
#   short_name: unacceptable_task_bundle
#   failure_msg: Pipeline task '%s' uses an unacceptable task bundle '%s'
#
deny[result] {
	task := bundles.unacceptable_task_bundle(lib.tasks_from_pipelinerun)[_]
	result := lib.result_helper(rego.metadata.chain(), [task.name, bundles.bundle(task)])
}

# METADATA
# title: Missing required data
# description: |-
#   The policy rules in this package require the task-bundles data to be provided.
# custom:
#   short_name: missing_required_data
#   failure_msg: Missing required task-bundles data
deny[result] {
	bundles.missing_task_bundles_data
	result := lib.result_helper(rego.metadata.chain(), [])
}
