#
# METADATA
# title: Task bundle checks
# description: >-
#   To be able to reproduce and audit builds accurately it's important
#   to know exactly what happened during the build. To do this
#   Enterprise Contract requires that all tasks are defined in a set of
#   known and trusted task bundles. This package includes rules to
#   confirm that the tasks that built the image were defined in task
#   bundles, and that the task bundles used are from the list of known
#   and trusted bundles.
#
package policy.release.attestation_task_bundle

import future.keywords.contains
import future.keywords.if

import data.lib
import data.lib.bundles

# METADATA
# title: Tasks defined using bundle references
# description: >-
#   Check for the existence of a task bundle. This rule will
#   fail if the task is not called from a bundle.
# custom:
#   short_name: tasks_defined_in_bundle
#   failure_msg: Pipeline task '%s' does not contain a bundle reference
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	name := bundles.disallowed_task_reference(lib.tasks_from_pipelinerun)[_].name
	result := lib.result_helper(rego.metadata.chain(), [name])
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
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	name := bundles.empty_task_bundle_reference(lib.tasks_from_pipelinerun)[_].name
	result := lib.result_helper(rego.metadata.chain(), [name])
}

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
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
warn contains result if {
	task := bundles.unpinned_task_bundle(lib.tasks_from_pipelinerun)[_]
	result := lib.result_helper(rego.metadata.chain(), [task.name, bundles.bundle(task)])
}

# METADATA
# title: Task bundles are latest versions
# description: >-
#   For each Task in the SLSA Provenance attestation, check if the Tekton Bundle used is
#   the most recent xref:acceptable_bundles.adoc#_task_bundles[acceptable bundle].
# custom:
#   short_name: task_ref_bundles_current
#   failure_msg: Pipeline task '%s' uses an out of date task bundle '%s'
#   solution: >-
#     A task bundle used is not the most recent. The most recent task bundles are defined
#     as in xref:acceptable_bundles.adoc#_task_bundles[acceptable bundles] list.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
warn contains result if {
	task := bundles.out_of_date_task_bundle(lib.tasks_from_pipelinerun)[_]
	result := lib.result_helper(rego.metadata.chain(), [task.name, bundles.bundle(task)])
}

# METADATA
# title: Task bundles are in acceptable bundles list
# description: >-
#   For each Task in the SLSA Provenance attestation, check if the Tekton Bundle used is
#   an xref:acceptable_bundles.adoc#_task_bundles[acceptable bundle] given the tracked
#   effective_on date.
# custom:
#   short_name: task_ref_bundles_acceptable
#   failure_msg: Pipeline task '%s' uses an unacceptable task bundle '%s'
#   solution: >-
#     For each Task in the SLSA Provenance attestation, check if the Tekton Bundle used is
#     an xref:acceptable_bundles.adoc#_task_bundles[acceptable bundle].
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	task := bundles.unacceptable_task_bundle(lib.tasks_from_pipelinerun)[_]
	result := lib.result_helper(rego.metadata.chain(), [task.name, bundles.bundle(task)])
}

# METADATA
# title: An acceptable Tekton bundles list was provided
# description: >-
#   Confirm the `task-bundles` rule data was provided, since it's
#   required by the policy rules in this package.
# custom:
#   short_name: acceptable_bundles_provided
#   failure_msg: Missing required task-bundles data
#   solution: >-
#     Create an acceptable bundles list. This is a list of task bundles with a top-level key
#     of 'task-bundles'. More information can be found at
#     xref:acceptable_bundles.adoc#_task_bundles[acceptable bundles].
#   collections:
#   - redhat
#
deny contains result if {
	bundles.missing_task_bundles_data
	result := lib.result_helper(rego.metadata.chain(), [])
}
