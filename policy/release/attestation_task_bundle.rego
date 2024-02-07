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

import rego.v1

import data.lib
import data.lib.bundles
import data.lib.image
import data.lib.refs
import data.lib.tkn

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
	some task in bundles.disallowed_task_reference(lib.tasks_from_pipelinerun)
	result := lib.result_helper(rego.metadata.chain(), [tkn.pipeline_task_name(task)])
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
	some task in bundles.empty_task_bundle_reference(lib.tasks_from_pipelinerun)
	result := lib.result_helper(rego.metadata.chain(), [tkn.pipeline_task_name(task)])
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
	some task in bundles.unpinned_task_bundle(lib.tasks_from_pipelinerun)
	result := lib.result_helper(rego.metadata.chain(), [tkn.pipeline_task_name(task), bundles.bundle(task)])
}

# METADATA
# title: Acceptable
# description: TODO
# custom:
#   short_name: acceptable
#   failure_msg: Pipeline task '%s' uses an unacceptable task bundle '%s'
#   solution: TODO
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some task in lib.tasks_from_pipelinerun
	some record in _records_for_task(task)

	# TODO: This can probably handle the task_ref_bundles_not_empty and tasks_defined_in_bundle. Further
	# testing needed.

	# If a record doesn't include an expiration date, it's always ok to use it.
	record.expires_on != ""
	result := _with_effective_on(
		lib.result_helper(rego.metadata.chain(), [tkn.pipeline_task_name(task), bundles.bundle(task)]),
		record.expires_on,
	)
}

_records_for_task(task) := records if {
	ref := image.parse(refs.task_ref(task).bundle)
	records := [record |
		some record in data["task-bundles"][ref.repo]
		record.tag == ref.tag
		record.digest == ref.digest
	]
	count(records) > 0
} else := [{"expires_on": _missing_record}]

# TODO: This has a slightly different implementation than the one from the labels package. Good
# enough for a POC but we should try to avoid such things.
_with_effective_on(result, effective_on) := new_result if {
	# A missing record is treated differently. It is a violation now regardless of the effective
	# time.
	effective_on != _missing_record
	new_result := json.patch(result, [{"op": "add", "path": "/effective_on", "value": effective_on}])
} else := result

# Symbol to specify a record for a given bundle was not found.
# TODO: Maybe there's a nicer way to handle this, but this doesn't seem too bad.
_missing_record := "MISSING-RECORD"

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
