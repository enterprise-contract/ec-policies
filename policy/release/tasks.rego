#
# METADATA
# description: |-
#   Enterprise Contract expects that a set of tasks were included
#   in the pipeline build for each image to be released.
#   This package includes a set of rules to verify that the expected
#   tasks ran in the pipeline when the image was built.
#   Required tasks are listed by the names given to them within the Tekton
#   Bundle image. Optionally invocation parameter of a Task can be also
#   mandated by including the name and the value in square brackets following
#   the name of the task. For example: ``name[PARAM=val]``. Only single parameter
#   is supported, to assert multiple parameters repeat the required task
#   definition for each parameter seperately.
#   The Tasks must be loaded from an acceptable Tekton Bundle.
#   See xref:release_policy.adoc#attestation_task_bundle_package[Task bundle checks].
#
package policy.release.tasks

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.tkn

# METADATA
# title: No tasks run
# description: |-
#   This policy enforces that at least one Task is present in the PipelineRun
#   attestation.
# custom:
#   short_name: tasks_missing
#   failure_msg: No tasks found in PipelineRun attestation
#   collections:
#   - minimal
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	count(tkn.tasks(att)) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Missing required task
# description: |-
#   This policy enforces that the required set of tasks are included
#   in the PipelineRun attestation.
# custom:
#   short_name: missing_required_task
#   failure_msg: Required task %q is missing
deny contains result if {
	some required_task in _missing_tasks(tkn.current_required_tasks)

	# Don't report an error if a task is required now, but not in the future
	required_task in tkn.latest_required_tasks
	result := lib.result_helper(rego.metadata.chain(), [required_task])
}

# METADATA
# title: Missing future required task
# description: |-
#   This policy warns when a task that will be required in the future
#   was not included in the PipelineRun attestation.
# custom:
#   short_name: missing_future_required_task
#   failure_msg: Task %q is missing and will be required in the future
warn contains result if {
	some required_task in _missing_tasks(tkn.latest_required_tasks)

	# If the required_task is also part of the current_required_tasks, do
	# not proceed with a warning since that's clearly a violation.
	not required_task in tkn.current_required_tasks
	result := lib.result_helper(rego.metadata.chain(), [required_task])
}

# METADATA
# title: Missing required tasks data
# description: |-
#   The policy rules in this package require the required-tasks data to be provided.
# custom:
#   short_name: missing_required_data
#   failure_msg: Missing required task-bundles data
deny contains result if {
	tkn.missing_required_tasks_data
	result := lib.result_helper(rego.metadata.chain(), [])
}

# _missing_tasks returns a set of task names that are in the given
# required_tasks, but not in the PipelineRun attestation.
_missing_tasks(required_tasks) := tasks if {
	tasks := {task |
		some att in lib.pipelinerun_attestations
		count(tkn.tasks(att)) > 0

		some task in required_tasks
		not task in tkn.tasks_names(att)
	}
}
