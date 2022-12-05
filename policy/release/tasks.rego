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
import data.lib.bundles
import data.lib.refs
import data.lib.time

# METADATA
# title: No tasks run
# description: |-
#   This policy enforces that at least one Task is present in the PipelineRun
#   attestation.
# custom:
#   short_name: tasks_missing
#   failure_msg: No tasks found in PipelineRun attestation
deny contains result if {
	some att in lib.pipelinerun_attestations
	not _has_tasks(att)
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
	some required_task in _missing_tasks(_current_required_tasks)

	# Don't report an error if a task is required now, but not in the future
	required_task in _latest_required_tasks
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
	some required_task in _missing_tasks(_latest_required_tasks)

	# If the required_task is also part of the _current_required_tasks, do
	# not proceed with a warning since that's clearly a violation.
	not required_task in _current_required_tasks
	result := lib.result_helper(rego.metadata.chain(), [required_task])
}

_attested_tasks(att) = names if {
	names := {name |
		some task in att.predicate.buildConfig.tasks
		task_ref := refs.task_ref(task)
		task_ref.kind == "task"
		bundle_ref := task_ref.bundle
		bundles.is_acceptable(bundle_ref)
		some name in _task_names(task, task_ref.name)
	}
}

_has_tasks(att) = result if {
	result = count(att.predicate.buildConfig.tasks) > 0
}

_task_names(task, raw_name) = names if {
	name := split(raw_name, "[")[0] # don't allow smuggling task name with parameters
	params := {n |
		task.invocation
		v := task.invocation.parameters[k]
		n := sprintf("%s[%s=%s]", [name, k, v])
	}

	names := {name} | params
}

# The latest set of required tasks. Tasks here are not required right now
# but will be required in the future.
_latest_required_tasks contains task if {
	some task in data["required-tasks"][0].tasks
}

# The set of required tasks that are required right now.
_current_required_tasks contains task if {
	some task in time.most_current(data["required-tasks"]).tasks
}

# _missing_tasks returns a set of task names that are in the given
# required_tasks, but not in the PipelineRun attestation.
_missing_tasks(required_tasks) := tasks if {
	tasks := {task |
		some att in lib.pipelinerun_attestations
		_has_tasks(att)

		some task in required_tasks
		not task in _attested_tasks(att)
	}
}
