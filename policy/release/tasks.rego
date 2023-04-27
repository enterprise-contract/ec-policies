#
# METADATA
# description: >-
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
#
package policy.release.tasks

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.tkn

# METADATA
# title: Pipeline run includes at least one task
# description: >-
#   This policy enforces that at least one Task is present in the PipelineRun
#   attestation.
# custom:
#   short_name: pipeline_has_tasks
#   failure_msg: No tasks found in PipelineRun attestation
#   solution: >- 
#     Make sure the build pipeline ran any tasks and that the build system is
#     generating a proper attestation.
#   collections:
#   - minimal
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	count(tkn.tasks(att)) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: All required tasks were included in the pipeline
# description: >-
#   This policy enforces that the required set of tasks are included
#   in the PipelineRun attestation.
# custom:
#   short_name: required_tasks_found
#   failure_msg: Required task %q is missing
#   solution: >-
#     Make sure all required tasks are in the build pipeline. The required task list
#     is contained as xref:configuration.html#_data_sources[data] under the key 'required-tasks'.
deny contains result if {
	some required_task in _missing_tasks(current_required_tasks)

	# Don't report an error if a task is required now, but not in the future
	required_task in latest_required_tasks
	result := lib.result_helper_with_term(rego.metadata.chain(), [required_task], required_task)
}

# METADATA
# title: Required tasks list for pipeline was provided
# description: >-
#   This policy warns if a task list does not exist in the required_tasks.yaml file
# custom:
#   short_name: pipeline_required_tasks_list_provided
#   failure_msg: Required tasks do not exist for pipeline
#   solution: >-
#     The required task list is contained as xref:configuration.html#_data_sources[data] 
#     under the key 'required-tasks'. Make sure this list exists.
warn contains result if {
	not required_pipeline_task_data
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Future required tasks were found
# description: >-
#   This policy warns when a task that will be required in the future
#   was not included in the PipelineRun attestation.
# custom:
#   short_name: future_required_tasks_found
#   failure_msg: Task %q is missing and will be required in the future
#   solution: >-
#     There is a task that will be required at a future date that is missing
#     from the build pipeline.
warn contains result if {
	some required_task in _missing_tasks(latest_required_tasks)

	# If the required_task is also part of the current_required_tasks, do
	# not proceed with a warning since that's clearly a violation.
	not required_task in current_required_tasks
	result := lib.result_helper_with_term(rego.metadata.chain(), [required_task], required_task)
}

# METADATA
# title: Required tasks list was provided
# description: >-
#   The policy rules in this package require the required-tasks data to be provided.
# custom:
#   short_name: required_tasks_list_provided
#   failure_msg: Missing required task-bundles data
#   solution: >-
#     Make sure the xref:configuration.html#_data_sources[data sources] contains a key
#     'required-tasks' that contains a list of tasks that are required to run in the
#     build pipeline.
deny contains result if {
	tkn.missing_required_tasks_data
	not required_pipeline_task_data
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

# get the future tasks that are pipeline specific. If none exists
# get the default list
latest_required_tasks := task_data if {
	some att in lib.pipelinerun_attestations
	count(tkn.tasks(att)) > 0
	task_data := tkn.latest_required_pipeline_tasks(att)
} else := task_data if {
	task_data := tkn.latest_required_default_tasks
}

# get current required tasks. fall back to the default list if
# no label exists in the attestation
current_required_tasks := task_data if {
	some att in lib.pipelinerun_attestations
	count(tkn.tasks(att)) > 0
	task_data := tkn.current_required_pipeline_tasks(att)
} else := task_data if {
	task_data := tkn.current_required_default_tasks
}

## get the required task data for a pipeline with a label
required_pipeline_task_data := task_data if {
	some att in lib.pipelinerun_attestations
	count(tkn.tasks(att)) > 0
	task_data := tkn.required_task_list(att)
}
