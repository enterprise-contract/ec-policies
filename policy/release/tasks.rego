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
# custom:
#   tasks_required:
#     rule_data:
#       required_task_refs:
#       - clamav-scan
#       - deprecated-image-check
#       - get-clair-scan
#       - sanity-inspect-image
#       - sanity-label-check[POLICY_NAMESPACE=required_checks]
#       - sanity-label-check[POLICY_NAMESPACE=optional_checks]
#
package policy.release.tasks

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.bundles
import data.lib.refs

# This generates all errors that can be omitted from the `tasks_required`
# rule. Since required tasks can change over time, we need this so we
# don't need to repeat the list of tasks in the test where this list of
# errors is also used. It needs to be placed here to be able to access
# the package level metadata/annotations above.
all_required_tasks contains task if {
	some link in rego.metadata.chain()
	some task in link.annotations.custom.tasks_required.rule_data.required_task_refs
}

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
# title: Required tasks not run
# description: |-
#   This policy enforces that the required set of tasks is run in a
#   PipelineRun.
# custom:
#   short_name: tasks_required
#   failure_msg: Required task(s) '%s' not found in the PipelineRun attestation
deny contains result if {
	some att in lib.pipelinerun_attestations
	_has_tasks(att)
	missing_tasks := all_required_tasks - _attested_tasks(att)
	result := lib.result_helper(rego.metadata.chain(), [concat("', '", missing_tasks)])
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
	name := split(raw_name, "[")[0] # don't allow smuggling task name with paramters
	params := {n |
		task.invocation
		v := task.invocation.parameters[k]
		n := sprintf("%s[%s=%s]", [name, k, v])
	}

	names := {name} | params
}
