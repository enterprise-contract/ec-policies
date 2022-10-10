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
#       - add-sbom-and-push
#       - clamav-scan
#       - deprecated-image-check
#       - get-clair-scan
#       - sanity-inspect-image
#       - sanity-label-check[POLICY_NAMESPACE=required_checks]
#       - sanity-label-check[POLICY_NAMESPACE=optional_checks]
#       - sast-go
#
package policy.release.tasks

import data.lib
import data.lib.bundles
import data.lib.refs
import future.keywords.in

# This generates all errors that can be omitted from the `tasks_required`
# rule. Since required tasks can change over time, we need this so we
# don't need to repeat the list of tasks in the test where this list of
# errors is also used. It needs to be placed here to be able to access
# the package level metadata/annotations above.
all_required_tasks := {t | t := rego.metadata.chain()[_].annotations.custom.tasks_required.rule_data.required_task_refs[_]}

# METADATA
# title: No tasks run
# description: |-
#   This policy enforces that at least one Task is present in the PipelineRun
#   attestation.
# custom:
#   short_name: tasks_missing
#   failure_msg: No tasks found in PipelineRun attestation
deny[result] {
	att := lib.pipelinerun_attestations[_]

	count(att.predicate.buildConfig.tasks) == 0

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
deny[result] {
	att := lib.pipelinerun_attestations[_]

	# reported by tasks_missing above
	count(att.predicate.buildConfig.tasks) > 0

	# collects names of tasks that are present in the attestation
	attested_tasks := {t |
		task := att.predicate.buildConfig.tasks[_]
		task_ref := refs.task_ref(task)
		task_ref.kind == "task"
		bundle_ref := task_ref.bundle
		bundles.is_acceptable(bundle_ref)
		t := _task_names(task, task_ref.name)[_]
	}

	# if all attested_tasks equal all_required_tasks this set is empty,
	# otherwise it contains the tasks that are required but are not
	# present in the attestation
	all_missing := all_required_tasks - attested_tasks

	result := lib.result_helper(rego.metadata.chain(), [concat("', '", all_missing)])
}

_task_names(task, raw_name) = names {
	name := split(raw_name, "[")[0] # don't allow smuggling task name with paramters
	params := {n |
		task.invocation
		v := task.invocation.parameters[k]
		n := sprintf("%s[%s=%s]", [name, k, v])
	}

	names := {name} | params
}
