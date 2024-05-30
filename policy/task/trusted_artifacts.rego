#
# METADATA
# title: Trusted Artifacts Conventions
# description: >-
#   Policies to verify that a Tekton task definition conforms to the expected conventions required
#   for using Trusted Artifacts.
#
package policy.task.trusted_artifacts

import rego.v1

import data.lib
import data.lib.k8s

# METADATA
# title: Parameter
# description: Trusted Artifact parameters follow the expected naming convention.
# custom:
#   short_name: parameter
#   failure_msg: The parameter %q of the Task %q does not use the _ARTIFACT suffix
#
deny contains result if {
	some param_name in _ta_parameters
	not _has_ta_suffix(param_name)
	result := lib.result_helper(rego.metadata.chain(), [param_name, k8s.name_version(input)])
}

# METADATA
# title: Result
# description: Trusted Artifact results follow the expected naming convention.
# custom:
#   short_name: result
#   failure_msg: The result %q of the Task %q does not use the _ARTIFACT suffix
#
deny contains result if {
	some result_name in _ta_results
	not _has_ta_suffix(result_name)
	result := lib.result_helper(rego.metadata.chain(), [result_name, k8s.name_version(input)])
}

_ta_parameters contains param_name if {
	some step in input.spec.steps
	_is_ta_step(step)
	"use" in step.args
	some arg in step.args
	some arg_param in regex.find_n(`\$\(params\..*\)`, arg, -1)
	param_name := trim_prefix(trim_suffix(arg_param, ")"), "$(params.")
}

_ta_results contains result_name if {
	some step in input.spec.steps
	_is_ta_step(step)
	"create" in step.args
	some arg in step.args
	some arg_result in regex.find_n(`\$\(results\..*\.path\)`, arg, -1)
	result_name := trim_prefix(trim_suffix(arg_result, ".path)"), "$(results.")
}

_has_ta_suffix(name) if endswith(name, "_ARTIFACT")

_is_ta_step(step) if contains(step.image, "trusted-artifacts")
