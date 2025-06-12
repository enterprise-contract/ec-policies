#
# METADATA
# title: Pre-build-script task checks
# description: >-
#   This package verifies that the pre-build-script tasks in the
#   attestation are executed in a controlled environment
#
package pre_build_script_task

import rego.v1

import data.lib
import data.lib.image
import data.lib.tekton

# METADATA
# title: Script runner image comes from allowed registry
# description: >-
#   Verify that the images used to run the pre-build script tasks come from a known
#   set of trusted registries to reduce potential supply chain attacks. By default this
#   policy defines trusted registries as registries that are fully maintained by Red
#   Hat and only contain content produced by Red Hat. The list of allowed registries
#   can be customized by setting the `allowed_registry_prefixes` list in the rule data.
# custom:
#   short_name: pre_build_script_task_runner_image_allowed
#   failure_msg: Pre-Build-Script task runner image %q is from a disallowed registry
#   solution: >-
#     Make sure the image referenced in the parameter 'SCRIPT_RUNNER_IMAGE' comes from
#     a trusted registry. The list of trusted registries is a configurable
#     xref:ec-cli:ROOT:configuration.adoc#_data_sources[data source].
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#   - base_image_registries.allowed_registries_provided
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.pre_build_tasks(attestation)
	image_ref := tekton.task_param(task, _pre_build_script_runner_image_param)
	not _image_ref_permitted(image_ref)
	repo := image.parse(image_ref).repo
	result := lib.result_helper_with_term(rego.metadata.chain(), [image_ref], repo)
}

_pre_build_script_runner_image_param := "SCRIPT_RUNNER_IMAGE"

_image_ref_permitted(image_ref) if {
	allowed_prefixes := lib.rule_data(_rule_data_allowed_registries_key)
	some allowed_prefix in allowed_prefixes
	startswith(image_ref, allowed_prefix)
}

_rule_data_allowed_registries_key := "allowed_registry_prefixes"
