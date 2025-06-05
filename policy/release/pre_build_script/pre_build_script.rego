#
# METADATA
# title: Pre-build-script task checks
# description: >-
#   This package verifies that the pre-build-script task in the
#   attestation is run in a controlled environment: it must be
#   hermetic, and running in an allowed image)
#
package pre_build_script

import rego.v1

import data.lib
import data.lib.image
import data.lib.tekton

# METADATA
# title: Script runner image comes from allowed registry
# description: >-
#   Verify that the image used to run the pre-build script come from a known
#   set of trusted registries to reduce potential supply chain attacks. By default this
#   policy defines trusted registries as registries that are fully maintained by Red
#   Hat and only contain content produced by Red Hat. The list of allowed registries
#   can be customized by setting the `allowed_registry_prefixes` list in the rule data.
# custom:
#   short_name: pre_build_script_runner_image_allowed
#   failure_msg: Pre-Build-Script runner image %q is from a disallowed registry
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
	some task in tekton.pre_build_scripts(attestation)
	image_ref := tekton.task_param(task, "SCRIPT_RUNNER_IMAGE")
	not _image_ref_permitted(image_ref)
	repo := image.parse(image_ref).repo
	result := lib.result_helper_with_term(rego.metadata.chain(), [image_ref], repo)
}

# METADATA
# title: Pre-Build-Script task called with hermetic param set
# description: >-
#   Verify the pre-build-script task (run-script-oci-ta) in the
#   PipelineRun	attestation was invoked with the proper parameters to
#   make the pre-build script execution hermetic.
# custom:
#   short_name: pre_build_script_hermetic
#   failure_msg: >-
#     Pre-Build-Script task was not invoked with
#     the hermetic parameter set: '%s'
#   solution: >-
#     Make sure that the pre-build-script task (run-script-oci-ta) has
#     a parameter named 'HERMETIC' and it's set to 'true'.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some not_hermetic_script in _hermetic_pre_build_scripts
	result := lib.result_helper(rego.metadata.chain(), [tekton.task_name(not_hermetic_script)])
}

_hermetic_pre_build_scripts contains task if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.pre_build_scripts(attestation)
	not tekton.task_is_hermetic(task)
}

_image_ref_permitted(image_ref) if {
	allowed_prefixes := lib.rule_data(_rule_data_key)
	some allowed_prefix in allowed_prefixes
	startswith(image_ref, allowed_prefix)
} else if {
	allowed_digests := {img.digest |
		some component in input.snapshot.components
		img := image.parse(component.containerImage)
	}
	image.parse(image_ref).digest in allowed_digests
}

_rule_data_key := "allowed_registry_prefixes"
