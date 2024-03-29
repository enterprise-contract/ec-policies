#
# METADATA
# title: Base image checks
# description: >-
#   This package is responsible for verifying the base (parent) images
#   reported in the attestation are allowed.
#
package policy.release.base_image_registries

import rego.v1

import data.lib

# METADATA
# title: Base image comes from permitted registry
# description: >-
#   Verify that the base images used when building a container image come from a known
#   set of trusted registries to reduce potential supply chain attacks. By default this
#   policy defines trusted registries as registries that are fully maintained by Red
#   Hat and only contain content produced by Red Hat. The list of permitted registries
#   can be customized by setting the `allowed_registry_prefixes` list in the rule data.
# custom:
#   short_name: base_image_permitted
#   failure_msg: Base image %q is from a disallowed registry
#   solution: >-
#     Make sure the image used in each task comes from a trusted registry. The list of
#     trusted registries is a configurable xref:ec-cli:ROOT:configuration.adoc#_data_sources[data source].
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - base_image_registries.base_image_info_found
#   - base_image_registries.allowed_registries_provided
#
deny contains result if {
	some image_ref in _base_images
	not _image_ref_permitted(image_ref, lib.rule_data(_rule_data_key))
	result := lib.result_helper(rego.metadata.chain(), [image_ref])
}

# METADATA
# title: Base image task result was provided
# description: >-
#   Verify the attestation provides the expected information about which base images
#   were used during the build process. The base image information is expected to
#   be found in a task result called BASE_IMAGES_DIGESTS.
# custom:
#   short_name: base_image_info_found
#   failure_msg: Base images result is missing
#   solution: >-
#     A Tekton task must exist that emits a result named BASE_IMAGES_DIGESTS.
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	count(lib.pipelinerun_attestations) > 0

	# Some images are built "from scratch" and do not have any base images, e.g. UBI.
	# The missing check verifies that no results exists, not that no base
	# images were used.
	count(_base_images_results) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Allowed base image registry prefixes list was provided
# description: >-
#   Confirm the `allowed_registry_prefixes` rule data was provided, since it's
#   required by the policy rules in this package.
# custom:
#   short_name: allowed_registries_provided
#   failure_msg: "%s"
#   solution: >-
#     Make sure to configure a list of trusted registries as a
#     xref:ec-cli:ROOT:configuration.adoc#_data_sources[data source].
#   collections:
#   - minimal
#   - redhat
#   - policy_data
#
deny contains result if {
	some error in _rule_data_errors
	result := lib.result_helper(rego.metadata.chain(), [error])
}

_image_ref_permitted(image_ref, allowed_prefixes) if {
	some allowed_prefix in allowed_prefixes
	startswith(image_ref, allowed_prefix)
}

_base_images contains name if {
	some _, image in _base_images_results
	some name in split(image.value, "\n")
	count(name) > 0
}

_base_images_results contains result if {
	some result in lib.results_named(lib.build_base_images_digests_result_name)
}

# Verify allowed_registry_prefixes is a non-empty list of strings
_rule_data_errors contains msg if {
	# match_schema expects either a marshaled JSON resource (String) or an Object. It doesn't
	# handle an Array directly.
	value := json.marshal(lib.rule_data(_rule_data_key))
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
			"minItems": 1,
		},
	)[1]
	msg := sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, violation.error])
}

_rule_data_key := "allowed_registry_prefixes"
