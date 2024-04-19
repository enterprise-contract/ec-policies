#
# METADATA
# title: Base image checks
# description: >-
#   This package is responsible for verifying the base (parent) images
#   reported in the SLSA Provenace or the SBOM are allowed.
#
package policy.release.base_image_registries

import rego.v1

import data.lib
import data.lib.sbom

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
# title: Base images provided
# description: >-
#   Verify the expected information was provided about which base images were used during
#   the build process.The list of base images is a combination of two sources. One is
#   extracted from the SLSA Provenance in the form of Tekton Task result called
#   BASE_IMAGES_DIGESTS. The other comes from the components in the `formulation` attribute
#   of any associated CycloneDX SBOMs.
# custom:
#   short_name: base_image_info_found
#   failure_msg: Base images information is missing
#   solution: >-
#     Either a Tekton task must exist that emits a result named BASE_IMAGES_DIGESTS, or a
#     CycloneDX SBOM must be associated with the image.
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	# Some images are built "from scratch" and not have any base images, e.g. UBI.
	# This check distinguishes such images by simply ensuring that either the expected
	# Task result exists regardless of its value, or at least one SBOM is attached to
	# the image.
	count(lib.results_named(lib.build_base_images_digests_result_name)) == 0
	count(sbom.cyclonedx_sboms) == 0

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
	some _, image in lib.results_named(lib.build_base_images_digests_result_name)
	some name in split(image.value, "\n")
	name != ""
}

_base_images contains base_image if {
	some s in sbom.cyclonedx_sboms
	some formulation in s.formulation
	some component in formulation.components
	component.type == "container"
	_is_base_image(component)
	base_image := component.name
}

_is_base_image(component) if {
	base_image_properties := [property |
		some property in component.properties
		_is_base_image_property(property)
	]
	count(base_image_properties) > 0
}

_is_base_image_property(property) if {
	property.name == "konflux:container:is_base_image"
	value := property.value
	json.is_valid(value)
	json.unmarshal(value) == true
}

_is_base_image_property(property) if {
	property.name == "konflux:container:is_builder_image:for_stage"
	value := property.value
	json.is_valid(value)
	type_name(json.unmarshal(value)) == "number"
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
