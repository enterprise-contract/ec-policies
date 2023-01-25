#
# METADATA
# title: Base image checks
# description: |-
#   This package is responsible for verifying the base (parent) images
#   reported in the attestation are acceptable.
#
package policy.release.base_image_registries

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Restrict registry of base images
# description: |-
#   The base images used when building a container image must come from a known set
#   of trusted registries to reduce potential supply chain attacks. This policy
#   defines trusted registries as registries that are fully maintained by Red Hat
#   and only contain content produced by Red Hat.
# custom:
#   short_name: disallowed_base_image
#   failure_msg: Base image %q is from a disallowed registry
#   collections:
#   - minimal
#
deny contains result if {
	some image_ref in _base_images
	not _image_ref_permitted(image_ref, lib.rule_data("allowed_registry_prefixes"))
	result := lib.result_helper(rego.metadata.chain(), [image_ref])
}

# METADATA
# title: Base images must be provided
# description: |-
#   The attestation must provide the expected information about which base images
#   were used during the build process.
# custom:
#   short_name: base_images_missing
#   failure_msg: Base images result is missing
#   collections:
#   - minimal
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
# title: Missing rule data
# description: |-
#   The policy rules in this package require the allowed_registry_prefixes
#   rule data to be provided.
# custom:
#   short_name: missing_rule_data
#   failure_msg: Missing required allowed_registry_prefixes rule data
#   collections:
#   - minimal
#
deny contains result if {
	count(lib.rule_data("allowed_registry_prefixes")) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

_image_ref_permitted(image_ref, allowed_prefixes) if {
	startswith(image_ref, allowed_prefixes[_])
}

_base_images contains name if {
	some name in split(_base_images_results[_].value, "\n")
	count(name) > 0
}

_base_images_results contains result if {
	some result in lib.results_named(lib.build_base_images_digests_result_name)
}
