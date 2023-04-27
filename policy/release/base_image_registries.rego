#
# METADATA
# title: Base image checks
# description: >-
#   This package is responsible for verifying the base (parent) images
#   reported in the attestation are acceptable.
#
package policy.release.base_image_registries

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Base image comes from permitted registry
# description: >-
#   The base images used when building a container image must come from a known set
#   of trusted registries to reduce potential supply chain attacks. By default this
#   policy defines trusted registries as registries that are fully maintained by Red
#   Hat and only contain content produced by Red Hat. The list of permitted registries
#   can be customized by setting the `allowed_registry_prefixes` list in the rule data.
# custom:
#   short_name: base_image_permitted
#   failure_msg: Base image %q is from a disallowed registry
#   solution: >- 
#     Make sure the image used in each task comes from a trusted registry. The list of 
#     trusted registries is a configurable xref:configuration.html#_data_sources[data source].
#   collections:
#   - minimal
#
deny contains result if {
	some image_ref in _base_images
	not _image_ref_permitted(image_ref, lib.rule_data("allowed_registry_prefixes"))
	result := lib.result_helper(rego.metadata.chain(), [image_ref])
}

# METADATA
# title: Base image task result was provided
# description: >-
#   The attestation must provide the expected information about which base images
#   were used during the build process. The base image information is expected to
#   be found in a task result called `BASE_IMAGES_DIGESTS`.
# custom:
#   short_name: base_image_info_found
#   failure_msg: Base images result is missing
#   solution: >-
#     A Tekton task must exist that emits a result named 'BASE_IMAGES_DIGESTS'.
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
# title: Allowed base image registry prefixes list was provided
# description: >-
#   The policy rules in this package require the `allowed_registry_prefixes`
#   rule data to be provided.
# custom:
#   short_name: allowed_registries_provided
#   failure_msg: Missing required allowed_registry_prefixes rule data
#   solution: >-
#     Make sure to configure a list of trusted registries as a
#     xref:configuration.html#_data_sources[data source].
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
