#
# METADATA
# title: SBOM
# description: >-
#   Checks general properties of the SBOMs associated with the image being validated. More specific
#   rules for SPDX and CycloneDX SBOMs are in separate packages.
#
package policy.release.sbom

import rego.v1

import data.lib

# METADATA
# title: Found
# description: Confirm an SBOM attestation exists.
# custom:
#   short_name: found
#   failure_msg: No SBOM attestations found
#   solution: >-
#     Make sure the build process produces an SBOM attestation.
#   collections:
#   - minimal
#   - redhat
#
deny contains result if {
	count(_sboms) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Disallowed packages list is provided
# description: >-
#   Confirm the `disallowed_packages` and `disallowed_attributes` rule data were
#   provided, since they are required by the policy rules in this package.
# custom:
#   short_name: disallowed_packages_provided
#   failure_msg: "%s"
#   solution: >-
#     Provide a list of disallowed packages or package attributes in the
#     expected format.
#   collections:
#   - redhat
#   - policy_data
#
deny contains result if {
	some error in lib.sbom.rule_data_errors
	result := lib.result_helper(rego.metadata.chain(), [error])
}

_sboms := array.concat(lib.sbom.spdx_sboms, lib.sbom.cyclonedx_sboms)
