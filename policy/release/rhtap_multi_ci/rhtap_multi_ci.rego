#
# METADATA
# title: RHTAP Multi-CI
# description: >-
#   Checks for images built using an RHTAP build pipeline in either Jenkins,
#   GitLab or GitHub. RHTAP pipelines are defined under
#   https://github.com/redhat-appstudio/tssc-sample-templates/tree/main/skeleton/ci
#
package rhtap_multi_ci

import rego.v1

import data.lib

# METADATA
# title: SLSA Provenance Attestation Found
# description: >-
#   Verify an attestation created by the RHTAP Multi-CI build pipeline is present.
# custom:
#   short_name: attestation_found
#   failure_msg: "A SLSA v1.0 provenance with one of the following RHTAP Multi-CI
#     build types was not found: %s."
#   solution: >-
#     It appears the build pipeline did not create the expected SLSA provenance
#     attestation. Check for relevant error messages in the 'cosign-sign-attest'
#     pipeline step logs.
#   collections:
#   - rhtap-multi-ci
#   # For compatibility. These will be removed these soon.
#   - rhtap-github
#   - rhtap-gitlab
#   - rhtap-jenkins
#
deny contains result if {
	count(_attestations) < 1
	result := lib.result_helper(rego.metadata.chain(), [lib.quoted_values_string(_known_build_types)])
}

# -----------------------------------------------------------------------------

_known_build_types := [_build_type(known_ci_type) | some known_ci_type in _known_ci_types]

_build_type(ci_type) := sprintf("https://redhat.com/rhtap/slsa-build-types/%s-build/v1", [ci_type])

# RHTAP Multi-CI currently supports these environments:
_known_ci_types := ["jenkins", "github", "gitlab"]

# Just the potentially relevant attestations
_attestations := [att |
	some att in _all_attestations

	# Beware we are not supporting SLSA formats other than v1.0 here
	att.statement.predicateType == _slsa_provenance_predicate_type_v1

	# Just the RHTAP Multi-CI build types
	some known_build_type in _known_build_types
	att.statement.predicate.buildDefinition.buildType == known_build_type
]

# Standard predicate type for SLSA V1.0
_slsa_provenance_predicate_type_v1 := "https://slsa.dev/provenance/v1"

# The actual raw attestation is found under the 'statement' key.
# See https://enterprisecontract.dev/docs/ec-cli/policy_input.html#_validate_image
_all_attestations := input.attestations
