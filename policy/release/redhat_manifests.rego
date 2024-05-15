#
# METADATA
# title: Red Hat manifests
# description: >-
#   Red Hat images are expected to include certain manifest files. This package
#   verifies this requirement is met.
#
package policy.release.redhat_manifests

import rego.v1

import data.lib

# METADATA
# title: Missing Red Hat manifests
# description: Verify the expected Red Hat manifests are available in the image.
# custom:
#   short_name: redhat_manifests_missing
#   failure_msg: "Missing Red Hat manifest %q"
#   collections:
#   - redhat
#
deny contains result if {
	wanted := {_sbom_purl_path}
	found := {name | some name, content in input.image.files}
	some missing in (wanted - found)
	result := lib.result_helper_with_term(rego.metadata.chain(), [missing], missing)
}

_sbom_purl_path := "root/buildinfo/content_manifests/sbom-purl.json"
