package policy.release.redhat_manifests_test

import rego.v1

import data.lib
import data.policy.release.redhat_manifests

test_success if {
	lib.assert_empty(redhat_manifests.deny) with input.image.files as {redhat_manifests._sbom_purl_path: {}}
}

test_missing_manifests if {
	purl_violation := {
		"code": "redhat_manifests.redhat_manifests_missing",
		"msg": sprintf("Missing Red Hat manifest \"%s\"", [redhat_manifests._sbom_purl_path]),
		"term": redhat_manifests._sbom_purl_path,
	}

	lib.assert_equal_results({purl_violation}, redhat_manifests.deny) with input.image as {}
	lib.assert_equal_results({purl_violation}, redhat_manifests.deny) with input.image.files as {"something/else": {}}
}
