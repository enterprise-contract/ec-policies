package policy.release.redhat_manifests

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

test_success if {
	lib.assert_empty(deny) with input.image.files as {_sbom_purl_path: {}, _sbom_cyclonedx_path: {}}
}

test_missing_manifests if {
	cyclonedx_violation := {
		"code": "redhat_manifests.redhat_manifests_missing",
		"msg": sprintf("Missing Red Hat manifest \"%s\"", [_sbom_cyclonedx_path]),
		"term": _sbom_cyclonedx_path,
	}
	purl_violation := {
		"code": "redhat_manifests.redhat_manifests_missing",
		"msg": sprintf("Missing Red Hat manifest \"%s\"", [_sbom_purl_path]),
		"term": _sbom_purl_path,
	}

	lib.assert_equal_results({cyclonedx_violation, purl_violation}, deny) with input.image as {}
	lib.assert_equal_results({purl_violation}, deny) with input.image.files as {
		_sbom_cyclonedx_path: {},
		"something/else": {},
	}
	lib.assert_equal_results({cyclonedx_violation}, deny) with input.image.files as {
		_sbom_purl_path: {},
		"something/else": {},
	}
}
