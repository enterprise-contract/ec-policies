#
# METADATA
# description: >-
#   Checks the CycloneDX SBOMs associated with the image being validated do not include packages
#   that have been deemed not allowed.
#   NOTE: The policy rules in this package will eventually move to the release.sbom_cyclonedx
#   package once the required ec.purl.parse rego function is widely available.
#
package policy.beta.packages

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.sbom

# METADATA
# title: Allowed
# description: >-
#   Confirm the CycloneDX SBOM contains only allowed packages. By default all packages are allowed.
#   Use the "disallowed_packages" rule data key to provide a list of disallowed packages.
# custom:
#   short_name: allowed
#   failure_msg: "Package is not allowed: %s"
#   solution: >-
#     Update the image to not use a disallowed package.
#   collections:
#   - redhat
#
deny contains result if {
	some s in sbom.cyclonedx_sboms
	some component in s.components
	_contains(component.purl, lib.rule_data("disallowed_packages"))
	result := lib.result_helper(rego.metadata.chain(), [component.purl])
}

_contains(needle, haystack) if {
	needle_purl := ec.purl.parse(needle)

	some hay in haystack
	hay_purl := ec.purl.parse(hay.purl)

	needle_purl.type == hay_purl.type
	needle_purl.namespace == hay_purl.namespace
	needle_purl.name == hay_purl.name
	_matches_version(needle_purl.version, hay)
} else := false

_matches_version(version, matcher) if {
	matcher.format in {"semverv", "semver"}
	matcher.min != ""
	matcher.max != ""
	semver.compare(_to_semver(version), _to_semver(matcher.min)) != -1
	semver.compare(_to_semver(version), _to_semver(matcher.max)) != 1
} else if {
	matcher.format in {"semverv", "semver"}
	matcher.min != ""
	object.get(matcher, "max", "") == ""
	semver.compare(_to_semver(version), _to_semver(matcher.min)) != -1
} else if {
	matcher.format in {"semverv", "semver"}
	matcher.max != ""
	object.get(matcher, "min", "") == ""
	semver.compare(_to_semver(version), _to_semver(matcher.max)) != 1
} else := false

_to_semver(v) := trim_prefix(v, "v")
