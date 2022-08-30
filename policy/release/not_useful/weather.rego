# METADATA
# title: Weather related checks
# description: |-
#   This package is just for test purposes. Note that
#   it has a custom title and a descripion. Note also
#   that it is the only package so far with an extra "level"
#   in it, i.e. it's `not_useful.weather`. This is to test
#   the idea of arbitrarily deep package namespaces. And
#   later I'd like to check wildcards for that, e.g. can we
#   specify via configuration that `not_useful.*` packages
#   are included or skipped.
# custom:
#   summary: Dummy rules for snow days and heatwaves
#
package policy.release.not_useful.weather

import data.lib

# METADATA
# title: Snow day
# description: |-
#   It's expected this rule will be skipped by policy configuration.
#   This rule is for demonstration and test purposes.
# custom:
#   short_name: snow
#   failure_msg: It's snowing, no releases today
#
deny[result] {
	true
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Too hot to release
# description: |-
#   It's expected this rule will be skipped by policy configuration.
#   This rule is for demonstration and test purposes.
# custom:
#   short_name: heatwave
#   failure_msg: It's too hot, no releases today
#
deny[result] {
	true
	result := lib.result_helper(rego.metadata.chain(), [])
}
