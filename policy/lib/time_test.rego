# METADATA
# custom:
#   effective_on: 2001-02-03T00:00:00Z
#   scope: package
package lib.time

import data.lib

future_timestamp := time.add_date(time.now_ns(), 0, 0, 1)

# METADATA
# custom:
#   effective_on: 2004-05-06T00:00:00Z
test_when_rule_precedence {
	when(rego.metadata.chain()) == "2004-05-06T00:00:00Z"
}

test_when_package_precedence {
	when(rego.metadata.chain()) == "2001-02-03T00:00:00Z"
}

test_effective_current_time_ns {
	lib.assert_equal(effective_current_time_ns, time.now_ns()) # with no config at all
	lib.assert_equal(effective_current_time_ns, time.now_ns()) with data.config as {} # no config.policy
	lib.assert_equal(effective_current_time_ns, time.now_ns()) with data.config.policy as {} # no config.policy.when_ns
	lib.assert_equal(effective_current_time_ns, lib.time.future_timestamp) with data.config.policy.when_ns as lib.time.future_timestamp
}
