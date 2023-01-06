package release.main

import data.lib

test_passing {
	lib.assert_empty(deny | warn) with data.config.policy.exclude as ["mock_package"]
		with data.policy as {"release": {"mock_package": {}}}
}

test_deny {
	lib.assert_equal(deny, {{"code": "test_failure"}}) with data.policy as _non_passing
}

test_warn {
	lib.assert_equal(warn, {{"code": "test_warning"}}) with data.policy as _non_passing
}

_non_passing := {"release": {"mock_package": {
	"deny": {{"code": "test_failure"}},
	"warn": {{"code": "test_warning"}},
}}}
