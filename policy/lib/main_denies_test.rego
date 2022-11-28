package lib

import data.lib

test_namespace {
	lib.assert_empty(namespace_denies("bogus"))
	lib.assert_not_empty(namespace_denies("release")) with data.policy as mock_policies

	lib.assert_empty(namespace_warns("bogus"))
	lib.assert_not_empty(namespace_warns("release")) with data.policy as mock_policies
}

test_include_exclude {
	# Rules excluded by wildcard
	lib.assert_empty(namespace_denies("release")) with data.config.policy.exclude as ["*"]
		with data.policy as mock_policies

	# Rules excluded by name
	lib.assert_empty(namespace_denies("release")) with data.config.policy.exclude as ["mock_package"]
		with data.policy as mock_policies

	# Rules included by name
	lib.assert_equal(1, count(namespace_denies("release"))) with data.config.policy.include as ["mock_package"]
		with data.policy as mock_policies

	# Rules excluded by wildcard
	lib.assert_empty(namespace_warns("release")) with data.config.policy.exclude as ["*"]
		with data.policy as mock_policies

	# Rules excluded by name
	lib.assert_empty(namespace_warns("release")) with data.config.policy.exclude as ["mock_package"]
		with data.policy as mock_policies

	# Rules included by name
	lib.assert_equal(1, count(namespace_warns("release"))) with data.config.policy.include as ["mock_package"]
		with data.policy as mock_policies
}

mock_policies := {"release": {"mock_package": {
	"deny": {{"code": "test_failure"}},
	"warn": {{"code": "test_warning"}},
}}}
