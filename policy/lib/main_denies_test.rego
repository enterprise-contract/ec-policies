package lib

import data.lib

test_namespace {
	lib.assert_empty(namespace_denies("bogus"))
	lib.assert_not_empty(namespace_denies("release")) with data.policy as mock_policies

	lib.assert_empty(namespace_warns("bogus"))
	lib.assert_not_empty(namespace_warns("release")) with data.policy as mock_policies
}

mock_policies := {"release": {"mock_package": {
	"deny": {{"code": "test_failure"}},
	"warn": {{"code": "test_warning"}},
}}}
