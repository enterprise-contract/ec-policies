package lib

import data.lib

test_include_defaults {
	lib.assert_equal(default_include_rules, ["*"])
	lib.assert_equal(default_include_rules, include_rules)
	lib.assert_equal(default_exclude_rules, [])
	lib.assert_equal(default_exclude_rules, exclude_rules)

	package_included("foo")
	package_included("bar")
	package_included("baz")

	not package_excluded("foo")
	not package_excluded("bar")
	not package_excluded("baz")
}

mock_config := {"policy": {
	"include_rules": ["foo", "bar"],
	"exclude_rules": ["baz"],
}}

test_include_config {
	lib.assert_equal(["foo", "bar"], include_rules) with data.config as mock_config
	lib.assert_equal(["baz"], exclude_rules) with data.config as mock_config

	package_included("foo") with data.config as mock_config
	package_included("bar") with data.config as mock_config
	package_excluded("baz") with data.config as mock_config

	not package_excluded("foo") with data.config as mock_config
	not package_excluded("bar") with data.config as mock_config
	not package_included("baz") with data.config as mock_config
}
