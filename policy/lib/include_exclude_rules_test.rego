package lib

import data.lib

test_include_defaults {
	lib.assert_equal(include_rules, {"*"})
	lib.assert_equal(exclude_rules, set())

	lib.assert_equal(include_rules, {"zip"}) with data.rule_collections as {"default": {"include": ["zip"]}}
	lib.assert_equal(exclude_rules, {"zap"}) with data.rule_collections as {"default": {"exclude": ["zap"]}}

	rule_included("foo", "whatever_code")
}

test_include_config {
	mock_config := {"policy": {
		"include_rules": {"foo"},
		"exclude_rules": {"bar"},
	}}

	lib.assert_equal({"foo"}, include_rules) with data.config as mock_config
	lib.assert_equal({"bar"}, exclude_rules) with data.config as mock_config

	rule_included("foo", "whatever_code") with data.config as mock_config
	not rule_included("bar", "whatever_code") with data.config as mock_config
}

test_include_by_specifying_collection {
	mock_config_with_collection := {"policy": {"collection": "set1"}}

	mock_rule_collections := {"set1": {"include": ["foo"], "exclude": ["bar"]}}

	lib.assert_equal({"foo"}, include_rules) with data.config as mock_config_with_collection with data.rule_collections as mock_rule_collections
	lib.assert_equal({"bar"}, exclude_rules) with data.config as mock_config_with_collection with data.rule_collections as mock_rule_collections

	rule_included("foo", "whatever_code") with data.config as mock_config_with_collection with data.rule_collections as mock_rule_collections
	not rule_included("bar", "whatever_code") with data.config as mock_config_with_collection with data.rule_collections as mock_rule_collections
}

test_include_fully_qualified_rules {
	mock_config_to_include := {"policy": {
		"exclude_rules": ["*"],
		"include_rules": ["foo.particular_code"],
	}}

	rule_included("foo", "particular_code") with data.config as mock_config_to_include
	not rule_included("foo", "another_code") with data.config as mock_config_to_include
	not rule_included("bar", "whatever_code") with data.config as mock_config_to_include

	mock_config_to_exclude := {"policy": {
		"include_rules": ["*"],
		"exclude_rules": ["foo.particular_code"],
	}}

	not rule_included("foo", "particular_code") with data.config as mock_config_to_exclude
	rule_included("foo", "another_code") with data.config as mock_config_to_exclude
	rule_included("bar", "whatever_code") with data.config as mock_config_to_exclude
}
