package lib

import data.lib

test_include_defaults {
	lib.assert_equal(include, {"*"})
	lib.assert_equal(exclude, set())

	lib.assert_equal(include, {"zip"}) with data.rule_collections as {"default": {"include": ["zip"]}}
	lib.assert_equal(exclude, {"zap"}) with data.rule_collections as {"default": {"exclude": ["zap"]}}

	rule_included("foo", "whatever_code")
}

test_include_config {
	mock_config := {"policy": {
		"include": {"foo"},
		"exclude": {"bar"},
	}}

	lib.assert_equal({"foo"}, include) with data.config as mock_config
	lib.assert_equal({"bar"}, exclude) with data.config as mock_config

	rule_included("foo", "whatever_code") with data.config as mock_config
	not rule_included("bar", "whatever_code") with data.config as mock_config
}

test_include_fully_qualified_rules {
	mock_config_to_include := {"policy": {
		"exclude": ["*"],
		"include": ["foo.particular_code"],
	}}

	rule_included("foo", "particular_code") with data.config as mock_config_to_include
	not rule_included("foo", "another_code") with data.config as mock_config_to_include
	not rule_included("bar", "whatever_code") with data.config as mock_config_to_include

	mock_config_to_exclude := {"policy": {
		"include": ["*"],
		"exclude": ["foo.particular_code"],
	}}

	not rule_included("foo", "particular_code") with data.config as mock_config_to_exclude
	rule_included("foo", "another_code") with data.config as mock_config_to_exclude
	rule_included("bar", "whatever_code") with data.config as mock_config_to_exclude
}

test_merge_collection_config {
	mock_config_to_include := {"policy": {"collections": ["s1", "s2"]}}
	mock_rule_collections := {
		"s1": {
			"include": ["eggs", "bacon", "sausage"],
			"exclude": ["oatmeal"],
		},
		"s2": {"exclude": ["porridge"]},
	}
	lib.assert_equal(
		["eggs", "bacon", "sausage"],
		merge_collection_config(mock_config_to_include.policy.collections, "include"),
	) with data.config as mock_config_to_include with data.rule_collections as mock_rule_collections
	lib.assert_equal(
		["oatmeal", "porridge"],
		merge_collection_config(mock_config_to_include.policy.collections, "exclude"),
	) with data.config as mock_config_to_include with data.rule_collections as mock_rule_collections
}

test_include_exclude {
	mock_config_with_collections := {"policy": {"collections": ["c1", "c2"]}}
	mock_config_complete := {"policy": {
		"collections": ["c1", "c2"],
		"include": ["eggs", "bacon", "sausage"],
		"exclude": ["oatmeal", "porridge"],
	}}
	mock_config_without_collections := {"policy": {
		"include": ["eggs", "bacon", "sausage"],
		"exclude": ["oatmeal", "porridge"],
	}}
	mock_config_empty := {"policy": {}}

	mock_rule_collection := {
		"c1": {
			"include": ["toast", "jam"],
			"exclude": ["scone"],
		},
		"c2": {
			"include": ["biscuit", "gravy"],
			"exclude": ["muffin"],
		},
		"default": {
			"include": ["*"],
			"exclude": ["not_useful"],
		},
	}
	mock_rule_collection_empty := {}

	## Include Tests
	# Test that we get the "include" rules from the collections in the "collections"
	lib.assert_equal(
		["toast", "jam", "biscuit", "gravy"],
		_include_exclude("include", "flugelhorn"),
	) with data.config as mock_config_with_collections with data.rule_collections as mock_rule_collection

	# Test that we get the "include" rules from the collections in the "collections" key and the rules in "include"
	lib.assert_equal(
		["toast", "jam", "biscuit", "gravy", "eggs", "bacon", "sausage"],
		_include_exclude("include", "flugelhorn"),
	) with data.config as mock_config_complete with data.rule_collections as mock_rule_collection

	# Test that we get the "include" rules from the "include" key
	lib.assert_equal(
		["eggs", "bacon", "sausage"],
		_include_exclude("include", "flugelhorn"),
	) with data.config as mock_config_without_collections with data.rule_collections as mock_rule_collection

	# Test that we get the default "include" rule when we have an empty policy
	lib.assert_equal(
		["*"],
		_include_exclude("include", "flugelhorn"),
	) with data.config as mock_config_empty with data.rule_collections as mock_rule_collection

	# Test that we get the fallback_rule when we have an empty config and an empty ruleset
	lib.assert_equal(
		["flugelhorn"],
		_include_exclude("include", ["flugelhorn"]),
	) with data.config as mock_config_empty with data.rule_collections as mock_rule_collection_empty

	## Exclude Tests
	# Test that we get the "exclude" rules from the collections in the "collections"
	lib.assert_equal(
		["scone", "muffin"],
		_include_exclude("exclude", "flugelhorn"),
	) with data.config as mock_config_with_collections with data.rule_collections as mock_rule_collection

	# Test that we get the "exclude" rules from the collections in the "collections" key and the rules in "exclude"
	lib.assert_equal(
		["scone", "muffin", "oatmeal", "porridge"],
		_include_exclude("exclude", "flugelhorn"),
	) with data.config as mock_config_complete with data.rule_collections as mock_rule_collection

	# Test that we get the "exclude" rules from the "exclude" key
	lib.assert_equal(
		["oatmeal", "porridge"],
		_include_exclude("exclude", "flugelhorn"),
	) with data.config as mock_config_without_collections with data.rule_collections as mock_rule_collection

	# Test that we get the default "include" rule when we have an empty policy
	lib.assert_equal(
		["not_useful"],
		_include_exclude("exclude", "flugelhorn"),
	) with data.config as mock_config_empty with data.rule_collections as mock_rule_collection

	# Test that we get the fallback_rule when we have an empty config and an empty ruleset
	lib.assert_equal(
		["flugelhorn"],
		_include_exclude("exclude", ["flugelhorn"]),
	) with data.config as mock_config_empty with data.rule_collections as mock_rule_collection_empty
}
