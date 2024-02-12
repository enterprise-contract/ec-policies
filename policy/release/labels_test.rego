package policy.release.labels_test

import rego.v1

import data.lib
import data.policy.release.labels

test_all_good if {
	lib.assert_empty(labels.deny | labels.warn) with input.image as _image with data.rule_data as _rule_data
	lib.assert_empty(labels.deny | labels.warn) with input.image as _fbc_image with data.rule_data as _rule_data
}

test_deprecated_image_labels if {
	expected := {{
		"code": "labels.deprecated_labels",
		"msg": "The \"oldie\" label is deprecated, replace with \"shiny\"",
		"term": "oldie",
	}}

	image := json.patch(_image, [{
		"op": "add",
		"path": "/config/Labels/oldie",
		"value": "sudo rm -rf /",
	}])

	lib.assert_equal_results(labels.deny, expected) with input.image as image
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.deny) with input.image as image
		with data.rule_data as _rule_data_with_date
}

test_required_image_labels if {
	expected := {{
		"code": "labels.required_labels",
		"msg": "The required \"name\" label is missing. Label description: Name of the image.",
		"term": "name",
	}}

	image := json.remove(_image, ["/config/Labels/name"])

	lib.assert_equal_results(labels.deny, expected) with input.image as image
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.deny) with input.image as image
		with data.rule_data as _rule_data_with_date
}

test_fbc_required_image_labels if {
	expected := {{
		"code": "labels.required_labels",
		"msg": "The required \"fbc.name\" label is missing. Label description: Name of the FBC image.",
		"term": "fbc.name",
	}}

	image := json.remove(_fbc_image, ["/config/Labels/fbc.name"])

	lib.assert_equal_results(labels.deny, expected) with input.image as image
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.deny) with input.image as image
		with data.rule_data as _rule_data_with_date
}

test_optional_image_labels if {
	expected := {{
		"code": "labels.optional_labels",
		"msg": "The optional \"summary\" label is missing. Label description: A short description of the image.",
		"term": "summary",
	}}

	image := json.remove(_image, ["/config/Labels/summary"])

	lib.assert_equal_results(labels.warn, expected) with input.image as image
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.warn) with input.image as image
		with data.rule_data as _rule_data_with_date
}

test_fbc_optional_image_labels if {
	expected := {{
		"code": "labels.optional_labels",
		"msg": "The optional \"fbc.summary\" label is missing. Label description: A short description of the FBC image.",
		"term": "fbc.summary",
	}}

	image := json.remove(_fbc_image, ["/config/Labels/fbc.summary"])

	lib.assert_equal_results(labels.warn, expected) with input.image as image
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.warn) with input.image as image
		with data.rule_data as _rule_data_with_date
}

test_disallowed_inherited_image_labels if {
	expected := {{
		"code": "labels.disallowed_inherited_labels",
		"msg": "The \"unique\" label should not be inherited from the parent image",
		"term": "unique",
	}}

	image := json.patch(_image, [
		{"op": "add", "path": "/config/Labels/unique", "value": "spam"},
		{"op": "add", "path": "/parent/config/Labels/unique", "value": "spam"},
	])

	lib.assert_equal_results(labels.deny, expected) with input.image as image
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.deny) with input.image as image
		with data.rule_data as _rule_data_with_date

	# A missing label on either image does not trigger a violation.
	lib.assert_empty(labels.deny) with input.image as json.patch(_image, [{
		"op": "add",
		"path": "/parent/config/Labels/unique",
		"value": "spam",
	}])
		with data.rule_data as _rule_data
	lib.assert_empty(labels.deny) with input.image as json.patch(_image, [{
		"op": "add",
		"path": "/config/Labels/unique",
		"value": "spam",
	}])
		with data.rule_data as _rule_data
}

test_fbc_disallowed_inherited_image_labels if {
	expected := {{
		"code": "labels.disallowed_inherited_labels",
		"msg": "The \"fbc.unique\" label should not be inherited from the parent image",
		"term": "fbc.unique",
	}}

	image := json.patch(_fbc_image, [
		{"op": "add", "path": "/config/Labels/fbc.unique", "value": "spam"},
		{"op": "add", "path": "/parent/config/Labels/fbc.unique", "value": "spam"},
	])

	lib.assert_equal_results(labels.deny, expected) with input.image as image
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.deny) with input.image as image
		with data.rule_data as _rule_data_with_date

	# A missing label on either image does not trigger a violation.
	lib.assert_empty(labels.deny) with input.image as json.patch(_fbc_image, [{
		"op": "add",
		"path": "/parent/config/Labels/fbc.unique",
		"value": "spam",
	}])
		with data.rule_data as _rule_data
	lib.assert_empty(labels.deny) with input.image as json.patch(_fbc_image, [{
		"op": "add",
		"path": "/config/Labels/fbc.unique",
		"value": "spam",
	}])
		with data.rule_data as _rule_data
}

test_rule_data_provided if {
	d := {
		"required_labels": [
			# Wrong type
			1,
			# Duplicated items
			{"name": "name", "description": "label-description"},
			{"name": "name", "description": "label-description"},
			# Additional properties
			{"name": "name", "description": "label-description", "foo": "bar"},
		],
		"fbc_required_labels": [1],
		"optional_labels": [1],
		"fbc_optional_labels": [1],
		"disallowed_inherited_labels": [
			# Wrong type
			1,
			# Duplicated items
			{"name": "name"},
			{"name": "name"},
			# Additional properties
			{"name": "name", "foo": "bar"},
		],
		"fbc_disallowed_inherited_labels": [1],
		"deprecated_labels": [
			# Wrong type
			1,
			# Duplicated items
			{"name": "deprecated-name", "replacement": "label-replacement"},
			{"name": "deprecated-name", "replacement": "label-replacement"},
			# Additional properties
			{"name": "deprecated-name", "replacement": "label-description", "foo": "bar"},
		],
	}

	expected := {
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data deprecated_labels has unexpected format: (Root): array items[1,2] must be unique",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data deprecated_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data deprecated_labels has unexpected format: 3: Additional property foo is not allowed",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data disallowed_inherited_labels has unexpected format: (Root): array items[1,2] must be unique",
		},
		{
			"code": "labels.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data disallowed_inherited_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data disallowed_inherited_labels has unexpected format: 3: Additional property foo is not allowed",
		},
		{
			"code": "labels.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data fbc_disallowed_inherited_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data fbc_optional_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data fbc_required_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data optional_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data required_labels has unexpected format: (Root): array items[1,2] must be unique",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data required_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data required_labels has unexpected format: 3: Additional property foo is not allowed",
		},
	}

	lib.assert_equal_results(labels.deny, expected) with input.image as _image
		with data.rule_data as d
}

_image := {
	"config": {"Labels": {
		"name": "test-image",
		"description": "test image",
		"summary": "test",
	}},
	"parent": {"config": {"Labels": {
		"name": "test-parent-image",
		"description": "test parent image",
		"summary": "parent",
	}}},
}

_fbc_image := {
	"config": {"Labels": {
		"fbc.name": "test-image",
		"fbc.description": "test image",
		"fbc.summary": "test",
		"operators.operatorframework.io.index.configs.v1": "/config",
	}},
	"parent": {"config": {"Labels": {
		"fbc.name": "test-parent-image",
		"fbc.description": "test parent image",
		"fbc.summary": "parent",
	}}},
}

_rule_data := {
	"deprecated_labels": [{"name": "oldie", "replacement": "shiny"}],
	"required_labels": [
		{"name": "name", "description": "Name of the image."},
		{"name": "description", "description": "Detailed description of the image."},
	],
	"fbc_required_labels": [
		{"name": "fbc.name", "description": "Name of the FBC image."},
		{"name": "fbc.description", "description": "Detailed description of the FBC image."},
	],
	"optional_labels": [{"name": "summary", "description": "A short description of the image."}],
	"fbc_optional_labels": [{"name": "fbc.summary", "description": "A short description of the FBC image."}],
	"disallowed_inherited_labels": [{"name": "unique"}],
	"fbc_disallowed_inherited_labels": [{"name": "fbc.unique"}],
}

_mock_effective_on := "3000-01-01T00:00:00Z"

_rule_data_with_date[category] := values_with_date if {
	some category, values in _rule_data
	values_with_date := [value_with_date |
		some value in values
		value_with_date := object.union(value, {"effective_on": _mock_effective_on})
	]
}

_assert_effective_on_date(violations) if {
	got_effective_on := {date |
		some violation in violations
		date := object.get(violation, "effective_on", "")
	}
	lib.assert_equal(got_effective_on, {_mock_effective_on})
}
