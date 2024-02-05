package policy.pipeline.basic_test

import rego.v1

import data.lib
import data.policy.pipeline.basic

test_unexpected_kind if {
	lib.assert_equal_results(basic.deny, {{
		"code": "basic.expected_kind",
		"msg": "Unexpected kind 'Foo' for pipeline definition",
	}}) with input.kind as "Foo"
}
