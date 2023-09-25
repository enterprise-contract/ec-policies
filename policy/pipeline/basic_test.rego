package policy.pipeline.basic_test

import data.lib
import data.policy.pipeline.basic

test_unexpected_kind {
	lib.assert_equal_results(basic.deny, {{
		"code": "basic.expected_kind",
		"msg": "Unexpected kind 'Foo' for pipeline definition",
	}}) with input.kind as "Foo"
}
