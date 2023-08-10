package policy.pipeline.basic

import data.lib

test_unexpected_kind {
	lib.assert_equal_results(deny, {{
		"code": "basic.expected_kind",
		"msg": "Unexpected kind 'Foo' for pipeline definition",
	}}) with input.kind as "Foo"
}
