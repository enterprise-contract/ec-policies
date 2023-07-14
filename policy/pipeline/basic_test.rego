package policy.pipeline.basic

import data.lib

test_unexpected_kind {
	lib.assert_equal_results(deny, {{
		"code": "basic.unexpected_kind",
		"msg": "Unexpected kind 'Foo'",
	}}) with input.kind as "Foo"
}
