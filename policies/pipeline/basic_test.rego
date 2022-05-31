package policies.pipeline.basic

import data.lib

test_unexpected_kind {
	lib.assert_equal(deny, {{
		"code": "unexpected_kind",
		"msg": "Unexpected kind 'Foo'",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.kind as "Foo"
}
