package policy.stepaction.kind_test

import rego.v1

import data.lib
import data.stepaction.kind

test_invalid_kind if {
	lib.assert_equal_results(kind.deny, {{
		"code": "stepaction.kind.valid",
		"msg": `Unexpected kind "Foo" for StepAction definition`,
	}}) with input.kind as "Foo"
}

test_valid_kind if {
	lib.assert_empty(kind.deny) with input as {"kind": "StepAction"}
}
