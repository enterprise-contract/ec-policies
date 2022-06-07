package pipeline.main

import data.lib

test_passing {
	lib.assert_empty(deny) with input.kind as "Pipeline"
		with data.config.policy.non_blocking_checks as ["required_tasks"]
}

test_failing {
	lib.assert_equal(deny, {{
		"code": "unexpected_kind",
		"msg": "Unexpected kind 'Zipline'",
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.kind as "Zipline"
		with data.config.policy.non_blocking_checks as ["required_tasks"]
}

test_in_future {
	denial := {"msg": "should fail", "effective_on": "2099-05-02T00:00:00Z"}
	lib.assert_equal(warn, {denial}) with all_denies as {denial}
		with data.config.policy.when_ns as lib.time.future_timestamp
}
