package lib

import data.lib

test_current_and_future {
	lib.assert_empty(current_and_future_denies("bogus"))
	lib.assert_not_empty(current_and_future_denies("release"))
	lib.assert_not_empty(current_and_future_denies("pipeline")) with input.kind as "Foo"
}

test_effective_current_time_ns {
	lib.assert_equal(effective_current_time_ns, time.now_ns()) # with no config at all
	lib.assert_equal(effective_current_time_ns, time.now_ns()) with data.config as {} # no config.policy
	lib.assert_equal(effective_current_time_ns, time.now_ns()) with data.config.policy as {} # no config.policy.when_ns
	lib.assert_equal(effective_current_time_ns, lib.time.future_timestamp) with data.config.policy.when_ns as lib.time.future_timestamp
}

test_future_handling {
	future_denial := {"msg": "future", "effective_on": "2099-05-02T00:00:00Z"}
	current_denial := {"msg": "current", "effective_on": "1999-05-02T00:00:00Z"}

	lib.assert_equal(true, lib.in_future(future_denial))

	lib.assert_empty(lib.current_rules({future_denial}))
	lib.assert_empty(lib.future_rules({current_denial}))

	lib.assert_equal({future_denial}, lib.future_rules({future_denial}))
	lib.assert_equal({current_denial}, lib.current_rules({current_denial}))

	lib.assert_equal({current_denial}, lib.current_rules({current_denial, future_denial}))
	lib.assert_equal({future_denial}, lib.future_rules({future_denial, current_denial}))
}
