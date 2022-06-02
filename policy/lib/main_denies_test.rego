package lib

import data.lib

test_current_and_future {
	lib.assert_empty(current_and_future_denies("bogus"))
	lib.assert_not_empty(current_and_future_denies("release"))
	lib.assert_not_empty(current_and_future_denies("pipeline")) with input.kind as "Foo"
}
