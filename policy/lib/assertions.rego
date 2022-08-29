package lib

# Produce more useful output when a test fails

# Beware: `lib.assert_equal(<boolean>, ...)` does not work like
# you would expect, so it's better not to use this for booleans
#
assert_equal(left_value, right_value) {
	not _assert_equal_fails(left_value, right_value)
}

_assert_equal_fails(left_value, right_value) {
	left_value != right_value
	_assert_output_two_values("equal", left_value, right_value)
}

assert_not_equal(left_value, right_value) {
	not _assert_not_equal_fails(left_value, right_value)
}

_assert_not_equal_fails(left_value, right_value) {
	left_value == right_value
	_assert_output_two_values("not equal", left_value, right_value)
}

assert_empty(value) {
	not _assert_empty_fails(value)
}

_assert_empty_fails(value) {
	count(value) > 0
	_assert_output_one_value("empty", value)
}

assert_not_empty(value) {
	not _assert_not_empty_fails(value)
}

_assert_not_empty_fails(value) {
	count(value) == 0
	_assert_output_one_value("not empty", value)
}

_assert_output_two_values(assert_type, left_value, right_value) {
	debug_output := sprintf("Assert %s failure:\n  Left value:  %s\n  Right value: %s", [assert_type, left_value, right_value])

	# Use trace to show debug output in query explanations and print for stdout
	trace(debug_output)
	print(debug_output)
}

_assert_output_one_value(assert_type, value) {
	debug_output := sprintf("Assert %s failure:\n  Value: %s", [assert_type, value])
	trace(debug_output)
	print(debug_output)
}
