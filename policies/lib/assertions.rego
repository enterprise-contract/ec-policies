package lib

# Produce more useful output when a test fails

assert_equal(left_value, right_value) {
	not _assert_equal_fails(left_value, right_value)
}

_assert_equal_fails(left_value, right_value) {
	left_value != right_value
	debug_output := sprintf("Assert equal failure:\n  Left value:  %s\n  Right value: %s\n", [left_value, right_value])

	# Shows up in query explanation
	trace(debug_output)

	# Shows up on stdout
	print(debug_output)
}

assert_empty(value) {
	not _assert_empty_fails(value)
}

_assert_empty_fails(value) {
	count(value) > 0
	debug_output := sprintf("Assert empty failure:\n  Value:  %s\n", [value])
	trace(debug_output)
	print(debug_output)
}

assert_not_empty(value) {
	not _assert_not_empty_fails(value)
}

_assert_not_empty_fails(value) {
	count(value) == 0
	debug_output := sprintf("Assert not empty failure:\n  Value:  %s\n", [value])
	trace(debug_output)
	print(debug_output)
}
