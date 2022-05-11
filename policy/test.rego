package policy.test

# Check if a result is present
deny[msg] {
	not input.result
	msg := "Found tests without results"
}

# Check if all tests succeeded
deny[msg] {
 	# Reminder: the tests reside in $INPUT_DIR/test/<name>.json
	# The filename prints in json format with a failed test
	input.result != "SUCCESS"
	msg := "There are failed tests"
}
