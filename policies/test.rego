package policies.test

# Check if we have any test data is present
deny[{"msg": msg}] {
	not input.result
	msg := "No tests provided"
}

# Check if we have any test data provided
deny[{"msg": msg}] {
	count(input.test) == 0
	msg := "Empty test data provided"
}

deny[{"msg": msg}] {
	with_results := [result | result := input.test[_].result]
	count(with_results) != count(input.test)

	msg := "Found tests without results"
}

# Check if all tests succeeded
deny[{"msg": msg}] {
	# Collect all failed tests and convert their name to "test:<name>" format
	# Reminder: the tests reside in $DATA_DIR/test/<name>/data.json
	all_failed := {failure | data.test[name].result != "SUCCESS"; failure := sprintf("test:%s", [name])}

	# For the complement operation below (subtraction) we need
	# non_blocking_checks as set and this creates that from the array
	non_blocking_set = {x | x := data.config.policy.non_blocking_checks[_]}

	# Failed tests are those that don't have their result equal to "SUCCESS"
	# and are not on the list of non_blocking_checks
	failed_blocking := all_failed - non_blocking_set

	# Fail if there are any
	count(failed_blocking) > 0

	msg := "All tests did not end with SUCCESS"
}
