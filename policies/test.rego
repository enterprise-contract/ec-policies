package hacbs.contract.test

# Check if we have any test data is present
deny[{"msg": msg}] {
	not data.test
	msg := "No test data provided"
}

# Check if we have any test data provided
deny[{"msg": msg}] {
	count(data.test) == 0
	msg := "Empty test data provided"
}

deny[{"msg": msg}] {
	with_results := [result | result := data.test[_].result]
	count(with_results) != count(data.test)

	msg := "Found tests without results"
}

# Check if all tests succeeded 
deny[{"msg": msg}] {
	all_failed := [failure | data.test[_].result != "SUCCESS"; failure := 1]
	count(all_failed) > 0

	msg := "All tests did not end with SUCCESS"
}
