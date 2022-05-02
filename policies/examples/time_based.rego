package examples.time_based

# When effective_on is specified, the policy will be ignored until the day/time is reached.
# Use "effective_on := time.now_ns()", or omit the variable declaration, to make the policy
# always applicable.
effective_on := time.parse_rfc3339_ns("2099-05-02T00:00:00Z")

# This policy always fails
deny[{"msg": msg}] {
	true
	msg := "Roads?"
}
