package examples.time_based

# This policy always fails
# METADATA
# custom:
#   effective_on: 2099-05-02T00:00:00Z

# When effective_on is specified, the policy will be ignored until the day/time is reached.
# Use "effective_on := time.now_ns()", or omit the variable declaration, to make the policy
# always applicable.
deny[{"msg": msg, "effective_on": rego.metadata.rule().custom.effective_on}] {
	true
	msg := "Roads?"
}

# This policy always fails, but doesn't have effective_on set
# METADATA
# custom:
deny[{"msg": msg}] {
	true
	msg := "no effective date"
}

# This policy always fails, and has a effective_on in the past
# METADATA
# custom:
#   effective_on: 1970-01-01T01:00:00Z
deny[{"msg": msg, "effective_on": rego.metadata.rule().custom.effective_on}] {
	true
	msg := "from the past"
}
