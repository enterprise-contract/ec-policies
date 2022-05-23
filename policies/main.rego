package main

denials := {denial |
	not skip(policy)
	data.policies[policy].deny[_]
	denial := data.policies[policy].deny[_]
}

deny := {d | denials[d]; not in_future(d)}

future_deny := {d | denials[d]; in_future(d)}

skip(test_name) {
	data.config.policy.non_blocking_checks[_] == test_name
}

in_future(denial) {
	# if the denial has effective_on set
	denial.effective_on

	# Use the nanosecond epoch defined in the policy config -- if present. Otherwise, use now.
	when_ns := object.get(data.config, ["policy", "when_ns"], time.now_ns())
	time.parse_rfc3339_ns(denial.effective_on) > when_ns
}
