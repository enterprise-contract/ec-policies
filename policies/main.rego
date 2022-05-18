package main

deny = {denial |
	not skip(policy)
	data.policies[policy].deny[_]
	denial := data.policies[policy].deny[_]
}

future_deny = {denial |
	skip_not_in_effect(policy)
	data.policies[policy].deny[_]
	denial := data.policies[policy].deny[_]
}

skip(test_name) {
	data.config.policy.non_blocking_checks[_] == test_name
}

skip_not_in_effect(policy_name) {
	# Use the nanosecond epoch defined in the policy if present. Otherwise, use now.
	when_ns := object.get(data.config.policy, ["when_ns"], time.now_ns())
	data.policies[policy_name].effective_on > when_ns
}

skip(policy_name) {
	skip_not_in_effect(policy_name)
}
