package main

deny = {denial |
	not skip(policy)
	data.policies[policy].deny[_]
	denial := data.policies[policy].deny[_]
}

skip(test_name) {
	data.config.policy.non_blocking_checks[_] == test_name
}
