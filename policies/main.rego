package hacbs.contract.main

deny = {denial |
	not skip(policy)
	data.hacbs.contract.policies[policy].deny[_]
	denial := data.hacbs.contract.policies[policy].deny[_]
}

skip(test_name) {
	data.config.policy.non_blocking_checks[_] == test_name
}
