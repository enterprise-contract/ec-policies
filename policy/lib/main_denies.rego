package lib

# Collect all non-skipped deny rules under data.policy.<policy_namespace>
# regardless of whether they are effective now or in the future
#
current_and_future_denies(policy_namespace) := deny_set {
	deny_set := {d |
		policy_packages := data.policy[policy_namespace]
		policy_package := policy_packages[package_name]
		not skip_package(package_name)
		d := policy_package.deny[_]
	}
}

# Filter the current_and_future_denies set to return only denies
# that are effective now
#
current_denies(all_denies) := deny_set {
	deny_set := {d | all_denies[d]; not in_future(d)}
}

# Filter the current_and_future_denies set to return only denies
# that are effective in the future
#
future_denies(all_denies) := deny_set {
	deny_set := {d | all_denies[d]; in_future(d)}
}

# Used to ignore deny rules for a package if package_name is present
# in the non_blocking_checks list
#
skip_package(package_name) {
	data.config.policy.non_blocking_checks[_] == package_name
}

# Todo maybe: Skip a rule based on package_name and rule short_name

# Return true if a particular deny rule is effective in the future
# but not effective right now
#
in_future(denial) {
	# if the denial has effective_on set
	denial.effective_on

	# Use the nanosecond epoch defined in the policy config -- if present. Otherwise, use now.
	when_ns := object.get(data.config, ["policy", "when_ns"], time.now_ns())
	time.parse_rfc3339_ns(denial.effective_on) > when_ns
}
