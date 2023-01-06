package lib

# NOTE: Eventually, this file is removed and all remaining exclude logic
# is handled by the ec-cli. However, the policy rules in release.test
# have custom exclusion logic that have not yet been ported to the ec-cli.

# exclude returns the full set of rules that should be excluded.
exclude := r {
	r := _exclude | _non_blocking_checks
}

# _non_blocking_checks returns a set of rule that should be excluded
# based on the deprecated non_blocking_checks policy attributes. This
# will be removed in future. Defaults to an empty set.
_non_blocking_checks := result {
	data.config
	result := to_set(data.config.policy.non_blocking_checks)
} else := result {
	result := set()
}

# _exclude returns a set of rules that should be excluded based
# on the policy configuration. Defaults to an empty set.
_exclude := result {
	result := to_set(data.config.policy.exclude)
} else := result {
	result := set()
}
