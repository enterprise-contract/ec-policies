package lib

import data.lib

# Collect all non-skipped deny or warn rules under data.policy.<policy_namespace>
# regardless of whether they are effective now or in the future.
#
# Remember that passing (i.e. untriggered) denies or warns will not be included
# in this list. The list contains potential failures only.
#
_current_and_future_denies_or_warns(policy_namespace, deny_or_warn) := rule_set {
	rule_set := {r |
		policy_packages := data.policy[policy_namespace]
		policy_package := policy_packages[package_name]
		not skip_package(package_name)
		r := policy_package[deny_or_warn][_]
	}
}

current_and_future_denies(policy_namespace) := _current_and_future_denies_or_warns(policy_namespace, "deny")

current_and_future_warns(policy_namespace) := _current_and_future_denies_or_warns(policy_namespace, "warn")

# Filter to return only rules that are effective now
#
current_rules(all_rules) := rule_set {
	rule_set := {r | all_rules[r]; not in_future(r)}
}

# Filter to return only rules that are effective in the future
#
future_rules(all_rules) := rule_set {
	rule_set := {r | all_rules[r]; in_future(r)}
}

# Used to ignore rules for a package if package_name is present
# in the non_blocking_checks list
#
skip_package(package_name) {
	data.config.policy.non_blocking_checks[_] == package_name
}

# Todo maybe: Skip a rule based on package_name and rule short_name

# Return true if a particular rule is effective in the future
# but not effective right now
#
in_future(rule) {
	# The rule has effective_on set
	rule.effective_on

	# The rule is effective in the future but not now
	time.parse_rfc3339_ns(rule.effective_on) > lib.time.effective_current_time_ns
}
