package lib

import data.lib

# Collect all non-skipped deny or warn rules under data.policy.<policy_namespace>.
#
# Remember that passing (i.e. untriggered) denies or warns will not be included
# in this list. The list contains potential failures only.
#
_namespace_denies_or_warns(policy_namespace, deny_or_warn) := rule_set {
	rule_set := {r |
		policy_packages := data.policy[policy_namespace]
		policy_package := policy_packages[package_name]

		r := policy_package[deny_or_warn][rule_result]

		# Filter out any rules that are not included
		lib.rule_included(package_name, rule_result.code)
	}
}

namespace_denies(policy_namespace) := _namespace_denies_or_warns(policy_namespace, "deny")

namespace_warns(policy_namespace) := _namespace_denies_or_warns(policy_namespace, "warn")
