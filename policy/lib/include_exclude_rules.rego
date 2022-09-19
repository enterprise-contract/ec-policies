package lib

# Used in main_denies.rego to determine if a rule should be included or not
#
rule_included(package_name, rule_code) {
	full_rule_name := package_and_code(package_name, rule_code)

	# The package is included
	package_included(package_name)

	# ..and the rule is not explicitly excluded
	not included_in(full_rule_name, exclude_rules)
} else {
	full_rule_name := package_and_code(package_name, rule_code)

	# The rule is explicitly included, regardless of the package
	included_in(full_rule_name, include_rules)

	# ..and not explicitly excluded
	not included_in(full_rule_name, exclude_rules)
}

# At risk of introducing ambiguity by overloading the dot separator,
# we'll use a dot to separate package and rule name
#
package_and_code(package_name, rule_code) := result {
	result := sprintf("%s.%s", [package_name, rule_code])
}

# Returns true if the package (and all its rules) should be included
#
package_included(package_name) {
	# To make it intuitive, both "foo" and "foo.*" can be used to specify
	# a package, and "*" acts like a wildcard to match any package
	package_name_matchers := {package_name, sprintf("%s.*", [package_name]), "*"}

	# Package is in the include list
	any_included_in(package_name_matchers, include_rules)

	# ..and not the exclude list
	none_included_in(package_name_matchers, exclude_rules)
}

include_rules := to_set(_include_exclude_rules("include", ["*"]))

_exclude_rules := to_set(_include_exclude_rules("exclude", []))

# Temporary for backwards compatibility while we deprecate the
# non_blocking_checks policy configuration
exclude_rules := r {
	r := _exclude_rules | to_set(_non_blocking_checks)
}

# Will be removed in future
_non_blocking_checks := result {
	data.config
	result := object.get(data.config, ["policy", "non_blocking_checks"], [])
} else := result {
	result := []
}

# Look in various places to find the include_rules/exclude_rules lists
_include_exclude_rules(include_exclude, fallback_default) := result {
	# A collection was specified in the policy config
	result := data.rule_collections[data.config.policy.collection][include_exclude]
} else := result {
	# The list was specified explicitly in the policy config
	result := data.config.policy[sprintf("%s_rules", [include_exclude])]
} else := result {
	# Use the value from the default collection
	result := data.rule_collections["default"][include_exclude]
} else := result {
	# Just in case none of the above exist
	result := fallback_default
}
