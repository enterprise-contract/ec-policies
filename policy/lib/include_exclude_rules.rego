package lib

#-----------------------------------------------------------------------------
# Used in main_denies.rego to determine if a package should be skipped.
# (Somewhat duplicates the non_blocking_checks behavior and hopefully will
# replace that entirely in future.)
#

package_included(package_name) {
	any_included_in(with_wildcard(package_name), include_rules)
	none_included_in(with_wildcard(package_name), exclude_rules)
}

package_excluded(package_name) {
	any_included_in(with_wildcard(package_name), exclude_rules)
}

package_excluded(package_name) {
	none_included_in(with_wildcard(package_name), include_rules)
}

with_wildcard(package_name) := {package_name, "*"}

#-----------------------------------------------------------------------------
# It's expected that there will be values in data.config.policy.include_rules
# and data.config.policy.exclude_rules and these will be lists of strings.
# Sensible defaults will be used if they are not present.
#

# This wildcard means every rule is included by default
default_include_rules := ["*"]

# The empty list here means no rules are excluded by default
default_exclude_rules := []

# Find the include_rules configuration or set the default if it doesn't exist
include_rules := result {
	data.config
	result := object.get(data.config, ["policy", "include_rules"], default_include_rules)
} else := default_include_rules {
	true
}

# Find the exclude_rules configuration or set the default if it doesn't exist
exclude_rules := result {
	data.config
	result := object.get(data.config, ["policy", "exclude_rules"], default_exclude_rules)
} else := default_exclude_rules {
	true
}
