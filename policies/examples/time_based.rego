# METADATA
# scope: package
# custom:
#   effective_on: 2000-01-01T00:00:00Z
package examples.time_based

import future.keywords.in

# This policy always fails
# METADATA
# custom:
#   effective_on: 2099-05-02T00:00:00Z

# When effective_on is specified, the policy will be ignored until the day/time is reached.
# Use "effective_on := time.now_ns()", or omit the variable declaration, to make the policy
# always applicable.
deny[{"msg": msg, "effective_on": effective_on}] {
	true
	msg := "Roads?"
	effective_on := when(rego.metadata.chain())
}

# This policy always fails, but doesn't have effective_on set
# METADATA
# custom:
deny[{"msg": msg}] {
	true
	msg := "no effective date"
}

# This policy always fails, and has a effective_on in the past
# METADATA
# custom:
#   effective_on: 1970-01-01T01:00:00Z
deny[{"msg": msg, "effective_on": effective_on}] {
	true
	msg := "from the past"
	effective_on := when(rego.metadata.chain())
}

# This policy fails if today is after 2000-01-01T00:00:00Z but not before it
# as per the package annotation
deny[{"msg": msg, "effective_on": effective_on}] {
	true
	msg := "Y2K"
	effective_on := when(rego.metadata.chain())
}

when(m) = effective_on {
	precedence := ["rule", "document", "package"]
	all_effective_on := [e |
		a := m[_].annotations
		e = a.custom.effective_on
		a.scope in precedence
	]

	# first one found in precedence 
	effective_on := all_effective_on[0]
}
