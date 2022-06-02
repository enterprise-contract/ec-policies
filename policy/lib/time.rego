package lib.time

import future.keywords.in

# A default value in the past. Could be whatever but beware you'll have to
# update a bunch of tests if you change it.
#
default_effective_on := "2022-01-01T00:00:00Z"

# This supports finding an effective_on date in multiple scopes, giving
# precedence to the narrowest scope. Let's keep it that way even though
# currently we're not using any scopes except for the rule scope.
#
when(metadata_chain) = effective_on {
	scope_precedence := ["rule", "document", "package"]
	all_effective_on := [e |
		annotations := metadata_chain[_].annotations
		e := annotations.custom.effective_on
		annotations.scope in scope_precedence
	]

	# Use the first one found in scope_precedence or fall back to the default
	# value if effective_on was not found in annotations
	effective_on := array.concat(all_effective_on, [default_effective_on])[0]
}
