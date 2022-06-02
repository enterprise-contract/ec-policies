package lib.time

import future.keywords.in

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
