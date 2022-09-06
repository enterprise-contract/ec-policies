package lib

import future.keywords.in

# It's fairly idiomatic rego to just write this inline but still
# I think this makes things a little more readable
#
to_set(arr) := {member | member := arr[_]}

# Without the in keyword it could be done like this:
#  needle == haystack[_]
#
included_in(needle, haystack) {
	needle in haystack
}

# Return true if any of the needles are found in the haystack
any_included_in(needles, haystack) {
	# (Set intersection)
	count(to_set(needles) & to_set(haystack)) > 0
}

# Return true if all of the needles are found in the haystack
all_included_in(needles, haystack) {
	# (Set difference)
	count(to_set(needles) - to_set(haystack)) == 0
}

# Return true if none of the needles are found in the haystack
none_included_in(needles, haystack) {
	not any_included_in(needles, haystack)
}

# Return true if any of the needles are missing from the haystack
any_not_included_in(needles, haystack) {
	not all_included_in(needles, haystack)
}
