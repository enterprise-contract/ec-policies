package lib

import future.keywords.in

# It's fairly idiomatic rego to just write this inline but still
# I think this is nice to make things a little more readable
#
to_set(arr) := {member | member := arr[_]}

# Without the in keyword it could be done like this:
#  needle == haystack[_]
#
included_in(needle, haystack) {
	needle in haystack
}

# Return true if any of the needles are found in the haystack
#
any_included_in(needles, haystack) {
	needles_set := to_set(needles)
	haystack_set := to_set(haystack)
	count(needles_set & haystack_set) > 0
}

# Return true if all of the needles are found in the haystack
#
all_included_in(needles, haystack) {
	needles_set := to_set(needles)
	haystack_set := to_set(haystack)
	count(needles_set - haystack_set) == 0
}

# Return true if none of the needles are found in the haystack
#
none_included_in(needles, haystack) {
	needles_set := to_set(needles)
	haystack_set := to_set(haystack)
	count(needles_set & haystack_set) == 0
}
