package lib.arrays

import rego.v1

_max_int := 9223372036854775807

# Returns true if left is less or equal to right. Comparison is done by using
# native comparison in Rego if both left and right are of the same type, or by
# comparing their numerical values if they're not. Undefined values are always
# less or equal to any other value.
le(left, right) := is_le if {
	type_name(left) == type_name(right)
	is_le := left <= right
} else := is_le if {
	is_le := to_number(left) <= to_number(right)
}

# Calculates the rank of an object by given key within an array ary. That is,
# returns number of elements `o` of ary that have `o[key]` less than `obj[key]`
# for a given object `obj`.
rank(obj, key, ary) := count(less_or_eq) if {
	less_or_eq := [o |
		some o in ary
		left := object.get(o, key, _max_int)
		right := object.get(obj, key, _max_int)
		le(left, right)
	]
}

# Sorts elements of the array of objects by the the specified key in ascending
# order. Performs a # N x (N-1) search of an element of `ary` that has the rank
# corresponding to the indexing variable 1..N.
sort_by(key, ary) := [sorted |
	some i in numbers.range(1, count(ary))

	ranked := [o |
		some o in ary

		i == rank(o, key, ary)
	]

	count(ranked) > 0 # skip gaps in ranking that happen when two or more objects have the same rank
	some sorted in ranked # flatten any objects with the same rank
]
