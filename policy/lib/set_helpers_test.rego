package lib_test

import rego.v1

import data.lib

my_list := ["a", "b", "c"]

my_set := {"a", "b", "c"}

test_to_set if {
	lib.assert_equal(my_set, lib.to_set(my_list))
	lib.assert_equal(my_set, lib.to_set(my_set))
}

test_to_array if {
	lib.assert_equal(my_list, lib.to_array(my_set))
	lib.assert_equal(my_list, lib.to_array(my_list))
}

test_included_in if {
	lib.included_in("a", my_list)
	lib.included_in("a", my_set)
	not lib.included_in("z", my_list)
	not lib.included_in("z", my_set)
}

test_any_included_in if {
	lib.any_included_in(["a", "z"], my_list)
	lib.any_included_in(["a", "z"], my_set)
	lib.any_included_in({"a", "z"}, my_list)
	lib.any_included_in({"a", "z"}, my_set)

	not lib.any_included_in({"x", "z"}, my_set)
}

test_all_included_in if {
	lib.all_included_in({"a", "b"}, my_set)
	not lib.all_included_in({"a", "z"}, my_set)
}

test_none_included_in if {
	lib.none_included_in({"x", "z"}, my_set)
	not lib.none_included_in({"a", "z"}, my_set)
}

test_any_not_included_in if {
	lib.any_not_included_in({"a", "z"}, my_set)
	not lib.any_not_included_in({"a", "b"}, my_set)
}
