package lib

import data.lib

my_list := ["a", "b", "c"]

my_set := {"a", "b", "c"}

test_to_set {
	lib.assert_equal(my_set, to_set(my_list))
	lib.assert_equal(my_set, to_set(my_set))
}

test_included_in {
	included_in("a", my_list)
	included_in("a", my_set)
	not included_in("z", my_list)
	not included_in("z", my_set)
}

test_any_included_in {
	any_included_in(["a", "z"], my_list)
	any_included_in(["a", "z"], my_set)
	any_included_in({"a", "z"}, my_list)
	any_included_in({"a", "z"}, my_set)

	not any_included_in({"x", "z"}, my_set)
}

test_all_included_in {
	all_included_in({"a", "b"}, my_set)
	not all_included_in({"a", "z"}, my_set)
}

test_none_included_in {
	none_included_in({"x", "z"}, my_set)
	not none_included_in({"a", "z"}, my_set)
}

test_any_not_included_in {
	any_not_included_in({"a", "z"}, my_set)
	not any_not_included_in({"a", "b"}, my_set)
}
