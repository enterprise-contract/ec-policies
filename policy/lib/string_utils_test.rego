package lib

import data.lib

my_list := ["a", "b", "c"]

my_set := {"a", "b", "c"}

test_item_in_list {
	item_in_list("a", my_list)
	item_in_list("a", my_set)
	not item_in_list("z", my_list)
	not item_in_list("z", my_set)

	list_includes_item(my_list, "a")
	list_includes_item(my_set, "a")
	not list_includes_item(my_list, "z")
	not list_includes_item(my_set, "z")
}

test_quoted_values_string {
	lib.assert_equal("'a', 'b', 'c'", quoted_values_string(["a", "b", "c"]))
	lib.assert_equal("'a', 'b', 'c'", quoted_values_string({"a", "b", "c"}))
}
