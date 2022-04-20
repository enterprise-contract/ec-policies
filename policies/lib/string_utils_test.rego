package lib

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
	"'a', 'b', 'c'" == quoted_values_string(my_list)
	"'a', 'b', 'c'" == quoted_values_string(my_set)
}

test_log_entry_string {
	"in transparency log entry 123 on example.com" == log_entry_string(123, "example.com")
}
