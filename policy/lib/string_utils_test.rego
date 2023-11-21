package lib_test

import data.lib
import future.keywords.if

test_quoted_values_string if {
	lib.assert_equal("'a', 'b', 'c'", lib.quoted_values_string(["a", "b", "c"]))
	lib.assert_equal("'a', 'b', 'c'", lib.quoted_values_string({"a", "b", "c"}))
}
