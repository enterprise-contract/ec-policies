package lib

import data.lib

test_quoted_values_string {
	lib.assert_equal("'a', 'b', 'c'", quoted_values_string(["a", "b", "c"]))
	lib.assert_equal("'a', 'b', 'c'", quoted_values_string({"a", "b", "c"}))
}
