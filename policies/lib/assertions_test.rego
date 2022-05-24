package lib

test_assert_equal {
	assert_equal("a", "a")
	assert_equal({"a": 10}, {"a": 10})
	assert_equal(["a"], ["a"])
	assert_equal({"a"}, {"a"})
}

test_assert_not_equal {
	not assert_equal("a", "b")
	not assert_equal({"a": 10}, {"a", 11})
	not assert_equal(["a"], ["b"])
	not assert_equal({"a"}, {"b"})
}

test_assert_empty {
	assert_empty([])
	assert_empty({})
	assert_empty(set())
}

test_assert_not_empty {
	not assert_empty(["a"])
	not assert_empty({"a": 10})
	not assert_empty({"a"})
}
