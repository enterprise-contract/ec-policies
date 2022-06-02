package lib

test_assert_equal {
	assert_equal("a", "a")
	assert_equal({"a": 10}, {"a": 10})
	assert_equal(["a"], ["a"])
	assert_equal({"a"}, {"a"})
	not assert_equal("a", "b")
	not assert_equal({"a": 10}, {"a", 11})
	not assert_equal(["a"], ["b"])
	not assert_equal({"a"}, {"b"})
}

test_assert_not_equal {
	assert_not_equal("a", "b")
	assert_not_equal({"a": 10}, {"a", 11})
	assert_not_equal(["a"], ["b"])
	assert_not_equal({"a"}, {"b"})
	not assert_not_equal("a", "a")
	not assert_not_equal({"a": 10}, {"a": 10})
	not assert_not_equal(["a"], ["a"])
	not assert_not_equal({"a"}, {"a"})
}

test_assert_empty {
	assert_empty([])
	assert_empty({})
	assert_empty(set())
	not assert_empty(["a"])
	not assert_empty({"a"})
	not assert_empty({"a": "b"})
}

test_assert_not_empty {
	assert_not_empty(["a"])
	assert_not_empty({"a"})
	assert_not_empty({"a": "b"})
	not assert_not_empty([])
	not assert_not_empty({})
	not assert_not_empty(set())
}
