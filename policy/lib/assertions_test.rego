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

test_assert_equal_results {
	# Empty results
	assert_equal_results(set(), set())
	assert_equal_results({{}}, {{}})

	# collections attribute is ignored
	assert_equal_results({{"collections": ["a", "b"]}}, {{}})
	assert_equal_results({{}}, {{"collections": ["a", "b"]}})
	assert_equal_results({{"collections": ["a", "b"]}}, {{"collections": ["c", "d"]}})
	assert_equal_results(
		{{"spam": "maps", "collections": ["a", "b"]}},
		{{"spam": "maps", "collections": ["c", "d"]}},
	)

	# effective_on attribute is ignored
	assert_equal_results({{"effective_on": "2022-01-01T00:00:00Z"}}, {{}})
	assert_equal_results({{}}, {{"effective_on": "2022-01-01T00:00:00Z"}})
	assert_equal_results(
		{{"effective_on": "2022-01-01T00:00:00Z"}},
		{{"effective_on": "1970-01-01T00:00:00Z"}},
	)
	assert_equal_results(
		{{"spam": "maps", "effective_on": "2022-01-01T00:00:00Z"}},
		{{"spam": "maps", "effective_on": "1970-01-01T00:00:00Z"}},
	)

	# both collections and effective_on attributes are ignored
	assert_equal_results(
		{{"spam": "maps", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"}},
		{{"spam": "maps", "collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"}},
	)

	# any other attribute is not ignored
	not assert_equal_results(
		{{"spam": "maps", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"}},
		{{"collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"}},
	)

	# missing attributes in one result is not ignored
	not assert_equal_results(
		{{"spam": "SPAM", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"}},
		{{"collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"}},
	)
	not assert_equal_results(
		{{"collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"}},
		{{"spam": "SPAM", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"}},
	)

	# fallback for unexpected types
	assert_equal_results({"spam", "maps"}, {"spam", "maps"})
	not assert_equal_results({"spam", "maps"}, "spam")
	not assert_equal_results(
		# These are "objects" instead of the expected "set of objects"
		{"spam": "maps", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"},
		{"spam": "maps", "collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"},
	)
}
