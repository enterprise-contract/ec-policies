package lib.arrays

import data.lib

ary := [{"x": 1, "z": "X"}, {"x": 2}, {"x": 6, "y": "B"}, {"x": 1, "z": "X"}, {"x": -1}]

test_rank {
	lib.assert_equal(4, rank({"x": 4, "y": "A"}, "x", ary))
	lib.assert_equal(1, rank({"x": -1}, "x", ary))
	lib.assert_equal(0, rank({"x": -2}, "x", ary))
	lib.assert_equal(5, rank({"x": 7}, "x", ary))
	lib.assert_equal(count(ary), rank({}, "x", ary))
	lib.assert_equal(count(ary), rank({}, "w", ary))
}

test_sort_by {
	lib.assert_equal([{"x": -1}, {"x": 1, "z": "X"}, {"x": 1, "z": "X"}, {"x": 2}, {"x": 6, "y": "B"}], sort_by("x", ary))
	lib.assert_equal([{"x": 6, "y": "B"}, {"x": 1, "z": "X"}, {"x": 2}, {"x": 1, "z": "X"}, {"x": -1}], sort_by("y", ary))
}

test_sort_by_mixed_types {
	lib.assert_equal([{"x": 0}, {"x": "1"}, {"x": 2.0}], sort_by("x", [{"x": "1"}, {"x": 0}, {"x": 2.0}]))
}

test_le {
	le(0, 0)
	le("A", "A")
	le(1, "1")
	le("2", 2)
	le(3.0, 3.0)
	le("4.0", 4.0)
	le(5.0, "5.0")

	le(0, 1)
	le("A", "B")
	le("0", 1)
	le(0, "1")

	not le(1, 0)
	not le("B", "A")
	not le(1, "0")
	not le("1", 0)
}
