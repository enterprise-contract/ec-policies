package release

import data.lib

test_not_useful {
	lib.assert_equal(deny_bad_day, {{
		"code": "bad_day",
		"msg": "It just feels like a bad day to do a release",
		"effective_on": "2023-01-01T00:00:00Z",
	}})
}
