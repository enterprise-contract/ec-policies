package policies.not_useful

import data.lib

test_not_useful {
	lib.assert_equal(deny, {{"code": "bad_day", "msg": "It just feels like a bad day to do a release"}})
}
