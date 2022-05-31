# METADATA
# custom:
#   effective_on: 2022-01-01T00:00:00Z
package policies.release.not_useful

import data.lib

test_not_useful {
	lib.assert_equal(deny, {{
		"code": "bad_day",
		"msg": "It just feels like a bad day to do a release",
		"effective_on": "2022-01-01T00:00:00Z",
	}})
}
