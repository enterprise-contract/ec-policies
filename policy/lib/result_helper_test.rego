package lib

import data.lib

mock_annotations := {"custom": {
	"short_name": "Hey",
	"failure_msg": "Bad thing %s",
}}

expected_result := {"code": "Hey", "effective_on": "2022-01-01T00:00:00Z", "msg": "Bad thing foo"}

test_result_helper {
	lib.assert_equal(expected_result, result_helper([{"annotations": mock_annotations}], ["foo"]))
}
