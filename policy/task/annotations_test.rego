package policy.task.annotation_test

import rego.v1

import data.lib
import data.policy.task.annotation

test_valid_expiry_dates if {
	# regal ignore:line-length
	lib.assert_empty(annotation.deny) with input.metadata.annotations as {annotation._expires_on_annotation: "2000-01-02T03:04:05Z"}
}

test_invalid_expiry_dates if {
	lib.assert_equal_results(annotation.deny, {{
		"code": "annotation.expires_on_format",
		"msg": `Expires on time is not in RFC3339 format: "meh"`,
	}}) with input.metadata.annotations as {annotation._expires_on_annotation: "meh"}
}
