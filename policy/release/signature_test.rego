package policy.release.signature

import data.lib

mock_data(signatures) = d {
	d := {"body": {"sha": "nm32n5235"}, "signatures": signatures}
}

test_bad_email_format {
	expected_msg := "Signature ecredhat.com in commit nm32n5235 is not a valid email address"
	lib.assert_equal(warn, {{
		"code": "disallowed_commit_signature_email",
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input as mock_data(["ecredhat.com"])
}

test_good_email_format {
	lib.assert_equal(warn, set()) with input as mock_data(["ec@redhat.com"])
}

test_bad_domain {
	expected_msg := "Signature ec@evil.com in commit nm32n5235 has disallowed domain"
	lib.assert_equal(warn, {{
		"code": "disallowed_commit_signature_domain",
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input as mock_data(["ec@evil.com"])
}

test_good_domain {
	lib.assert_equal(warn, set()) with input as mock_data(["ec@redhat.com"])
}

test_domain_case {
	lib.assert_equal(warn, set()) with input as mock_data(["ec@REDHAT.com"])
	lib.assert_equal(warn, set()) with input as mock_data(["ec@redhat.com"])
}
