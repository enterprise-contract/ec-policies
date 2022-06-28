package policy.pipeline.pipeline_version

import data.lib

mock_pipeline(version) = p {
	p := {
		"kind": "Pipeline",
		"metadata": {
			"name": "keystone",
			"labels": {"app.kubernetes.io/version": version},
		},
	}
}

test_passing {
	# Exceeds minimum version
	lib.assert_empty(deny) with input as mock_pipeline("0.5")
	lib.assert_empty(deny) with input as mock_pipeline("0.5.1")
	lib.assert_empty(deny) with input as mock_pipeline("1")
	lib.assert_empty(deny) with input as mock_pipeline("1.0")
	lib.assert_empty(deny) with input as mock_pipeline("1.0.1")
	lib.assert_empty(deny) with input as mock_pipeline("999")
	lib.assert_empty(deny) with input as mock_pipeline("999.999")
	lib.assert_empty(deny) with input as mock_pipeline("999.999.999")

	# Matches minimum version
	lib.assert_empty(deny) with input as mock_pipeline("0.4")
	lib.assert_empty(deny) with input as mock_pipeline("0.4.0")
}

expected_outdated_deny(version) = d {
	d := {{
		"code": "pipeline_version", "effective_on": "2023-01-01T00:00:00Z",
		"msg": sprintf(`Version of Pipeline "keystone" is outdated, %s. Update to 0.4 or newer`, [version]),
	}}
}

test_outdated_version {
	lib.assert_equal(deny, expected_outdated_deny("0")) with input as mock_pipeline("0")
	lib.assert_equal(deny, expected_outdated_deny("0.3")) with input as mock_pipeline("0.3")
	lib.assert_equal(deny, expected_outdated_deny("0.3.9")) with input as mock_pipeline("0.3.9")
	lib.assert_equal(deny, expected_outdated_deny("0.3.999")) with input as mock_pipeline("0.3.999")
}

test_invalid_version_format {
	expected_deny := {{
		"code": "pipeline_version_format", "effective_on": "2023-01-01T00:00:00Z",
		"msg": `Pipeline "keystone" defines an invalid version format, spam. Use "." separated digits`,
	}}

	lib.assert_equal(deny, expected_deny) with input as mock_pipeline("spam")
}

test_missing_version {
	expected_deny := {{
		"code": "pipeline_version_exists", "effective_on": "2023-01-01T00:00:00Z",
		"msg": `Pipeline "keystone" does not define a version`,
	}}

	lib.assert_equal(deny, expected_deny) with input as mock_pipeline(null) with input.metadata.labels as {}
}
