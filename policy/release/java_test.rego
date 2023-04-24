package policy.release.java

import data.lib

test_all_good {
	attestations := [lib.att_mock_helper_ref(
		lib.java_sbom_component_count_result_name,
		{"redhat": 12, "rebuilt": 42},
		"java-task-1",
		_bundle,
	)]
	lib.assert_empty(deny) with input.attestations as attestations
}

test_has_foreign {
	attestations := [lib.att_mock_helper_ref(
		lib.java_sbom_component_count_result_name,
		{"redhat": 12, "rebuilt": 42, "central": 1},
		"java-task-1",
		_bundle,
	)]
	expected := {{
		"code": "java.no_foreign_dependencies",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Found Java dependencies from 'central', expecting to find only from 'rebuilt,redhat'",
	}}
	lib.assert_equal(deny, expected) with input.attestations as attestations
}

test_trusted_dependency_source_list_provided {
	expected := {{
		"code": "java.trusted_dependencies_source_list_provided",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Missing required allowed_java_component_sources rule data",
	}}
	lib.assert_equal(expected, deny) with data.rule_data as {}
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
