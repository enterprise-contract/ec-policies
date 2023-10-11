package policy.release.java_test

import data.lib
import data.lib.tkn_test
import data.lib_test
import data.policy.release.java

test_all_good {
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.java_sbom_component_count_result_name,
			{"redhat": 12, "rebuilt": 42},
			"java-task-1",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("java-task-2", [{
			"name": lib.java_sbom_component_count_result_name,
			"type": "string",
			"value": {"redhat": 12, "rebuilt": 42},
		}])]),
	]
	lib.assert_empty(java.deny) with input.attestations as attestations
}

test_has_foreign {
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.java_sbom_component_count_result_name,
			{"redhat": 12, "rebuilt": 42, "central": 1},
			"java-task-1",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("java-task-2", [{
			"name": lib.java_sbom_component_count_result_name,
			"type": "string",
			"value": {"redhat": 12, "rebuilt": 42, "central": 1},
		}])]),
	]
	expected := {{
		"code": "java.no_foreign_dependencies",
		"msg": "Found Java dependencies from 'central', expecting to find only from 'rebuilt,redhat'",
	}}
	lib.assert_equal_results(java.deny, expected) with input.attestations as attestations
}

test_trusted_dependency_source_list_provided {
	expected := {{
		"code": "java.trusted_dependencies_source_list_provided",
		"msg": "Missing required allowed_java_component_sources rule data",
	}}
	lib.assert_equal_results(expected, java.deny) with data.rule_data as {}
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
