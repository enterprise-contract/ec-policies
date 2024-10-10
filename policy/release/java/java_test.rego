package release.java_test

import rego.v1

import data.lib
import data.lib.tekton_test
import data.lib_test
import data.release.java

test_all_good if {
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.java_sbom_component_count_result_name,
			{"redhat": 12, "rebuilt": 42},
			"java-task-1",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_result_ref("java-task-2", [{
			"name": lib.java_sbom_component_count_result_name,
			"type": "string",
			"value": {"redhat": 12, "rebuilt": 42},
		}])]),
	]
	lib.assert_empty(java.deny) with input.attestations as attestations
}

test_has_foreign if {
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.java_sbom_component_count_result_name,
			{"redhat": 12, "rebuilt": 42, "central": 1},
			"java-task-1",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_result_ref("java-task-2", [{
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

test_trusted_dependency_source_list_provided_not_empty if {
	expected := {{
		"code": "java.trusted_dependencies_source_list_provided",
		"msg": "Rule data allowed_java_component_sources has unexpected format: (Root): Array must have at least 1 items",
	}}
	lib.assert_equal_results(expected, java.deny) with data.rule_data as {}
}

test_trusted_dependency_source_list_provided_format if {
	d := {"allowed_java_component_sources": [
		# Wrong type
		1,
		# Duplicated items
		"foo",
		"foo",
	]}

	expected := {
		{
			"code": "java.trusted_dependencies_source_list_provided",
			"msg": "Rule data allowed_java_component_sources has unexpected format: (Root): array items[1,2] must be unique",
		},
		{
			"code": "java.trusted_dependencies_source_list_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_java_component_sources has unexpected format: 0: Invalid type. Expected: string, given: integer",
		},
	}

	lib.assert_equal_results(java.deny, expected) with data.rule_data as d
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
