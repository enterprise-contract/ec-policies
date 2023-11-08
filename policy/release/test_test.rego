package policy.release.test_test

import data.lib
import data.lib.tkn_test
import data.lib_test
import data.policy.release.test

# Because TEST_OUTPUT isn't in the task results, the lib.results_from_tests will be empty
test_needs_non_empty_data {
	slsav1_task := tkn_test.slsav1_task_result_ref("task2", [{"name": "NOT_TEST_OUTPUT", "type": "string", "value": {}}])
	attestations := [
		lib_test.att_mock_helper_ref("NOT_TEST_OUTPUT", {}, "task1", _bundle),
		lib_test.mock_slsav1_attestation_with_tasks([slsav1_task]),
	]
	lib.assert_equal_results(test.deny, {{
		"code": "test.test_data_found",
		"msg": "No test data found",
	}}) with input.attestations as attestations
}

# There is a test result, but the data inside it doesn't include the "result" key
test_needs_tests_with_results {
	slsav1_task := tkn_test.slsav1_task_result_ref("task2", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"rezult": "SUCCESS"},
	}])
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.task_test_result_name, {"rezult": "SUCCESS"},
			"task1", _bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([slsav1_task]),
	]
	lib.assert_equal_results(test.deny, {{
		"code": "test.test_results_found",
		"msg": "Found tests without results",
	}}) with input.attestations as attestations
}

test_needs_tests_with_results_mixed {
	slsav1_bad_task := tkn_test.slsav1_task_result_ref("task3", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"rezult": "SUCCESS"},
	}])
	slsav1_good_task := tkn_test.slsav1_task_result_ref("task4", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "SUCCESS"},
	}])

	attestations := [
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS"}, "task1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"rezult": "SUCCESS"}, "task2", _bundle),
		lib_test.mock_slsav1_attestation_with_tasks([slsav1_good_task, slsav1_bad_task]),
	]
	lib.assert_equal_results(test.deny, {{
		"code": "test.test_results_found",
		"msg": "Found tests without results",
	}}) with input.attestations as attestations
}

test_success_data {
	slsav1_good_task := tkn_test.slsav1_task_result_ref("task1", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "SUCCESS"},
	}])
	attestations := [
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS"}, "task1", _bundle),
		lib_test.mock_slsav1_attestation_with_tasks([slsav1_good_task]),
	]
	lib.assert_empty(test.deny) with input.attestations as attestations
}

mock_a_failing_test := lib_test.att_mock_helper_ref(
	lib.task_test_result_name,
	{"result": "FAILURE"}, "failed_1", _bundle,
)

test_failure_data {
	slsav1_task := tkn_test.slsav1_task_result_ref("task1", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "FAILURE"},
	}])
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.task_test_result_name,
			{"result": "FAILURE"}, "failed_1", _bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([slsav1_task]),
	]

	lib.assert_empty(test.warn) with input.attestations as attestations
	lib.assert_equal_results(test.deny, {
		{
			"code": "test.no_failed_tests",
			"msg": "Test \"failed_1\" failed",
			"term": "failed_1",
		},
		{
			"code": "test.no_failed_tests",
			"msg": "Test \"task1\" failed",
			"term": "task1",
		},
	}) with input.attestations as attestations

	# Failed informative tests cause warnings, not violations
	lib.assert_empty(test.deny) with input.attestations as attestations
		with data.rule_data.informative_tests as ["task1", "failed_1"]
	lib.assert_equal_results(test.warn, {
		{
			"code": "test.no_failed_informative_tests",
			"msg": "Informative test \"failed_1\" failed",
			"term": "failed_1",
		},
		{
			"code": "test.no_failed_informative_tests",
			"msg": "Informative test \"task1\" failed",
			"term": "task1",
		},
	}) with input.attestations as attestations
		with data.rule_data.informative_tests as ["task1", "failed_1"]
}

mock_an_errored_test := lib_test.att_mock_helper_ref(
	lib.task_test_result_name,
	{"result": "ERROR"}, "errored_1", _bundle,
)

test_error_data {
	slsav1_task := tkn_test.slsav1_task_result_ref("errored_2", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "ERROR"},
	}])
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.task_test_result_name,
			{"result": "ERROR"}, "errored_1", _bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([slsav1_task]),
	]
	lib.assert_equal_results(test.deny, {
		{
			"code": "test.no_erred_tests",
			"msg": "Test \"errored_1\" erred",
			"term": "errored_1",
		},
		{
			"code": "test.no_erred_tests",
			"msg": "Test \"errored_2\" erred",
			"term": "errored_2",
		},
	}) with input.attestations as attestations
}

test_mix_data {
	slsav1_errored_task := tkn_test.slsav1_task_result_ref("errored_2", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "ERROR"},
	}])
	slsav1_failed_task := tkn_test.slsav1_task_result_ref("failed_2", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "FAILURE"},
	}])
	attestations := [
		mock_a_failing_test,
		mock_an_errored_test,
		lib_test.mock_slsav1_attestation_with_tasks([slsav1_failed_task]),
		lib_test.mock_slsav1_attestation_with_tasks([slsav1_errored_task]),
	]
	lib.assert_equal_results(test.deny, {
		{
			"code": "test.no_failed_tests",
			"msg": "Test \"failed_1\" failed",
			"term": "failed_1",
		},
		{
			"code": "test.no_erred_tests",
			"msg": "Test \"errored_1\" erred",
			"term": "errored_1",
		},
		{
			"code": "test.no_failed_tests",
			"msg": "Test \"failed_2\" failed",
			"term": "failed_2",
		},
		{
			"code": "test.no_erred_tests",
			"msg": "Test \"errored_2\" erred",
			"term": "errored_2",
		},
	}) with input.attestations as attestations
}

test_skipped_is_not_warning {
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.task_test_result_name,
			{"result": "SKIPPED"}, "skipped_1", _bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("skipped_2", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "SKIPPED"},
		}])]),
	]
	lib.assert_empty(test.warn) with input.attestations as attestations
}

test_skipped_is_deny {
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.task_test_result_name,
			{"result": "SKIPPED"}, "skipped_1", _bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("skipped_2", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "SKIPPED"},
		}])]),
	]
	lib.assert_equal_results(test.deny, {
		{
			"code": "test.no_skipped_tests",
			"msg": "Test \"skipped_1\" was skipped",
			"term": "skipped_1",
		},
		{
			"code": "test.no_skipped_tests",
			"msg": "Test \"skipped_2\" was skipped",
			"term": "skipped_2",
		},
	}) with input.attestations as attestations
}

test_warning_is_warning {
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.task_test_result_name,
			{"result": "WARNING"}, "warning_1", _bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("warning_2", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "WARNING"},
		}])]),
	]
	lib.assert_equal_results(test.warn, {
		{
			"code": "test.no_test_warnings",
			"msg": "Test \"warning_1\" returned a warning",
			"term": "warning_1",
		},
		{
			"code": "test.no_test_warnings",
			"msg": "Test \"warning_2\" returned a warning",
			"term": "warning_2",
		},
	}) with input.attestations as attestations
}

# regal ignore:rule-length
test_mixed_statuses {
	test_results := [
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "ERROR"}, "error_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS"}, "success_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "FAILURE"}, "failure_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SKIPPED"}, "skipped_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "FAILURE"}, "failure_2", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SKIPPED"}, "skipped_2", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "WARNING"}, "warning_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "ERROR"}, "error_2", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "WARNING"}, "warning_2", _bundle),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("success_20", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "SUCCESS"},
		}])]),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("failure_20", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "FAILURE"},
		}])]),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("error_20", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "ERROR"},
		}])]),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("warning_20", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "WARNING"},
		}])]),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("skipped_20", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "SKIPPED"},
		}])]),
	]

	lib.assert_equal_results(test.deny, {
		{
			"code": "test.no_erred_tests",
			"msg": "Test \"error_1\" erred",
			"term": "error_1",
		},
		{
			"code": "test.no_erred_tests",
			"msg": "Test \"error_2\" erred",
			"term": "error_2",
		},
		{
			"code": "test.no_failed_tests",
			"msg": "Test \"failure_1\" failed",
			"term": "failure_1",
		},
		{
			"code": "test.no_failed_tests",
			"msg": "Test \"failure_2\" failed",
			"term": "failure_2",
		},
		{
			"code": "test.no_failed_tests",
			"msg": "Test \"failure_20\" failed",
			"term": "failure_20",
		},
		{
			"code": "test.no_erred_tests",
			"msg": "Test \"error_20\" erred",
			"term": "error_20",
		},
		{
			"code": "test.no_skipped_tests",
			"msg": "Test \"skipped_1\" was skipped",
			"term": "skipped_1",
		},
		{
			"code": "test.no_skipped_tests",
			"msg": "Test \"skipped_2\" was skipped",
			"term": "skipped_2",
		},
		{
			"code": "test.no_skipped_tests",
			"msg": "Test \"skipped_20\" was skipped",
			"term": "skipped_20",
		},
	}) with input.attestations as test_results

	lib.assert_equal_results(test.warn, {
		{
			"code": "test.no_test_warnings",
			"msg": "Test \"warning_1\" returned a warning",
			"term": "warning_1",
		},
		{
			"code": "test.no_test_warnings",
			"msg": "Test \"warning_2\" returned a warning",
			"term": "warning_2",
		},
		{
			"code": "test.no_test_warnings",
			"msg": "Test \"warning_20\" returned a warning",
			"term": "warning_20",
		},
	}) with input.attestations as test_results
}

test_unsupported_test_result {
	test_results := [
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "EROR"}, "error_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCESS"}, "success_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "FAIL"}, "failure_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SKIPED"}, "skipped_1", _bundle),
		lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("skipped_20", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "SKIPED"},
		}])]),
	]

	lib.assert_equal_results(test.deny, {
		{
			"code": "test.test_results_known",
			"msg": "Test 'error_1' has unsupported result 'EROR'", "term": "error_1",
		},
		{
			"code": "test.test_results_known",
			"msg": "Test 'failure_1' has unsupported result 'FAIL'", "term": "failure_1",
		},
		{
			"code": "test.test_results_known",
			"msg": "Test 'skipped_1' has unsupported result 'SKIPED'", "term": "skipped_1",
		},
		{
			"code": "test.test_results_known",
			"msg": "Test 'success_1' has unsupported result 'SUCESS'", "term": "success_1",
		},
		{
			"code": "test.test_results_known",
			"msg": "Test 'skipped_20' has unsupported result 'SKIPED'", "term": "skipped_20",
		},
	}) with input.attestations as test_results
}

test_missing_wrong_attestation_type {
	pr := lib_test.att_mock_helper_ref("some-result", {"result": "value"}, "task1", _bundle)
	tr := object.union(pr, {"statement": {"predicate": {"buildType": lib.tekton_task_run}}})
	tr_result := {"name": lib.task_test_result_name, "type": "string", "value": {"result": "SKIPED"}}
	pr_slsav1 := lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("skipped_20", [tr_result])])
	tr_slsav1 := object.union(
		pr_slsav1,
		{"statement": {"predicate": {"buildDefinition": {"buildType": lib.tekton_task_run}}}},
	)

	lib.assert_empty(test.deny) with input.attestations as [tr, tr_slsav1]
}

test_wrong_attestation_type {
	pr := lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "ERROR"}, "errored_1", _bundle)
	tr := object.union(pr, {"statement": {"predicate": {"buildType": lib.tekton_task_run}}})
	tr_result := {"name": lib.task_test_result_name, "type": "string", "value": {"result": "ERROR"}}
	pr_slsav1 := lib_test.mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_result_ref("skipped_20", [tr_result])])
	tr_slsav1 := object.union(
		pr_slsav1,
		{"statement": {"predicate": {"buildDefinition": {"buildType": lib.tekton_task_run}}}},
	)
	lib.assert_empty(test.deny) with input.attestations as [tr, tr_slsav1]
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
