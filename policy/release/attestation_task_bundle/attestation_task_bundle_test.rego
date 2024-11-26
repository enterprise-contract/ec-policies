package attestation_task_bundle_test

import rego.v1

import data.attestation_task_bundle
import data.lib
import data.lib.tekton_test
import data.lib_test

mock_data(task) := {"statement": {"predicate": {
	"buildConfig": {"tasks": [task]},
	"buildType": lib.tekton_pipeline_run,
}}}

test_bundle_not_exists if {
	name := "my-task"
	attestations := [
		mock_data({
			"name": name,
			"ref": {"name": "my-task"},
		}),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task("my-task")]),
	]

	expected_msg := "Pipeline task 'my-task' does not contain a bundle reference"
	lib.assert_equal_results(attestation_task_bundle.deny, {{
		"code": "attestation_task_bundle.tasks_defined_in_bundle",
		"msg": expected_msg,
	}}) with input.attestations as attestations with data.trusted_tasks as trusted_tasks

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
}

test_bundle_not_exists_empty_string if {
	name := "my-task"
	image := ""

	attestations := [
		mock_data({
			"name": name,
			"ref": {"name": "my-task", "bundle": image},
		}),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle("my-task", image)]),
	]

	expected_msg := sprintf("Pipeline task '%s' uses an empty bundle image reference", [name])
	lib.assert_equal_results(attestation_task_bundle.deny, {{
		"code": "attestation_task_bundle.task_ref_bundles_not_empty",
		"msg": expected_msg,
	}}) with input.attestations as attestations with data.trusted_tasks as trusted_tasks

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
}

test_bundle_unpinned if {
	name := "my-task"
	image := "reg.com/repo:latest"
	attestations := [
		mock_data({
			"name": name,
			"ref": {
				"name": "my-task",
				"bundle": image,
			},
		}),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle("my-task", image)]),
	]

	expected_msg := sprintf("Pipeline task '%s' uses an unpinned task bundle reference '%s'", [name, image])
	lib.assert_equal_results(attestation_task_bundle.warn, {{
		"code": "attestation_task_bundle.task_ref_bundles_pinned",
		"msg": expected_msg,
	}}) with input.attestations as attestations with data.trusted_tasks as {}
}

test_bundle_reference_valid if {
	name := "my-task"
	image := "reg.com/repo:v2@sha256:abc"
	attestations := [
		mock_data({
			"name": name,
			"ref": {
				"name": "my-task",
				"bundle": image,
			},
		}),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle("my-task", image)]),
	]

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks

	lib.assert_empty(attestation_task_bundle.deny) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks
}

test_bundle_reference_digest_doesnt_match if {
	name := "my-task"
	image := "reg.com/repo:latest@sha256:abc"
	attestations := [
		mock_data({
			"name": name,
			"ref": {
				"name": "my-task",
				"bundle": image,
			},
		}),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle("my-task", image)]),
	]

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks

	lib.assert_equal_results(attestation_task_bundle.deny, {{
		"code": "attestation_task_bundle.task_ref_bundles_trusted",
		"msg": "Pipeline task 'my-task' uses an untrusted task bundle 'reg.com/repo:latest@sha256:abc'",
	}}) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks
}

test_bundle_reference_repo_not_present if {
	name := "my-task"
	image := "reg.com/super-custom-repo:v1@sha256:abc"
	attestations := [
		mock_data({
			"name": name,
			"ref": {
				"name": "my-task",
				"bundle": image,
			},
		}),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle("my-task", image)]),
	]

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks

	lib.assert_equal_results(attestation_task_bundle.deny, {{
		"code": "attestation_task_bundle.task_ref_bundles_trusted",
		"msg": "Pipeline task 'my-task' uses an untrusted task bundle 'reg.com/super-custom-repo:v1@sha256:abc'",
	}}) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks
}

# All good when the most recent bundle is used.
test_trusted_bundle_up_to_date if {
	image := "reg.com/repo:v2@sha256:abc"
	attestations := [
		lib_test.mock_slsav02_attestation_bundles([image]),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle("my-task", image)]),
	]

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks

	lib.assert_empty(attestation_task_bundle.deny) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks
}

# Warn about out of date bundles that are still trusted.
test_trusted_bundle_out_of_date_past if {
	images := ["reg.com/repo:v2@sha256:bcd"]
	attestations := [
		lib_test.mock_slsav02_attestation_bundles(images),
		lib_test.mock_slsav1_attestation_bundles(images, "task-run-0"),
	]

	lib.assert_equal_results(attestation_task_bundle.warn, {{
		"code": "attestation_task_bundle.task_ref_bundles_current",
		# regal ignore:line-length
		"msg": "Pipeline task 'task-run-0' uses an out of date task bundle 'reg.com/repo:v2@sha256:bcd', new version of the Task must be used before 2022-04-11T00:00:00Z",
	}}) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2022-03-12T00:00:00Z")

	lib.assert_empty(attestation_task_bundle.deny) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2022-03-12T00:00:00Z")
}

# Deny bundles that are no longer active.
test_trusted_bundle_expired if {
	image := ["reg.com/repo:v1@sha256:def"]
	attestations := [
		lib_test.mock_slsav02_attestation_bundles(image),
		lib_test.mock_slsav1_attestation_bundles(image, "task-run-0"),
	]
	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks

	lib.assert_equal_results(attestation_task_bundle.deny, {{
		"code": "attestation_task_bundle.task_ref_bundles_trusted",
		"msg": "Pipeline task 'task-run-0' uses an untrusted task bundle 'reg.com/repo:v1@sha256:def'",
	}}) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks
}

test_trusted_bundles_provided if {
	expected := {{
		"code": "attestation_task_bundle.trusted_bundles_provided",
		"msg": "Missing required trusted_tasks data",
	}}
	lib.assert_equal_results(expected, attestation_task_bundle.deny) with data.trusted_tasks as {}
}

test_warn_cases if {
	trusted_tasks := {"oci://q.io/r/task-buildah:0.1": [
		{"ref": "sha256:c37e54", "effective_on": "2023-11-06T00:00:00Z"},
		{"ref": "sha256:97f216", "effective_on": "2023-10-25T00:00:00Z", "expires_on": "2023-11-06T00:00:00Z"},
		{"ref": "sha256:487b82", "effective_on": "2023-10-21T00:00:00Z", "expires_on": "2023-10-25T00:00:00Z"},
	]}

	attestation_c37e54 := mock_data({"ref": {
		"name": "buildah",
		"bundle": "q.io/r/task-buildah:0.1@sha256:c37e54",
	}})

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as [attestation_c37e54]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-11-07T00:00:00Z")
	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as [attestation_c37e54]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-11-06T00:00:00Z")
	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as [attestation_c37e54]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-11-05T00:00:00Z")
	attestation_97f216 := mock_data({"name": "buildah", "ref": {
		"name": "buildah",
		"bundle": "q.io/r/task-buildah:0.1@sha256:97f216",
	}})

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as [attestation_97f216]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-11-07T00:00:00Z")
	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as [attestation_97f216]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-11-06T00:00:00Z")

	expected_97f216 := {{
		"code": "attestation_task_bundle.task_ref_bundles_current",
		# regal ignore:line-length
		"msg": "Pipeline task 'buildah' uses an out of date task bundle 'q.io/r/task-buildah:0.1@sha256:97f216', new version of the Task must be used before 2023-11-06T00:00:00Z",
	}}

	lib.assert_equal_results(
		expected_97f216,
		attestation_task_bundle.warn,
	) with input.attestations as [attestation_97f216]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-11-05T00:00:00Z")
	lib.assert_equal_results(
		expected_97f216,
		attestation_task_bundle.warn,
	) with input.attestations as [attestation_97f216]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-10-25T00:00:00Z")

	attestation_487b82 := mock_data({"name": "buildah", "ref": {
		"name": "buildah",
		"bundle": "q.io/r/task-buildah:0.1@sha256:487b82",
	}})

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as [attestation_487b82]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-11-07T00:00:00Z")
	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as [attestation_487b82]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-11-06T00:00:00Z")
	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as [attestation_487b82]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-11-05T00:00:00Z")
	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as [attestation_487b82]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-10-25T00:00:00Z")

	expected_487b82 := {{
		"code": "attestation_task_bundle.task_ref_bundles_current",
		# regal ignore:line-length
		"msg": "Pipeline task 'buildah' uses an out of date task bundle 'q.io/r/task-buildah:0.1@sha256:487b82', new version of the Task must be used before 2023-10-25T00:00:00Z",
	}}

	lib.assert_equal_results(
		expected_487b82,
		attestation_task_bundle.warn,
	) with input.attestations as [attestation_487b82]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-10-21T00:00:00Z")
	lib.assert_equal_results(
		expected_487b82,
		attestation_task_bundle.warn,
	) with input.attestations as [attestation_487b82]
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-10-22T00:00:00Z")
}

test_ec316 if {
	image_ref := "registry.io/repository/image:0.3@sha256:abc"
	attestations := [
		mock_data({
			"name": "my-task",
			"ref": {"name": "my-task", "bundle": image_ref},
		}),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle("my-task", image_ref)]),
	]

	trusted_tasks := {
		"oci://registry.io/repository/image:0.1": [{"ref": "sha256:abc", "effective_on": "2024-02-02T00:00:00Z"}],
		"oci://registry.io/repository/image:0.2": [{"ref": "sha256:abc", "effective_on": "2024-02-02T00:00:00Z"}],
		"oci://registry.io/repository/image:0.3": [
			{"ref": "sha256:abc", "effective_on": "2024-02-02T00:00:00Z"},
			{"ref": "sha256:abc", "effective_on": "2024-01-21T00:00:00Z"},
			{"ref": "sha256:abc", "effective_on": "2024-01-21T00:00:00Z"},
		],
	}

	lib.assert_empty(attestation_task_bundle.warn) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks

	lib.assert_empty(attestation_task_bundle.deny) with input.attestations as attestations
		with data.trusted_tasks as trusted_tasks
}

trusted_tasks := {
	"oci://reg.com/repo:v2": [
		# Latest v2
		{"ref": "sha256:abc", "effective_on": "2022-04-11T00:00:00Z"},
		# Older v2
		{"ref": "sha256:bcd", "effective_on": "2022-03-11T00:00:00Z", "expires_on": "2022-04-11T00:00:00Z"},
	],
	"oci://reg.com/repo:v1": [
		# Latest v1
		{"ref": "sha256:cde", "effective_on": "2022-02-01T00:00:00Z"},
		# Older v1
		{"ref": "sha256:def", "effective_on": "2021-01-01T00:00:00Z", "expires_on": "2022-02-01T00:00:00Z"},
	],
}
