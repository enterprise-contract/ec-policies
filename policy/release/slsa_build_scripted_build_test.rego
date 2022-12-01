package policy.release.slsa_build_scripted_build

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.bundles

test_all_good if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": _image_url},
			{"name": "IMAGE_DIGEST", "value": _image_digest},
		],
		"ref": {"bundle": bundles.acceptable_bundle_ref},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	lib.assert_empty(deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [_mock_attestation(tasks)]
}

# It's unclear if this should be allowed or not. This unit test exists to
# highlight the current behavior.
test_scattered_results if {
	tasks := [
		{
			"results": [{"name": "IMAGE_URL", "value": _image_url}],
			"ref": {"bundle": bundles.acceptable_bundle_ref},
			"steps": [{"entrypoint": "/bin/bash"}],
		},
		{
			"results": [{"name": "IMAGE_DIGEST", "value": _image_digest}],
			"ref": {"bundle": bundles.acceptable_bundle_ref},
			"steps": [{"entrypoint": "/bin/bash"}],
		},
	]

	expected := {{
		"code": "missing_build_task",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Build task not found",
	}}

	lib.assert_equal(expected, deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [_mock_attestation(tasks)]
}

test_missing_task_steps if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": _image_url},
			{"name": "IMAGE_DIGEST", "value": _image_digest},
		],
		"ref": {"bundle": bundles.acceptable_bundle_ref},
		# "steps" is not defined
	}]

	expected := {{
		"code": "empty_build_task",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Build task \"buildah\" does not contain any steps",
	}}

	lib.assert_equal(expected, deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [_mock_attestation(tasks)]
}

test_empty_task_steps if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": _image_url},
			{"name": "IMAGE_DIGEST", "value": _image_digest},
		],
		"ref": {"bundle": bundles.acceptable_bundle_ref},
		"steps": [],
	}]

	expected := {{
		"code": "empty_build_task",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Build task \"buildah\" does not contain any steps",
	}}

	lib.assert_equal(expected, deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [_mock_attestation(tasks)]
}

test_unacceptable_bundle if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": _image_url},
			{"name": "IMAGE_DIGEST", "value": _image_digest},
		],
		"ref": {"bundle": "registry.img/unacceptable@sha256:digest"},
		"steps": [],
	}]

	expected := {{
		"code": "missing_build_task",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Build task not found",
	}}

	lib.assert_equal(expected, deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [_mock_attestation(tasks)]
}

test_results_missing_value_url if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"bundle": bundles.acceptable_bundle_ref},
		"steps": [],
	}]

	expected := {{
		"code": "missing_build_task",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Build task not found",
	}}

	lib.assert_equal(expected, deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [_mock_attestation(tasks)]
}

test_results_missing_value_digest if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": "url"},
			{"name": "IMAGE_DIGEST"},
		],
		"ref": {"bundle": bundles.acceptable_bundle_ref},
		"steps": [],
	}]

	expected := {{
		"code": "missing_build_task",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Build task not found",
	}}

	lib.assert_equal(expected, deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [_mock_attestation(tasks)]
}

test_results_empty_value_url if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": ""},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"bundle": bundles.acceptable_bundle_ref},
		"steps": [],
	}]

	expected := {{
		"code": "missing_build_task",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Build task not found",
	}}

	lib.assert_equal(expected, deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [_mock_attestation(tasks)]
}

test_results_empty_value_digest if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": "url"},
			{"name": "IMAGE_DIGEST", "value": ""},
		],
		"ref": {"bundle": bundles.acceptable_bundle_ref},
		"steps": [],
	}]

	expected := {{
		"code": "missing_build_task",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Build task not found",
	}}

	lib.assert_equal(expected, deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [_mock_attestation(tasks)]
}

test_subject_mismatch if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": _image_url},
			{"name": "IMAGE_DIGEST", "value": "sha256:anotherdigest"},
		],
		"ref": {"bundle": bundles.acceptable_bundle_ref},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	expected := {{
		"code": "subject_build_task_mismatch",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "The attestation subject, \"some.image/foo:bar@sha256:123\", does not match the build task image, \"some.image/foo:bar@sha256:anotherdigest\"",
	}}

	lib.assert_equal(expected, deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [_mock_attestation(tasks)]
}

test_subject_with_tag_and_digest_is_good if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": "registry.io/repository/image:tag"},
			{"name": "IMAGE_DIGEST", "value": "sha256:digest"},
		],
		"ref": {"bundle": bundles.acceptable_bundle_ref},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	lib.assert_empty(deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{
			"subject": [{
				"name": "registry.io/repository/image",
				"digest": {"sha256": "digest"},
			}],
			"predicate": {
				"buildType": lib.pipelinerun_att_build_types[0],
				"buildConfig": {"tasks": tasks},
			},
		}]
}

test_subject_with_tag_and_digest_mismatch_tag_is_good if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": "registry.io/repository/image:tag"},
			{"name": "IMAGE_DIGEST", "value": "sha256:digest"},
		],
		"ref": {"bundle": bundles.acceptable_bundle_ref},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	lib.assert_empty(deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{
			"subject": [{
				"name": "registry.io/repository/image:different",
				"digest": {"sha256": "digest"},
			}],
			"predicate": {
				"buildType": lib.pipelinerun_att_build_types[0],
				"buildConfig": {"tasks": tasks},
			},
		}]
}

test_subject_with_tag_and_digest_mismatch_digest_fails if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": "registry.io/repository/image:tag"},
			{"name": "IMAGE_DIGEST", "value": "sha256:digest"},
		],
		"ref": {"bundle": bundles.acceptable_bundle_ref},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	expected := {{
		"code": "subject_build_task_mismatch",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "The attestation subject, \"registry.io/repository/image@sha256:unexpected\", does not match the build task image, \"registry.io/repository/image:tag@sha256:digest\"",
	}}

	lib.assert_equal(expected, deny) with data["task-bundles"] as bundles.bundle_data
		with input.attestations as [{
			"subject": [{
				"name": "registry.io/repository/image",
				"digest": {"sha256": "unexpected"},
			}],
			"predicate": {
				"buildType": lib.pipelinerun_att_build_types[0],
				"buildConfig": {"tasks": tasks},
			},
		}]
}

_image_url := "some.image/foo:bar"

_image_digest_algorithm := "sha256"

_image_digest_value := "123"

_image_digest := concat(":", [_image_digest_algorithm, _image_digest_value])

_mock_attestation(original_tasks) = d if {
	default_task := {
		"name": "buildah",
		"ref": {"kind": "Task"},
	}

	tasks := [task |
		some original_task in original_tasks
		task := object.union(default_task, original_task)
	]

	d := {
		"subject": [{
			"name": _image_url,
			"digest": {_image_digest_algorithm: _image_digest_value},
		}],
		"predicate": {
			"buildType": lib.pipelinerun_att_build_types[0],
			"buildConfig": {"tasks": tasks},
		},
	}
}
