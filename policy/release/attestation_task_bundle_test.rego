package policy.release.attestation_task_bundle

import data.lib

mock_data(task) = d {
	d := [{"predicate": {
		"buildConfig": {"tasks": [task]},
		"buildType": lib.pipelinerun_att_build_type,
	}}]
}

test_bundle_not_exists {
	name := "my-task"
	d := mock_data({
		"name": name,
		"ref": {"name": "good-task"},
	})

	expected_msg := "Task 'my-task' does not contain a bundle reference"
	lib.assert_equal(deny_disallowed_task_reference, {{
		"code": "disallowed_task_reference",
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as d

	lib.assert_empty(warn_out_of_date_task_bundle) with input.attestations as d
}

test_bundle_not_exists_empty_string {
	name := "my-task"
	image := ""
	d := mock_data({
		"name": name,
		"ref": {"name": "good-task", "bundle": image},
	})

	expected_msg := sprintf("Task '%s' uses an empty bundle image reference", [name])
	lib.assert_equal(deny_empty_task_bundle_reference, {{
		"code": "empty_task_bundle_reference",
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as d

	lib.assert_empty(warn_out_of_date_task_bundle) with input.attestations as d
}

test_bundle_reference_valid {
	name := "my-task"
	image := "quay.io/redhat-appstudio/hacbs-templates-bundle:latest"
	d := mock_data({
		"name": name,
		"ref": {
			"name": "good-task",
			"bundle": image,
		},
	})

	lib.assert_empty(warn_out_of_date_task_bundle) with input.attestations as d
	lib.assert_empty(deny_empty_task_bundle_reference) with input.attestations as d
}

# All good when the most recent bundle is used.
test_acceptable_bundle_up_to_date {
	attestations := mock_attestation(["reg.com/repo@sha256:abc"])

	lib.assert_empty(warn_out_of_date_task_bundle) with input.attestations as attestations
		with data["task-bundles"] as task_bundles

	lib.assert_empty(deny_unacceptable_task_bundle) with input.attestations as attestations
		with data["task-bundles"] as task_bundles
}

# All good when the most recent bundle is used when streams are used.
test_acceptable_bundle_up_to_date_with_streams {
	attestations := mock_attestation(["reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5-2@sha256:abc"])
	lib.assert_empty(warn_out_of_date_task_bundle) with input.attestations as attestations
		with data["task-bundles"] as task_bundles

	lib.assert_empty(deny_unacceptable_task_bundle) with input.attestations as attestations
		with data["task-bundles"] as task_bundles
}

# Warn about out of date bundles that are still acceptable.
test_acceptable_bundle_out_of_date_past {
	attestations := mock_attestation(["reg.com/repo@sha256:bcd", "reg.com/repo@sha256:cde"])

	lib.assert_equal(warn_out_of_date_task_bundle, {
		{
			"code": "out_of_date_task_bundle",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Task 'task-run-0' uses an out of date task bundle 'reg.com/repo@sha256:bcd'",
		},
		{
			"code": "out_of_date_task_bundle",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Task 'task-run-1' uses an out of date task bundle 'reg.com/repo@sha256:cde'",
		},
	}) with input.attestations as attestations
		with data["task-bundles"] as task_bundles

	lib.assert_empty(deny_unacceptable_task_bundle) with input.attestations as attestations
		with data["task-bundles"] as task_bundles
}

# Warn about out of date bundles that are still acceptable when streams are used.
test_acceptable_bundle_out_of_date_past_with_streams {
	# Verify streams are honored
	attestations := mock_attestation([
		"reg.com/repo:b7d8f6ae908641f5f2309ee6a9d6b2b83a56e1af-2@sha256:bcd",
		"reg.com/repo:120dda49a6cc3b89516b491e19fe1f3a07f1427f-2@sha256:cde",
	])

	lib.assert_equal(warn_out_of_date_task_bundle, {
		{
			"code": "out_of_date_task_bundle",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Task 'task-run-0' uses an out of date task bundle 'reg.com/repo:b7d8f6ae908641f5f2309ee6a9d6b2b83a56e1af-2@sha256:bcd'",
		},
		{
			"code": "out_of_date_task_bundle",
			"effective_on": "2022-01-01T00:00:00Z",
			"msg": "Task 'task-run-1' uses an out of date task bundle 'reg.com/repo:120dda49a6cc3b89516b491e19fe1f3a07f1427f-2@sha256:cde'",
		},
	}) with input.attestations as attestations
		with data["task-bundles"] as task_bundles

	lib.assert_empty(deny_unacceptable_task_bundle) with input.attestations as attestations
		with data["task-bundles"] as task_bundles
}

# Warn about bundles that are no longer active.
test_acceptable_bundle_expired {
	attestations := mock_attestation(["reg.com/repo@sha256:def"])
	lib.assert_empty(warn_out_of_date_task_bundle) with input.attestations as attestations
		with data["task-bundles"] as task_bundles

	lib.assert_equal(deny_unacceptable_task_bundle, {{
		"code": "unacceptable_task_bundle",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Task 'task-run-0' uses an unacceptable task bundle 'reg.com/repo@sha256:def'",
	}}) with input.attestations as attestations
		with data["task-bundles"] as task_bundles
}

# Warn about bundles that are no longer active when streams are used.
test_acceptable_bundle_expired_with_streams {
	attestations := mock_attestation(["reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5-1@sha256:def"])
	lib.assert_empty(warn_out_of_date_task_bundle) with input.attestations as attestations
		with data["task-bundles"] as task_bundles

	lib.assert_equal(deny_unacceptable_task_bundle, {{
		"code": "unacceptable_task_bundle",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Task 'task-run-0' uses an unacceptable task bundle 'reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5-1@sha256:def'",
	}}) with input.attestations as attestations
		with data["task-bundles"] as task_bundles
}

test_stream {
	lib.assert_equal(_stream(""), "default")
	lib.assert_equal(_stream("spam"), "default")
	lib.assert_equal(_stream("903d49a833d22f359bce3d67b15b006e1197bae5"), "default")
	lib.assert_equal(_stream("903d49a833d22f359bce3d67b15b006e1197bae5-9-9"), "default")
	lib.assert_equal(_stream("spam-903d49a833d22f359bce3d67b15b006e1197bae5-2"), "default")

	lib.assert_equal(_stream("903d49a833d22f359bce3d67b15b006e1197bae5-2"), "2")
	lib.assert_equal(_stream("903d49a833d22f359bce3d67b15b006e1197bae5-999"), "999")
}

test_tag_by_digest {
	refs := [
		{
			"digest": "sha256:abc",
			"tag": "ignore-me",
		},
		{
			"digest": "sha256:bcd",
			"tag": "the-tag",
		},
		{
			"digest": "sha256:bcd",
			"tag": "repeat-digest",
		},
	]

	# The first match is found
	lib.assert_equal(_tag_by_digest(refs, {"digest": "sha256:bcd", "tag": ""}), "the-tag")

	# Skip search if tag is already provided
	lib.assert_equal(_tag_by_digest(refs, {"digest": "sha256:bcd", "tag": "tag-known"}), "tag-known")

	# No match found
	lib.assert_equal(_tag_by_digest(refs, {"digest": "sha256:cde", "tag": ""}), "")
}

mock_attestation(bundles) = a {
	tasks := [task |
		bundle := bundles[index]
		task := {
			"name": sprintf("task-run-%d", [index]),
			"ref": {
				"name": "my-task",
				"bundle": bundle,
			},
		}
	]

	a := [{"predicate": {
		"buildConfig": {"tasks": tasks},
		"buildType": lib.pipelinerun_att_build_type,
	}}]
}

task_bundles = {"reg.com/repo": [
	{
		"digest": "sha256:012", # Ignore
		"tag": "903d49a833d22f359bce3d67b15b006e1197bae5-1",
		"effective_on": "2262-04-11T00:00:00Z",
	},
	{
		"digest": "sha256:abc", # Allow
		"tag": "903d49a833d22f359bce3d67b15b006e1197bae5-2",
		"effective_on": "2262-04-11T00:00:00Z",
	},
	{
		"digest": "sha256:123", # Ignore
		"tag": "b7d8f6ae908641f5f2309ee6a9d6b2b83a56e1af-1",
		"effective_on": "2262-03-11T00:00:00Z",
	},
	{
		"digest": "sha256:bcd", # Warn
		"tag": "b7d8f6ae908641f5f2309ee6a9d6b2b83a56e1af-2",
		"effective_on": "2262-03-11T00:00:00Z",
	},
	{
		"digest": "sha256:234", # Ignore
		"tag": "120dda49a6cc3b89516b491e19fe1f3a07f1427f-1",
		"effective_on": "2022-02-01T00:00:00Z",
	},
	{
		"digest": "sha256:cde", # Warn
		"tag": "120dda49a6cc3b89516b491e19fe1f3a07f1427f-2",
		"effective_on": "2022-02-01T00:00:00Z",
	},
	{
		"digest": "sha256:345", # Ignore
		"tag": "903d49a833d22f359bce3d67b15b006e1197bae5-1",
		"effective_on": "2021-01-01T00:00:00Z",
	},
	{
		"digest": "sha256:def", # Warn
		"tag": "903d49a833d22f359bce3d67b15b006e1197bae5-2",
		"effective_on": "2021-01-01T00:00:00Z",
	},
]}
