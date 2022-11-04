package policy.pipeline.required_tasks

import data.lib

mock_taskref_data(task_ref_names) = d {
	d := [x |
		name := task_ref_names[_]
		x := {"taskRef": {"name": name}}
	]
}

all_required_task_refs := [
	"clamav-scan",
	"conftest-clair",
	"get-clair-scan",
	"sanity-inspect-image",
	"sanity-label-check",
	"sast-go",
	"sast-java-sec-check",
	"sbom-json-check",
]

all_bar_two := array.slice(all_required_task_refs, 2, count(all_required_task_refs))

test_passing {
	lib.assert_empty(deny) with input.spec.tasks as mock_taskref_data(all_required_task_refs)
		with input.kind as "Pipeline"
}

test_failing {
	lib.assert_equal(deny, {{
		"code": "required_tasks",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Required tasks 'clamav-scan', 'conftest-clair' were not found in the pipeline's task list",
	}}) with input.kind as "Pipeline" with input.spec.tasks as mock_taskref_data(all_bar_two)
}

test_edge_cases {
	failure_msg_end := "not found in the pipeline's task list"

	# No tasks at all
	endswith(deny[_].msg, failure_msg_end) with input.kind as "Pipeline"

	# Task list is empty
	endswith(deny[_].msg, failure_msg_end) with input.kind as "Pipeline" with input.spec.tasks as []

	# A task without a taskRef
	endswith(deny[_].msg, failure_msg_end) with input.kind as "Pipeline" with input.spec.tasks as [{"foo": "bar"}]

	# A task without a taskRef name
	endswith(deny[_].msg, failure_msg_end) with input.kind as "Pipeline" with input.spec.tasks as [{"taskRef": {"foo": "bar"}}]
}
