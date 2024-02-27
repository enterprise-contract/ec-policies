package lib.tkn.recorded_att_test

import rego.v1

import data.lib

test_slsa_v02_task_extraction if {
	lib.assert_equal(
		[t |
			some task in lib.tkn.tasks({"statement": input})
			t := lib.tkn.task_data(task)
		],
		[
			{"name": "mock-av-scanner"},
			{"name": "<NAMELESS>"},
			{
				# regal ignore:line-length
				"bundle": "quay.io/lucarval/test-policies-chains@sha256:ae5952d5aac1664fbeae9191d9445244051792af903d28d3e0084e9d9b7cce61",
				"name": "mock-build",
			},
			{"name": "mock-git-clone"},
		],
	) with input as lib.tkn.recorded_att_test.att_01_slsa_v0_2_pipeline_in_cluster
}

test_slsa_v1_task_extraction if {
	lib.assert_equal(
		[t |
			some task in lib.tkn.tasks({"statement": input})
			t := lib.tkn.task_data(task)
		],
		[
			{"name": "mock-git-clone"},
			{"name": "mock-av-scanner"},
			{"name": "<NAMELESS>"},
			{
				# regal ignore:line-length
				"bundle": "quay.io/lucarval/test-policies-chains@sha256:b766741b8b3e135e4e31281aa4b25899e951798b5f213cc4a5360d01eb9b6880",
				"name": "mock-build",
			},
		],
	) with input as lib.tkn.recorded_att_test.att_05_slsa_v1_0_tekton_build_type_pipeline_in_cluster
}
