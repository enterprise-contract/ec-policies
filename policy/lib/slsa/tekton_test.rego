package slsa.tekton_test

import data.lib
import data.slsa.tekton

import future.keywords.contains
import future.keywords.if
import future.keywords.in

test_task_list if {
	tasks_v02 := tekton.tasks(data.slsa.tekton.test_data.att_01_SLSA_v0_2_Pipeline_in_cluster.predicate)
	tasks_v1 := tekton.tasks(data.slsa.tekton.test_data.att_05_SLSA_v1_0_tekton_build_type_Pipeline_in_cluster.predicate)

	lib.assert_equal(
		["git-clone", "scan", "build"],
		[n |
			some t in tasks_v02
			n := t.pipeline_task_name
		],
	)

	lib.assert_equal(
		["git-clone", "scan", "build"],
		[n |
			some t in tasks_v1
			n := t.pipeline_task_name
		],
	)
}
