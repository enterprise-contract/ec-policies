package lib.tkn.pipeline_test

import future.keywords.if

import data.lib
import data.lib.tkn
import data.lib.tkn_test

test_pipeline_label_selector_build_task_slsa_v1_0 if {
	task := json.patch(
		tkn_test.slsav1_task_result_ref(
			"build-container",
			[
				{"name": "IMAGE_URL", "type": "string", "value": "localhost:5000/repo:latest"},
				{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc"},
			],
		),
		[{"op": "add", "path": "/metadata/labels", "value": {tkn.task_label: "generic"}}],
	)

	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"resolvedDependencies": tkn_test.resolved_dependencies([task]),
			"internalParameters": {"labels": {tkn.pipeline_label: "ignored"}},
		}},
	}}

	lib.assert_equal(tkn.pipeline_label_selector(attestation), "generic")
}

test_pipeline_label_selector_build_task_slsa_v0_2 if {
	task := {
		"ref": {"name": "build-container", "kind": "Task"},
		"results": [
			{"name": "IMAGE_URL", "type": "string", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc"},
		],
		"invocation": {"environment": {"labels": {tkn.task_label: "generic"}}},
	}

	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildConfig": {"tasks": [task]},
			"invocation": {"environment": {"labels": {tkn.pipeline_label: "ignored"}}},
		},
	}}

	lib.assert_equal(tkn.pipeline_label_selector(attestation), "generic")
}

test_pipeline_label_selector_pipeline_run_slsa_v1_0 if {
	task := tkn_test.slsav1_task_result_ref("build-container", [
		{"name": "IMAGE_URL", "type": "string", "value": "localhost:5000/repo:latest"},
		{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc"},
	])

	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"resolvedDependencies": tkn_test.resolved_dependencies([task]),
			"internalParameters": {"labels": {tkn.pipeline_label: "generic"}},
		}},
	}}

	lib.assert_equal(tkn.pipeline_label_selector(attestation), "generic")
}

test_pipeline_label_selector_pipeline_run_slsa_v0_2 if {
	task := {
		"ref": {"name": "build-container", "kind": "Task"},
		"results": [
			{"name": "IMAGE_URL", "type": "string", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc"},
		],
	}

	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildConfig": {"tasks": [task]},
			"invocation": {"environment": {"labels": {tkn.pipeline_label: "generic"}}},
		},
	}}

	lib.assert_equal(tkn.pipeline_label_selector(attestation), "generic")
}

test_pipeline_label_selector_pipeline_definition if {
	pipeline := {"metadata": {"labels": {tkn.pipeline_label: "generic"}}}
	lib.assert_equal(tkn.pipeline_label_selector(pipeline), "generic")
}
