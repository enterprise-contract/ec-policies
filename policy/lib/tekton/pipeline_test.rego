package lib.tekton_test

import rego.v1

import data.lib
import data.lib.tekton

test_pipeline_label_selector_build_task_slsa_v1_0 if {
	task := json.patch(
		slsav1_task_result_ref(
			"build-container",
			[
				{"name": "IMAGE_URL", "type": "string", "value": "localhost:5000/repo:latest"},
				{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc"},
			],
		),
		[{"op": "add", "path": "/metadata/labels", "value": {tekton.task_label: "generic"}}],
	)

	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"resolvedDependencies": resolved_dependencies([task]),
			"internalParameters": {"labels": {tekton.pipeline_label: "ignored"}},
		}},
	}}

	lib.assert_equal(tekton.pipeline_label_selector(attestation), "generic")
}

test_pipeline_label_selector_build_task_slsa_v0_2 if {
	task := {
		"ref": {"name": "build-container", "kind": "Task"},
		"results": [
			{"name": "IMAGE_URL", "type": "string", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc"},
		],
		"invocation": {"environment": {"labels": {tekton.task_label: "generic"}}},
	}

	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildConfig": {"tasks": [task]},
			"invocation": {"environment": {"labels": {tekton.pipeline_label: "ignored"}}},
		},
	}}

	lib.assert_equal(tekton.pipeline_label_selector(attestation), "generic")
}

test_pipeline_label_selector_pipeline_run_slsa_v1_0 if {
	task := slsav1_task_result_ref("build-container", [
		{"name": "IMAGE_URL", "type": "string", "value": "localhost:5000/repo:latest"},
		{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc"},
	])

	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"resolvedDependencies": resolved_dependencies([task]),
			"internalParameters": {"labels": {tekton.pipeline_label: "generic"}},
		}},
	}}

	lib.assert_equal(tekton.pipeline_label_selector(attestation), "generic")
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
			"invocation": {"environment": {"labels": {tekton.pipeline_label: "generic"}}},
		},
	}}

	lib.assert_equal(tekton.pipeline_label_selector(attestation), "generic")
}

test_pipeline_label_selector_pipeline_definition if {
	pipeline := {"metadata": {"labels": {tekton.pipeline_label: "generic"}}}
	lib.assert_equal(tekton.pipeline_label_selector(pipeline), "generic")
}

test_fbc_pipeline_label_selector if {
	image := {"config": {"Labels": {"operators.operatorframework.io.index.configs.v1": "/configs"}}}
	lib.assert_equal(tekton.pipeline_label_selector({}), "fbc") with input.image as image
}
