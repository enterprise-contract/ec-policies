package lib.tkn.pipeline_test

import data.lib
import data.lib.tkn

test_selects_label_from_slsav1 {
	attestation := {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": lib.tekton_slsav1_pipeline_run,
			"externalParameters": {"runSpec": {"pipelineRef": {"name": "pipeline1"}}},
			"internalParameters": {"labels": {"pipelines.openshift.io/runtime": "generic"}},
		}},
	}
	lib.assert_equal("generic", tkn.pipeline_label_selector(attestation, "pipelines.openshift.io/runtime"))
}

test_selects_label_from_slsav02 {
	attestation := {"predicate": {
		"buildType": lib.tekton_slsav1_pipeline_run,
		"buildConfig": {"tasks": []},
		"invocation": {"environment": {"labels": {"pipelines.openshift.io/runtime": "generic"}}},
	}}
	lib.assert_equal("generic", tkn.pipeline_label_selector(attestation, "pipelines.openshift.io/runtime"))
}

test_selects_label_from_pipeline_definition {
	attestation := {"metadata": {"labels": {"pipelines.openshift.io/runtime": "generic"}}}
	lib.assert_equal("generic", tkn.pipeline_label_selector(attestation, "pipelines.openshift.io/runtime"))
}
