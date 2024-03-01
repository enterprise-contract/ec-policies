package policy.release.source_image_test

import rego.v1

import data.lib
import data.policy.release.source_image

test_success if {
	slsa_v02_attestation := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [
			{
				"name": "source-build-p1",
				"ref": {"kind": "Task", "name": "source-build"},
				"results": [
					{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo:v0.2"},
					{"name": "SOURCE_IMAGE_DIGEST", "value": "sha256:digest"},
				],
			},
			{
				"name": "source-build-p2",
				"ref": {"kind": "Task", "name": "source-build"},
				"results": [
					{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo:v0.2.newline\n"},
					{"name": "SOURCE_IMAGE_DIGEST", "value": "sha256:digest\n"},
				],
			},
		]},
	}}}

	slsa_v1_attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
			"resolvedDependencies": [
				{
					"name": "pipelineTask",
					"content": base64.encode(json.marshal({
						"spec": {"taskRef": {
							"name": "source-build",
							"kind": "Task",
						}},
						"status": {"taskResults": [
							{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo:v1.0"},
							{"name": "SOURCE_IMAGE_DIGEST", "value": "sha256:digest"},
						]},
					})),
				},
				{
					"name": "pipelineTask",
					"content": base64.encode(json.marshal({
						"spec": {"taskRef": {
							"name": "source-build",
							"kind": "Task",
						}},
						"status": {"taskResults": [
							{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo:v1.0.newline\n"},
							{"name": "SOURCE_IMAGE_DIGEST", "value": "sha256:digest\n"},
						]},
					})),
				},
			],
		}},
	}}

	attestations := [slsa_v02_attestation, slsa_v1_attestation]

	lib.assert_empty(source_image.deny) with input.attestations as attestations
		with ec.oci.image_manifest as mock_ec_oci_image_manifest
}

test_missing_source_image_references if {
	expected := {{"code": "source_image.exists", "msg": "No source image references found"}}

	# SLSA v0.2
	lib.assert_equal_results(expected, source_image.deny) with input.attestations as [{"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{
			"name": "source-build-p",
			"ref": {"kind": "Task", "name": "source-build"},
			"results": [{"name": "SPAM", "value": "spam"}],
		}]},
	}}}]

	# SLSA v1.0
	lib.assert_equal_results(expected, source_image.deny) with input.attestations as [{"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
			"resolvedDependencies": [{
				"name": "pipelineTask",
				"content": base64.encode(json.marshal({
					"spec": {"taskRef": {
						"name": "source-build",
						"kind": "Task",
					}},
					"status": {"taskResults": [{"name": "SPAM", "value": "spam"}]},
				})),
			}],
		}},
	}}]
}

test_inaccessible_source_image_references if {
	slsa_v02_attestation := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{
			"name": "source-build-p",
			"ref": {"kind": "Task", "name": "source-build"},
			"results": [
				{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo:v0.2"},
				{"name": "SOURCE_IMAGE_DIGEST", "value": "sha256:digest"},
			],
		}]},
	}}}

	slsa_v1_attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
			"resolvedDependencies": [{
				"name": "pipelineTask",
				"content": base64.encode(json.marshal({
					"spec": {"taskRef": {
						"name": "source-build",
						"kind": "Task",
					}},
					"status": {"taskResults": [
						{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo:v1.0"},
						{"name": "SOURCE_IMAGE_DIGEST", "value": "sha256:digest"},
					]},
				})),
			}],
		}},
	}}

	attestations := [slsa_v02_attestation, slsa_v1_attestation]

	expected := {
		{
			"code": "source_image.exists",
			"msg": "Unable to access source image \"registry.local/repo:v0.2@sha256:digest\"",
		},
		{
			"code": "source_image.exists",
			"msg": "Unable to access source image \"registry.local/repo:v1.0@sha256:digest\"",
		},
	}

	lib.assert_equal_results(expected, source_image.deny) with input.attestations as attestations
		with ec.oci.image_manifest as false
}

test_empty_source_image if {
	slsa_v02_attestation := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{
			"name": "source-build-p",
			"ref": {"kind": "Task", "name": "source-build"},
			"results": [
				{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo:v0.2"},
				{"name": "SOURCE_IMAGE_DIGEST", "value": "sha256:digest"},
			],
		}]},
	}}}

	slsa_v1_attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
			"resolvedDependencies": [{
				"name": "pipelineTask",
				"content": base64.encode(json.marshal({
					"spec": {"taskRef": {
						"name": "source-build",
						"kind": "Task",
					}},
					"status": {"taskResults": [
						{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo:v1.0"},
						{"name": "SOURCE_IMAGE_DIGEST", "value": "sha256:digest"},
					]},
				})),
			}],
		}},
	}}

	attestations := [slsa_v02_attestation, slsa_v1_attestation]

	expected := {
		{
			"code": "source_image.exists",
			"msg": "Source image has no layers \"registry.local/repo:v0.2@sha256:digest\"",
		},
		{
			"code": "source_image.exists",
			"msg": "Source image has no layers \"registry.local/repo:v1.0@sha256:digest\"",
		},
	}

	lib.assert_equal_results(expected, source_image.deny) with input.attestations as attestations
		with ec.oci.image_manifest as {"schemaVersion": 2}
}

mock_ec_oci_image_manifest(img) := manifest if {
	not contains(img, "\n")
	manifest := {"layers": [{
		"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
		"digest": "sha256:5144a0f6888523858d83d86a1a83871097723ada53fbb570130f1458b2ea4124",
		"size": 606587,
	}]}
}
