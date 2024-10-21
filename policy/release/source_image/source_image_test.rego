package source_image_test

import rego.v1

import data.lib
import data.source_image

test_success if {
	_mock_digest_nl := sprintf("%s\n", [_mock_digest])

	slsa_v02_attestation := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [
			{
				"name": "source-build-p1",
				"ref": {"kind": "Task", "name": "source-build"},
				"results": [
					{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo:v0.2"},
					{"name": "SOURCE_IMAGE_DIGEST", "value": _mock_digest},
				],
			},
			{
				"name": "source-build-p2",
				"ref": {"kind": "Task", "name": "source-build"},
				"results": [
					{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo:v0.2.newline\n"},
					{"name": "SOURCE_IMAGE_DIGEST", "value": _mock_digest_nl},
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
							{"name": "SOURCE_IMAGE_DIGEST", "value": _mock_digest},
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
							{"name": "SOURCE_IMAGE_DIGEST", "value": _mock_digest_nl},
						]},
					})),
				},
			],
		}},
	}}

	attestations := [slsa_v02_attestation, slsa_v1_attestation]

	lib.assert_empty(source_image.deny) with input.attestations as attestations
		with ec.oci.image_manifest as mock_ec_oci_image_manifest
		with ec.sigstore.verify_image as _mock_verify_image
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
				{"name": "SOURCE_IMAGE_DIGEST", "value": _mock_digest},
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
						{"name": "SOURCE_IMAGE_DIGEST", "value": _mock_digest},
					]},
				})),
			}],
		}},
	}}

	attestations := [slsa_v02_attestation, slsa_v1_attestation]

	expected := {
		{
			"code": "source_image.exists",
			"msg": sprintf("Unable to access source image \"registry.local/repo:v0.2@%s\"", [_mock_digest]),
		},
		{
			"code": "source_image.exists",
			"msg": sprintf("Unable to access source image \"registry.local/repo:v1.0@%s\"", [_mock_digest]),
		},
	}

	lib.assert_equal_results(expected, source_image.deny) with input.attestations as attestations
		with ec.oci.image_manifest as false
		with ec.sigstore.verify_image as _mock_verify_image
}

test_empty_source_image if {
	slsa_v02_attestation := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{
			"name": "source-build-p",
			"ref": {"kind": "Task", "name": "source-build"},
			"results": [
				{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo:v0.2"},
				{"name": "SOURCE_IMAGE_DIGEST", "value": _mock_digest},
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
						{"name": "SOURCE_IMAGE_DIGEST", "value": _mock_digest},
					]},
				})),
			}],
		}},
	}}

	attestations := [slsa_v02_attestation, slsa_v1_attestation]

	expected := {
		{
			"code": "source_image.exists",
			"msg": sprintf("Source image has no layers \"registry.local/repo:v0.2@%s\"", [_mock_digest]),
		},
		{
			"code": "source_image.exists",
			"msg": sprintf("Source image has no layers \"registry.local/repo:v1.0@%s\"", [_mock_digest]),
		},
	}

	lib.assert_equal_results(expected, source_image.deny) with input.attestations as attestations
		with ec.oci.image_manifest as {"schemaVersion": 2}
		with ec.sigstore.verify_image as _mock_verify_image
}

test_missing_signature if {
	slsa_v02_attestation := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{
			"name": "source-build-p1",
			"ref": {"kind": "Task", "name": "source-build"},
			"results": [
				{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo:v0.2"},
				{"name": "SOURCE_IMAGE_DIGEST", "value": _mock_digest},
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
						{"name": "SOURCE_IMAGE_DIGEST", "value": _mock_digest},
					]},
				})),
			}],
		}},
	}}

	attestations := [slsa_v02_attestation, slsa_v1_attestation]

	expected := {
		{
			"code": "source_image.signed",
			# regal ignore:line-length
			"msg": "Image signature verification failed for registry.local/repo:v0.2@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb: kaboom!",
		},
		{
			"code": "source_image.signed",
			"effective_on": "2022-01-01T00:00:00Z",
			# regal ignore:line-length
			"msg": "Image signature verification failed for registry.local/repo:v1.0@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb: kaboom!",
		},
	}

	lib.assert_equal_results(expected, source_image.deny) with input.attestations as attestations
		with ec.oci.image_manifest as mock_ec_oci_image_manifest
		with ec.sigstore.verify_image as {"errors": ["kaboom!"]}
}

mock_ec_oci_image_manifest(img) := manifest if {
	not contains(img, "\n")
	manifest := {"layers": [{
		"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
		"digest": "sha256:5144a0f6888523858d83d86a1a83871097723ada53fbb570130f1458b2ea4124",
		"size": 606587,
	}]}
}

_mock_digest := "sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

_mock_verify_image(_, _) := {"errors": []}
