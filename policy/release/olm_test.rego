package policy.release.olm_test

import rego.v1

import data.lib
import data.policy.release.olm

pinned := "registry.io/repository/image@sha256:cafe"

pinned2 := "registry.io/repository/image2@sha256:tea"

pinned_ref := {"digest": "sha256:cafe", "repo": "registry.io/repository/image", "tag": ""}

pinned_ref2 := {"digest": "sha256:tea", "repo": "registry.io/repository/image2", "tag": ""}

component1 := {
	"name": "Unnamed",
	"containerImage": pinned,
	"source": {},
}

component2 := {
	"name": "pinned_image2",
	"containerImage": pinned2,
	"source": {},
}

unpinned_component := {
	"name": "unpinned_image",
	"containerImage": "registry.io/repo/msd:no_digest",
	"source": {},
}

manifest := {
	"apiVersion": "operators.coreos.com/v1alpha1",
	"kind": "ClusterServiceVersion",
	"metadata": {"annotations": {
		"containerImage": pinned,
		"enclosurePicture": sprintf("%s,  %s", [pinned, pinned2]),
		"features.operators.openshift.io/disconnected": "true",
		"features.operators.openshift.io/fips-compliant": "true",
		"features.operators.openshift.io/proxy-aware": "true",
		"features.operators.openshift.io/cnf": "false",
		"features.operators.openshift.io/cni": "false",
		"features.operators.openshift.io/csi": "false",
		"features.operators.openshift.io/tls-profiles": "false",
		"features.operators.openshift.io/token-auth-aws": "false",
		"features.operators.openshift.io/token-auth-azure": "false",
		"features.operators.openshift.io/token-auth-gcp": "false",
		"operators.openshift.io/valid-subscription": `["spam"]`,
	}},
	"spec": {
		"version": "0.1.3",
		"relatedImages": [{"image": pinned}],
		"install": {"spec": {"deployments": [{
			"metadata": {"annotations": {"docket": sprintf("%s\n  %s", [pinned, pinned2])}},
			"spec": {"template": {
				"metadata": {"name": "c1"},
				"spec": {
					"containers": [{
						"name": "c1",
						"image": pinned,
						"env": [{"name": "RELATED_IMAGE_C1", "value": pinned}],
					}],
					"initContainers": [{
						"name": "i1",
						"image": pinned,
						"env": [{"name": "RELATED_IMAGE_E1", "value": pinned}],
					}],
				},
			}},
		}]}},
	},
	"not-metadata": {"annotations": {"something": pinned2}},
	"metadata-without-annotations": {"metadata": {}},
	"metadata-with-empty-annotations": {"metadata": {"annotations": {}}},
}

# regal ignore:rule-length
test_all_image_ref if {
	lib.assert_equal(
		[
			{"path": "spec.relatedImages[0].image", "ref": pinned_ref},
			{"path": "annotations.containerImage", "ref": pinned_ref},
			{"path": "annotations[\"containerImage\"]", "ref": pinned_ref},
			{"path": "annotations[\"enclosurePicture\"]", "ref": pinned_ref},
			{"path": "annotations[\"enclosurePicture\"]", "ref": pinned_ref2},
			{"path": "annotations[\"docket\"]", "ref": pinned_ref},
			{"path": "annotations[\"docket\"]", "ref": pinned_ref2},
			{
				"path": `spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.containers[0 ("c1")].image`,
				"ref": pinned_ref,
			},
			{
				# regal ignore:line-length
				"path": `spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.initContainers[0 ("i1")].image`,
				"ref": pinned_ref,
			},
			{
				# regal ignore:line-length
				"path": `spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.containers[0 ("c1")].env["RELATED_IMAGE_C1"]`,
				"ref": pinned_ref,
			},
			{
				# regal ignore:line-length
				"path": `spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.initContainers[0 ("i1")].env["RELATED_IMAGE_E1"]`,
				"ref": pinned_ref,
			},
		],
		olm.all_image_ref(manifest),
	)
}

test_all_good if {
	lib.assert_empty(olm.deny) with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
}

test_all_good_custom_dir if {
	lib.assert_empty(olm.deny) with input.image.files as {"other/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "other/"}
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
}

test_related_img_unpinned if {
	unpinned_manifest = json.patch(manifest, [{
		"op": "replace",
		"path": "/spec/install/spec/deployments/0/spec/template/spec/containers/0/env/0/value",
		"value": "registry.io/repository:tag",
	}])

	expected = {{
		"code": "olm.unpinned_references",
		# regal ignore:line-length
		"msg": `The "registry.io/repository:tag" image reference is not pinned at spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.containers[0 ("c1")].env["RELATED_IMAGE_C1"].`,
		"term": "registry.io/repository:tag",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": unpinned_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
}

test_feature_annotations_format if {
	bad_manifest := json.patch(manifest, [
		{"op": "add", "path": "/metadata/annotations/features.operators.openshift.io~1disconnected", "value": false},
		{"op": "add", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant", "value": true},
		{"op": "add", "path": "/metadata/annotations/features.operators.openshift.io~1proxy-aware", "value": 1},
		{"op": "add", "path": "/metadata/annotations/features.operators.openshift.io~1cnf", "value": "True"},
		{"op": "add", "path": "/metadata/annotations/features.operators.openshift.io~1cni", "value": null},
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1tls-profiles"},
	])

	expected := {
		{
			"code": "olm.feature_annotations_format",
			# regal ignore:line-length
			"msg": "The annotation \"features.operators.openshift.io/disconnected\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/disconnected",
		},
		{
			"code": "olm.feature_annotations_format",
			# regal ignore:line-length
			"msg": "The annotation \"features.operators.openshift.io/fips-compliant\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/fips-compliant",
		},
		{
			"code": "olm.feature_annotations_format",
			"msg": "The annotation \"features.operators.openshift.io/proxy-aware\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/proxy-aware",
		},
		{
			"code": "olm.feature_annotations_format",
			"msg": "The annotation \"features.operators.openshift.io/cnf\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/cnf",
		},
		{
			"code": "olm.feature_annotations_format",
			"msg": "The annotation \"features.operators.openshift.io/cni\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/cni",
		},
		{
			"code": "olm.feature_annotations_format",
			# regal ignore:line-length
			"msg": "The annotation \"features.operators.openshift.io/tls-profiles\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/tls-profiles",
		},
	}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": bad_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
}

test_feature_annotations_format_custom_rule_data if {
	bad_manifest := json.patch(manifest, [
		{"op": "add", "path": "/metadata/annotations/foo", "value": "bar"},
		{"op": "add", "path": "/metadata/annotations/spam", "value": "true"},
	])

	expected := {{
		"code": "olm.feature_annotations_format",
		"msg": "The annotation \"foo\" is either missing or has an unexpected value", "term": "foo",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": bad_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.required_olm_features_annotations as ["foo", "spam"]
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
}

test_required_olm_features_annotations_provided if {
	expected_empty := {{
		"code": "olm.required_olm_features_annotations_provided",
		# regal ignore:line-length
		"msg": "Rule data required_olm_features_annotations has unexpected format: (Root): Array must have at least 1 items",
	}}
	lib.assert_equal_results(olm.deny, expected_empty) with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
		with data.rule_data.required_olm_features_annotations as []

	d := [
		# Wrong type
		1,
		# Duplicated items
		"foo",
		"foo",
	]

	expected := {
		{
			"code": "olm.feature_annotations_format",
			"msg": "The annotation \"foo\" is either missing or has an unexpected value",
			"term": "foo",
		},
		{
			"code": "olm.feature_annotations_format",
			"msg": "The annotation '\\x01' is either missing or has an unexpected value",
			"term": 1,
		},
		{
			"code": "olm.required_olm_features_annotations_provided",
			"msg": "Rule data required_olm_features_annotations has unexpected format: (Root): array items[1,2] must be unique",
		},
		{
			"code": "olm.required_olm_features_annotations_provided",
			# regal ignore:line-length
			"msg": "Rule data required_olm_features_annotations has unexpected format: 0: Invalid type. Expected: string, given: integer",
		},
	}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
		with data.rule_data.required_olm_features_annotations as d
}

test_csv_semver_format_bad_semver if {
	csv := json.patch(manifest, [{"op": "add", "path": "/spec/version", "value": "spam"}])

	expected := {{
		"code": "olm.csv_semver_format",
		"msg": "The ClusterServiceVersion spec.version, \"spam\", is not a valid semver",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": csv}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
}

test_csv_semver_format_missing if {
	csv := json.patch(manifest, [{"op": "remove", "path": "/spec/version"}])

	expected := {{
		"code": "olm.csv_semver_format",
		"msg": "The ClusterServiceVersion spec.version, \"<MISSING>\", is not a valid semver",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": csv}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
}

test_subscriptions_annotation_format if {
	path := "/metadata/annotations/operators.openshift.io~1valid-subscription"
	files := {
		"m/csv-no-annotations.yaml": json.patch(manifest, [{"op": "remove", "path": "/metadata/annotations"}]),
		"m/csv-invalid-json.yaml": json.patch(manifest, [{"op": "add", "path": path, "value": "invalid-json"}]),
		"m/csv-empty.yaml": json.patch(manifest, [{"op": "add", "path": path, "value": "[]"}]),
		"m/csv-dupes.yaml": json.patch(manifest, [{"op": "add", "path": path, "value": `["spam", "spam"]`}]),
		"m/csv-bad-type.yaml": json.patch(manifest, [{"op": "add", "path": path, "value": "[1]"}]),
	}

	expected := {
		{
			"code": "olm.subscriptions_annotation_format",
			"msg": "Value of operators.openshift.io/valid-subscription annotation is missing",
		},
		{
			"code": "olm.subscriptions_annotation_format",
			"msg": "Value of operators.openshift.io/valid-subscription annotation is not valid JSON",
		},
		{
			"code": "olm.subscriptions_annotation_format",
			# regal ignore:line-length
			"msg": "Value of operators.openshift.io/valid-subscription annotation is invalid: (Root): Array must have at least 1 items",
		},
		{
			"code": "olm.subscriptions_annotation_format",
			# regal ignore:line-length
			"msg": "Value of operators.openshift.io/valid-subscription annotation is invalid: (Root): array items[0,1] must be unique",
		},
		{
			"code": "olm.subscriptions_annotation_format",
			# regal ignore:line-length
			"msg": "Value of operators.openshift.io/valid-subscription annotation is invalid: 0: Invalid type. Expected: string, given: integer",
		},
	}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as files
		with input.image.config.Labels as {olm.manifestv1: "m/"}
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
}

test_unpinned_snapshot_references_operator if {
	expected := {{
		"code": "olm.unpinned_snapshot_references",
		"msg": "The \"registry.io/repo/msd:no_digest\" image reference is not pinned in the input snapshot.",
		"term": "registry.io/repo/msd:no_digest",
	}}
	lib.assert_equal_results(olm.deny, expected) with input.snapshot.components as [unpinned_component, component1]
		with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
		with ec.oci.image_manifest as `{"config": {"digest": "sha256:goat"}}`
		with input.image.ref as unpinned_component.containerImage
}

test_unpinned_snapshot_references_different_input if {
	lib.assert_empty(olm.deny) with input.snapshot.components as [unpinned_component]
		with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
		with ec.oci.image_manifest as `{"config": {"digest": "sha256:goat"}}`
		with input.image.ref as pinned2
}

test_inaccessible_snapshot_references if {
	expected := {{
		"code": "olm.inaccessible_snapshot_references",
		"msg": "The \"registry.io/repository/image@sha256:cafe\" image reference is not accessible in the input snapshot.",
		"term": "registry.io/repository/image@sha256:cafe",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.snapshot.components as [component1]
		with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
		with ec.oci.image_manifest as false
}

test_unmapped_references_in_operator if {
	expected := {{
		"code": "olm.unmapped_references",
		"msg": "The \"registry.io/repository/image2@sha256:tea\" CSV image reference is not in the snapshot or accessible.",
		"term": "registry.io/repository/image2@sha256:tea",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.snapshot.components as [component1]
		with input.image.files as {"manifests/csv.yaml": manifest}
		with data.rule_data as {"pipeline_intention": "release", "allowed_registry_prefixes": ["registry.io"]}
		with ec.oci.image_manifest as mock_ec_oci_image_manifest
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
}

mock_ec_oci_image_manifest("registry.io/repository/image@sha256:cafe") := `{"config": {"digest": "sha256:cafe"}}`

mock_ec_oci_image_manifest("registry.io/repository/image2@sha256:tea") := false

test_olm_ci_pipeline if {
	# Make sure no violations are thrown if it isn't a release pipeline
	lib.assert_equal(false, olm._release_restrictions_apply) with data.rule_data as {"pipeline_intention": null}
}

test_unmapped_references_none_found if {
	lib.assert_empty(olm.deny) with input.snapshot.components as [component1, component2]
		with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_registry_prefixes as ["registry.io"]
}

test_allowed_registries if {
	# This should pass since registry.io is a member of allowed_registry_prefixes
	lib.assert_empty(olm.deny) with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_registry_prefixes as ["registry.io", "registry.redhat.io"]
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with input.image.files as {"manifests/csv.yaml": manifest}
}

test_unallowed_registries if {
	expected := {
		{
			"code": "olm.allowed_registries",
			# regal ignore:line-length
			"msg": "The \"registry.io/repository/image@sha256:cafe\" CSV image reference is not from an allowed registry.",
			"term": "registry.io/repository/image",
		},
		{
			"code": "olm.allowed_registries",
			# regal ignore:line-length
			"msg": "The \"registry.io/repository/image2@sha256:tea\" CSV image reference is not from an allowed registry.",
			"term": "registry.io/repository/image2",
		},
	}

	# This expects failure as registry.io is not a member of allowed_registry_prefixes
	lib.assert_equal_results(olm.deny, expected) with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_registry_prefixes as ["registry.access.redhat.com", "registry.redhat.io"]
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with input.image.files as {"manifests/csv.yaml": manifest}
}
