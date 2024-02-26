package policy.release.olm_test

import rego.v1

import data.lib
import data.policy.release.olm

pinned := "registry.io/repository/image@sha256:cafe"

pinned2 := "registry.io/repository/image2@sha256:cafe"

pinned_ref := {"digest": "sha256:cafe", "repo": "registry.io/repository/image", "tag": ""}

pinned_ref2 := {"digest": "sha256:cafe", "repo": "registry.io/repository/image2", "tag": ""}

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
}

test_all_good_custom_dir if {
	lib.assert_empty(olm.deny) with input.image.files as {"other/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "other/"}
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
}

test_feature_annotations_format_custom_rule_data if {
	bad_manifest := json.patch(manifest, [
		{"op": "add", "path": "/metadata/annotations", "value": {"foo": "bar"}},
		{"op": "add", "path": "/metadata/annotations", "value": {"spam": "true"}},
	])

	expected := {{
		"code": "olm.feature_annotations_format",
		"msg": "The annotation \"foo\" is either missing or has an unexpected value", "term": "foo",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": bad_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.required_olm_features_annotations as ["foo", "spam"]
}

test_required_olm_features_annotations_provided if {
	expected_empty := {{
		"code": "olm.required_olm_features_annotations_provided",
		# regal ignore:line-length
		"msg": "Rule data required_olm_features_annotations has unexpected format: (Root): Array must have at least 1 items",
	}}
	lib.assert_equal_results(olm.deny, expected_empty) with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.required_olm_features_annotations as []

	d := {"required_olm_features_annotations": [
		# Wrong type
		1,
		# Duplicated items
		"foo",
		"foo",
	]}

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
		with data.rule_data as d
}

test_csv_semver_format_bad_semver if {
	csv := json.patch(manifest, [{"op": "add", "path": "/spec/version", "value": "spam"}])

	expected := {{
		"code": "olm.csv_semver_format",
		"msg": "The ClusterServiceVersion spec.version, \"spam\", is not a valid semver",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": csv}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
}

test_csv_semver_format_missing if {
	csv := json.patch(manifest, [{"op": "remove", "path": "/spec/version"}])

	expected := {{
		"code": "olm.csv_semver_format",
		"msg": "The ClusterServiceVersion spec.version, \"<MISSING>\", is not a valid semver",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": csv}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
}
