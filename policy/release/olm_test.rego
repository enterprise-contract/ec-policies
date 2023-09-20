package policy.release.olm_test

import future.keywords.if

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
	}},
	"spec": {
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
		with input.image.config.Labels as {olm.olm_manifestv1: "manifests/"}
}

test_all_good_custom_dir if {
	lib.assert_empty(olm.deny) with input.image.files as {"other/csv.yaml": manifest}
		with input.image.config.Labels as {olm.olm_manifestv1: "other/"}
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
		with input.image.config.Labels as {olm.olm_manifestv1: "manifests/"}
}
