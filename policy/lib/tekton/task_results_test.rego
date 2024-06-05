package lib.tkn_test

import rego.v1

import data.lib
import data.lib.tkn

test_image_result if {
	results := [
		{
			"name": "IMAGE_URL",
			"value": "image1",
		},
		{
			"name": "IMAGE_DIGEST",
			"value": "1234",
		},
		{
			"name": "OTHER_IMAGE_URL",
			"value": "image2\n",
		},
		{
			"name": "OTHER_IMAGE_DIGEST",
			"value": "4321\n",
		},
	]
	lib.assert_equal(["image1", "image2"], tkn.task_result_artifact_url(slsav1_task_result("task1", results)))
	lib.assert_equal(["1234", "4321"], tkn.task_result_artifact_digest(slsav1_task_result("task1", results)))
}

test_artifact_result if {
	results := [
		{
			"name": "ARTIFACT_URI",
			"value": "image1",
		},
		{
			"name": "ARTIFACT_DIGEST",
			"value": "1234",
		},
		{
			"name": "OTEHR_ARTIFACT_URI",
			"value": "image2\n",
		},
		{
			"name": "OTHER_ARTIFACT_DIGEST",
			"value": "4321\n",
		},
	]
	lib.assert_equal(["image1", "image2"], tkn.task_result_artifact_url(slsav1_task_result("task1", results)))
	lib.assert_equal(["1234", "4321"], tkn.task_result_artifact_digest(slsav1_task_result("task1", results)))
}

test_images_result if {
	results := [{
		"name": "IMAGES",
		"value": "img1@sha256:digest1, img2@sha256:digest2\n",
	}]
	lib.assert_equal(["img1", "img2"], tkn.task_result_artifact_url(slsav1_task_result("task1", results)))
	lib.assert_equal(
		["sha256:digest1", "sha256:digest2"],
		tkn.task_result_artifact_digest(slsav1_task_result("task1", results)),
	)
}

test_artifact_outputs_result if {
	results := [
		{
			"name": "ARTIFACT_OUTPUTS",
			"value": {"uri": "img1", "digest": "1234"},
		},
		{
			"name": "OTHER_ARTIFACT_OUTPUTS",
			"value": {"uri": "img2\n", "digest": "4321\n"},
		},
	]
	lib.assert_equal(["img1", "img2"], tkn.task_result_artifact_url(slsav1_task_result("task1", results)))
	lib.assert_equal(["1234", "4321"], tkn.task_result_artifact_digest(slsav1_task_result("task1", results)))
}

test_invalid_result_name if {
	results := [{
		"name": "INVALID_OUTPUTS",
		"value": {"uri": "img1", "digest": "1234"},
	}]
	not tkn.task_result_artifact_url(slsav1_task_result("task1", results))
	not tkn.task_result_artifact_digest(slsav1_task_result("task1", results))
}

test_images_with_digests if {
	results_artifact_outputs := [{
		"name": "ARTIFACT_OUTPUTS",
		"value": {"uri": "img1\n", "digest": "1234\n"},
	}]
	results_images := [
		{
			"name": "image1_IMAGE_URL",
			"value": "img1\n",
		},
		{
			"name": "image1_IMAGE_DIGEST",
			"value": "1234\n",
		},
	]
	results_images_unordered := [
		{
			"name": "image1_IMAGE_URL",
			"value": "img1\n",
		},
		{
			"name": "image2_IMAGE_DIGEST",
			"value": "5678\n",
		},
		{
			"name": "image2_IMAGE_URL",
			"value": "img2\n",
		},
		{
			"name": "image1_IMAGE_DIGEST",
			"value": "1234\n",
		},
	]
	tasks_artifacts := [
		slsav1_task_result("task1", results_artifact_outputs),
		slsav1_task_result("task2", results_artifact_outputs),
	]
	lib.assert_equal(["img1@1234", "img1@1234"], tkn.images_with_digests(tasks_artifacts))

	tasks_images := [slsav1_task_result("task1", results_images), slsav1_task_result("task2", results_images)]
	lib.assert_equal(["img1@1234", "img1@1234"], tkn.images_with_digests(tasks_images))

	tasks_ordered := [slsav1_task_result("task1", results_images_unordered)]
	lib.assert_equal(["img1@1234", "img2@5678"], tkn.images_with_digests(tasks_ordered))
}
