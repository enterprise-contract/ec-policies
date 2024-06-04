package lib.tkn

import rego.v1

# handle the output artifacts from Tekton Chains
# https://tekton.dev/docs/chains/slsa-provenance/#output-artifacts

# returns the value of a task result with name IMAGE_URL
task_result_artifact_url(task) := value if {
	value := [url |
		some url in task_result_endswith(task, "IMAGE_URL")

		# don't allow empty results
		count(url) > 0
	]
	count(value) > 0
}

# returns the value of a task result with name ARTIFACT_URI
task_result_artifact_url(task) := value if {
	value := [url |
		some url in task_result_endswith(task, "ARTIFACT_URI")

		# don't allow empty results
		count(url) > 0
	]
	count(value) > 0
}

# returns the image url from the task result IMAGES
task_result_artifact_url(task) := value if {
	value := [v |
		some result in task_result_endswith(task, "IMAGES")
		some image in split(result, ",")
		split_item := split(image, "@")
		v := trim_space(split_item[0])
	]
	count(value) > 0
}

# returns the image url from the task result ARTIFACT_OUTPUTS
task_result_artifact_url(task) := value if {
	value := [url |
		some result in task_result_endswith(task, "ARTIFACT_OUTPUTS")
		url := trim_space(result.uri)
	]
	count(value) > 0
}

# returns the value of a task result with name IMAGE_DIGEST
task_result_artifact_digest(task) := value if {
	value := [digest |
		some digest in task_result_endswith(task, "IMAGE_DIGEST")

		# don't allow empty results
		count(digest) > 0
	]
	count(value) > 0
}

# returns the value of a task result with name ARTIFACT_DIGEST
task_result_artifact_digest(task) := value if {
	value := [digest |
		some digest in task_result_endswith(task, "ARTIFACT_DIGEST")

		# don't allow empty results
		count(digest) > 0
	]
	count(value) > 0
}

# returns the image digest from the task result IMAGES
task_result_artifact_digest(task) := value if {
	value := [v |
		some result in task_result_endswith(task, "IMAGES")
		some image in split(result, ",")
		split_item := split(image, "@")
		v := trim_space(split_item[1])
	]
	count(value) > 0
}

# returns the image digest from the task result ARTIFACT_OUTPUTS
task_result_artifact_digest(task) := value if {
	value := [url |
		some result in task_result_endswith(task, "ARTIFACT_OUTPUTS")
		url := trim_space(result.digest)
	]
	count(value) > 0
}

images_with_digests(tasks) := [sprintf("%v@%v", [i, d]) |
	some y
	some task in tasks
	images := task_result_artifact_url(task)
	digests := task_result_artifact_digest(task)
	i := images[y]
	d := digests[y]
]
