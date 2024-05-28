package lib.tkn

import rego.v1

# handle the output artifacts from Tekton Chains
# https://tekton.dev/docs/chains/slsa-provenance/#output-artifacts

# returns the value of a task result with name IMAGE_URL
task_result_artifact_url(task) := value if {
	value := [url |
		some url in task_result_endswith(task, "IMAGE_URL")
		count(url) > 0
	]
	count(value) > 0
}

# returns the value of a task result with name ARTIFACT_URI
task_result_artifact_url(task) := value if {
	value := [url |
		some url in task_result_endswith(task, "ARTIFACT_URI")
		count(url) > 0
	]
	count(value) > 0
}

# returns the image url from the task result IMAGES
task_result_artifact_url(task) := value if {
	results := task_result_endswith(task, "IMAGES")
	value := [v |
		some result in results
		some image in split(result, ",")
		split_item := split(image, "@")
		v := trim_space(split_item[0])
	]
	count(value) > 0
}

# returns the image url from the task result ARTIFACT_OUTPUTS
task_result_artifact_url(task) := value if {
	value := [url |
		outputs := task_result_endswith(task, "ARTIFACT_OUTPUTS")
		some output in outputs
		url := trim_space(output.uri)
	]
	count(value) > 0
}

# returns the value of a task result with name IMAGE_DIGEST
task_result_artifact_digest(task) := value if {
	value := [digest |
		some digest in task_result_endswith(task, "IMAGE_DIGEST")
		count(digest) > 0
	]
	count(value) > 0
}

# returns the value of a task result with name ARTIFACT_DIGEST
task_result_artifact_digest(task) := task_result_endswith(task, "ARTIFACT_DIGEST")

# returns the image digest from the task result IMAGES
task_result_artifact_digest(task) := value if {
	results := task_result_endswith(task, "IMAGES")
	value := [v |
		some result in results
		some image in split(result, ",")
		split_item := split(image, "@")
		v := trim_space(split_item[1])
	]
	count(value) > 0
}

# returns the image digest from the task result ARTIFACT_OUTPUTS
task_result_artifact_digest(task) := value if {
	value := [digest |
		outputs := task_result_endswith(task, "ARTIFACT_OUTPUTS")
		some output in outputs
		digest := trim_space(output.digest)
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
