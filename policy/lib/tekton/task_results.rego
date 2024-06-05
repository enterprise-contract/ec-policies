package lib.tkn

import rego.v1

# handle the output artifacts from Tekton Chains
# https://tekton.dev/docs/chains/slsa-provenance/#output-artifacts

# returns the value of a task result with name IMAGE_URL
task_result_artifact_url(task) := value if {
	value := _non_empty_strings(task_result_endswith(task, "IMAGE_URL"))
	count(value) > 0
}

# returns the value of a task result with name ARTIFACT_URI
task_result_artifact_url(task) := value if {
	value := _non_empty_strings(task_result_endswith(task, "ARTIFACT_URI"))
	count(value) > 0
}

# returns the image url from the task result IMAGES
task_result_artifact_url(task) := value if {
	value := _non_empty_strings([v |
		some result in task_result_endswith(task, "IMAGES")
		some image in split(result, ",")
		split_item := split(image, "@")
		v := split_item[0]
	])
	count(value) > 0
}

# returns the image url from the task result ARTIFACT_OUTPUTS
task_result_artifact_url(task) := value if {
	value := _non_empty_strings([result.uri |
		some result in task_result_endswith(task, "ARTIFACT_OUTPUTS")
	])
	count(value) > 0
}

# returns the value of a task result with name IMAGE_DIGEST
task_result_artifact_digest(task) := value if {
	value := _non_empty_strings(task_result_endswith(task, "IMAGE_DIGEST"))
	count(value) > 0
}

# returns the value of a task result with name ARTIFACT_DIGEST
task_result_artifact_digest(task) := value if {
	value := _non_empty_strings(task_result_endswith(task, "ARTIFACT_DIGEST"))
	count(value) > 0
}

# returns the image digest from the task result IMAGES
task_result_artifact_digest(task) := value if {
	value := _non_empty_strings([v |
		some result in task_result_endswith(task, "IMAGES")
		some image in split(result, ",")
		split_item := split(image, "@")
		v := split_item[1]
	])
	count(value) > 0
}

# returns the image digest from the task result ARTIFACT_OUTPUTS
task_result_artifact_digest(task) := value if {
	value := _non_empty_strings([result.digest |
		some result in task_result_endswith(task, "ARTIFACT_OUTPUTS")
	])
	count(value) > 0
}

_non_empty_strings(values) := [trimmed_value |
	some value in values
	trimmed_value := trim_space(value)
	count(trimmed_value) > 0
]

images_with_digests(tasks) := [sprintf("%v@%v", [i, d]) |
	some y
	some task in tasks
	images := task_result_artifact_url(task)
	digests := task_result_artifact_digest(task)
	i := images[y]
	d := digests[y]
]
