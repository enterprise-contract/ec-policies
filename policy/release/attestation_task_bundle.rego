package policy.release.attestation_task_bundle

import data.lib
import data.lib.image
import data.lib.time as time_lib

# METADATA
# title: Task bundle was not used or is not defined
# description: |-
#   Check for existence of a task bundle. Enforcing this rule will
#   fail the contract if the task is not called from a bundle.
# custom:
#   short_name: disallowed_task_reference
#   failure_msg: Task '%s' does not contain a bundle reference
#
warn[result] {
	task := lib.tasks_from_pipelinerun[_]
	name := task.name
	not task.ref.bundle
	result := lib.result_helper(rego.metadata.chain(), [name])
}

# METADATA
# title: Task bundle reference is empty
# description: |-
#   Check for a valid task bundle reference being used.
# custom:
#   short_name: empty_task_bundle_reference
#   failure_msg: Task '%s' uses an empty bundle image reference
#
warn[result] {
	task := lib.tasks_from_pipelinerun[_]
	name := task.name
	task.ref.bundle == ""
	result := lib.result_helper(rego.metadata.chain(), [name])
}

# METADATA
# title: Task bundle is out of date
# description: |-
#   Check if the Tekton Bundle used for the Tasks in the attestation
#   is the most recent acceptable one. See the file
#   data/acceptable_tekton_bundles.yml in this git repository for a
#   full list of acceptable Tekton Bundles.
# custom:
#   short_name: out_of_date_task_bundle
#   failure_msg: Task '%s' uses an out of date task bundle '%s'
#
warn[result] {
	att := input.attestations[_]
	task := att.predicate.buildConfig.tasks[_]
	bundle := task.ref.bundle
	ref := image.parse(bundle)
	collection := _collection("task-bundles", ref)

	collection[match_index].digest == ref.digest
	match_index > 0

	result := lib.result_helper(rego.metadata.chain(), [task.name, bundle])
}

# METADATA
# title: Task bundle is not acceptable
# description: |-
#   Check if the Tekton Bundle used for the Tasks in the attestation
#   are acceptable given the tracked effective_on date. See the file
#   data/acceptable_tekton_bundles.yml in this git repository for a
#   full list of acceptable Tekton Bundles.
# custom:
#   short_name: unacceptable_task_bundle
#   failure_msg: Task '%s' uses an unacceptable task bundle '%s'
#
warn[result] {
	att := input.attestations[_]
	task := att.predicate.buildConfig.tasks[_]
	bundle := task.ref.bundle
	ref := image.parse(bundle)
	collection := _collection("task-bundles", ref)

	matches := [record |
		record := collection[_]
		record.digest == ref.digest
	]

	count(matches) == 0

	result := lib.result_helper(rego.metadata.chain(), [task.name, bundle])
}

# _collection returns an array representing the full list of records to
# be taken into consideration when evaluating policy rules for bundle
# references. Any irrelevant records are filtered out from the array.
_collection(type, ref) = items {
	full_collection := data.acceptable_tekton_bundles[type][ref.repo]
	stream_collection := _collection_by_stream(full_collection, ref)
	items := time_lib.acceptable_items(stream_collection)
}

# _collection_by_stream returns a filtered array where each item has
# the same stream value as the given ref.
#
# Some OCI repositories may contain multiple sets of images that are
# actively updated. Each of these sets is called a stream. In such
# cases, it is necessary to split the collection into multiple stream
# collections so the policy can be properly applied. See the _stream
# docs for an explanation of the stream identification process.
_collection_by_stream(items, ref) = some_items {
	tag := _tag_by_digest(items, ref)
	stream := _stream(tag)
	some_items := [item |
		item := items[_]
		_stream(item.tag) == stream
	]
}

_stream_regex := `^[a-f0-9]{40}(-\d+)$`

# _stream computes the stream of the given image tag. If the tag matches
# the _stream_regex, then the stream is the last matched group. Otherwise
# the stream is "default".
_stream(tag) = stream {
	regex.match(_stream_regex, tag)
	parts := split(tag, "-")
	stream := parts[count(parts) - 1]
} else = "default" {
	true
}

# _tag_by_digest determines the tag of the image reference based on the
# possiblities in the given collection. This is useful to ensure streams
# can be properly computed for image references where only the digest is
# provided. If the image reference already has a tag, that value is
# always returned.
_tag_by_digest(collection, ref) = new_tag {
	ref.tag == ""
	selected := [item |
		item := collection[_]
		item.digest == ref.digest
	]

	new_tag := selected[0].tag
} else = ref.tag {
	true
}
