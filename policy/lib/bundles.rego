package lib.bundles

import future.keywords.in

import data.lib.image
import data.lib.refs
import data.lib.time as time_lib

# Returns a subset of tasks that do not use a bundle reference.
disallowed_task_reference(tasks) = matches {
	matches := {task |
		task := tasks[_]
		not bundle(task)
	}
}

# Returns a subset of tasks that use an empty bundle reference.
empty_task_bundle_reference(tasks) = matches {
	matches := {task |
		task := tasks[_]
		bundle(task) == ""
	}
}

# Returns a subset of tasks that use bundle references not pinned to a digest.
unpinned_task_bundle(tasks) = matches {
	matches := {task |
		task := tasks[_]
		ref := image.parse(bundle(task))
		ref.digest == ""
	}
}

# Returns a subset of tasks that use an acceptable bundle reference, but
# an updated bundle reference exists.
out_of_date_task_bundle(tasks) = matches {
	matches := {task |
		task := tasks[_]
		ref := image.parse(bundle(task))
		collection := _collection(ref)

		is_equal(collection[match_index], ref)
		match_index > 0
	}
}

# Returns a subset of tasks that do not use an acceptable bundle reference.
unacceptable_task_bundle(tasks) = matches {
	matches := {task |
		task := tasks[_]
		ref := image.parse(bundle(task))
		collection := _collection(ref)

		matches := [record |
			record := collection[_]
			is_equal(record, ref)
		]

		count(matches) == 0
	}
}

# Returns true if the provided bundle reference is acceptable
is_acceptable(bundle_ref) {
	ref := image.parse(bundle_ref)
	collection := _collection(ref)
	matches := [r |
		r := collection[_]
		is_equal(r, ref)
	]

	count(matches) > 0
}

# Returns whether or not the ref matches the digest of the record.
is_equal(record, ref) = match {
	ref.digest != ""
	match := record.digest == ref.digest
}

# Returns whether or not the ref matches the tag of the record as a fallback
# in case the digest is blank for the ref. This is a weaker comparison as,
# unlike digests, tags are not immutable entities. It is expected that a
# missing digest results in a warning whenever possible.
is_equal(record, ref) = match {
	ref.digest == ""
	match := record.tag == ref.tag
}

bundle(task) = b {
	b := refs.task_ref(task).bundle
}

# _collection returns an array representing the full list of records to
# be taken into consideration when evaluating policy rules for bundle
# references. Any irrelevant records are filtered out from the array.
_collection(ref) = items {
	full_collection := data["task-bundles"][ref.repo]
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
