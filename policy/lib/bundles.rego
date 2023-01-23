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

# Returns if the required task-bundles data is missing
missing_task_bundles_data {
	count(data["task-bundles"]) == 0
} else := false

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
	items := time_lib.acceptable_items(full_collection)
}
