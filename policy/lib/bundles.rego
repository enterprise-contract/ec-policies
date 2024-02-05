package lib.bundles

import rego.v1

import data.lib.arrays
import data.lib.image
import data.lib.refs
import data.lib.time as time_lib

# Return the bundle reference as is
bundle(task) := refs.task_ref(task).bundle

# Returns a subset of tasks that do not use a bundle reference.
disallowed_task_reference(tasks) := {task |
	some task in tasks
	not bundle(task)
}

# Returns a subset of tasks that use an empty bundle reference.
empty_task_bundle_reference(tasks) := {task |
	some task in tasks
	bundle(task) == ""
}

# Returns a subset of tasks that use bundle references not pinned to a digest.
unpinned_task_bundle(tasks) := {task |
	some task in tasks
	ref := image.parse(bundle(task))
	ref.digest == ""
}

# Returns if the required task-bundles data is missing
default missing_task_bundles_data := false

missing_task_bundles_data if {
	count(_task_bundles) == 0
}

# Returns a subset of tasks that use an acceptable bundle reference, but
# an updated bundle reference exists.
out_of_date_task_bundle(tasks) := {task |
	some task in tasks

	ref := image.parse(_bundle_ref(task, _task_bundles))

	_newer_version_exists(ref)
	_is_acceptable(ref)
}

# Returns a subset of tasks that do not use an acceptable bundle reference.
unacceptable_task_bundle(tasks) := {task |
	some task in tasks

	ref := image.parse(_bundle_ref(task, _task_bundles))

	not _is_acceptable(ref)
}

# Returns if the task uses an acceptable bundle reference
is_acceptable_task(task) if {
	ref := image.parse(_bundle_ref(task, _task_bundles))

	_is_acceptable(ref)
}

_is_acceptable(ref) if {
	_record_exists(ref)
}

# Returns true if the provided bundle reference is recorded within the
# acceptable bundles data
_record_exists(ref) if {
	# all records in acceptable task bundles for the given repository
	records := _task_bundles[ref.repo]

	some record in records

	# an acceptable task bundle reference is one that is recorded in the
	# acceptable task bundles, this is done by matching it's digest; note no
	# care is given to the expiry or freshness
	record.digest == ref.digest
}

# Evaluates to true if the tasks bundle reference is found in the acceptable
# task bundles data, but also there are no records in acceptable task bundles
# data with the same tag and at least one record is newer, regardless of it's
# effective on date, i.e. has a effective_on that is newer than the provided
# reference's effective_on. Two references are considered belonging to the same
# version if they have the same tag.
_newer_version_exists(ref) if {
	# all records in acceptable task bundles for the given repository
	records := _task_bundles[ref.repo]

	# find the record with the newest effective_on for the given digest
	records_with_same_digest := arrays.sort_by("effective_on", [r | some r in records; r.digest == ref.digest])
	record := records_with_same_digest[count(records_with_same_digest) - 1]

	some other in records

	record.tag == other.tag

	time.parse_rfc3339_ns(other.effective_on) > time.parse_rfc3339_ns(record.effective_on)
}

# Evaluates to true if the tasks bundle reference is found in the acceptable
# task bundles data, but also there are no records in acceptable task bundles
# data with the same tag and at least one record is newer, regardless of it's
# effective on date, i.e. has a effective_on that is newer than the provided
# reference's effective_on. In this case we cannot rely on the tags to signal
# versions so we take all records for a specific reference to belong to the same
# version.
_newer_version_exists(ref) if {
	# all records in acceptable task bundles for the given repository
	records := _task_bundles[ref.repo]

	# find the record with the newest effective_on for the given digest
	records_with_same_digest := arrays.sort_by("effective_on", [r | some r in records; r.digest == ref.digest])
	record := records_with_same_digest[count(records_with_same_digest) - 1]

	# No other record in acceptable bundles matches the tag from the record
	# matched by the digest to the reference
	count([other |
		some other in records
		record.digest != other.digest # not the same record
		record.tag == other.tag # we found at least one other tag equal to the one we want to compare with
	]) == 0

	# There are newer records
	count([newer |
		some newer in records
		time.parse_rfc3339_ns(newer.effective_on) > time.parse_rfc3339_ns(record.effective_on)
	]) > 0
}

# Determine the image reference of the task bundle, if the provided task bundle
# image reference doesn't have the tag within it try to lookup the tag from the
# acceptable task bundles data
_bundle_ref(task, acceptable) := ref if {
	ref := bundle(task)
	img := image.parse(ref)
	img.tag != ""
} else := ref if {
	ref_no_tag := bundle(task)
	img := image.parse(ref_no_tag)
	img.tag == ""

	# try to find the tag for the reference based on it's digest
	records := acceptable[img.repo]

	some record in records
	record.digest == img.digest
	record.tag != ""

	ref := image.str({
		"digest": img.digest,
		"repo": img.repo,
		"tag": record.tag,
	})
} else := ref_no_tag if {
	ref_no_tag := bundle(task)
}

# _task_bundles provides a safe way to access the list of acceptable task-bundles. It prevents a
# policy rule from incorrectly not evaluating due to missing data. It also removes stale records.
_task_bundles[repo] := pruned_records if {
	some repo, records in data["task-bundles"]
	pruned_records := time_lib.acceptable_items(records)
}
