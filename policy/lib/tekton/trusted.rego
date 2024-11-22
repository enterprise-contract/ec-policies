package lib.tekton

import rego.v1

import data.lib.json as j
import data.lib.time as time_lib

# regal ignore:prefer-package-imports
import data.lib.rule_data as lib_rule_data

# Returns a subset of tasks that use unpinned Task references.
unpinned_task_references(tasks) := {task |
	some task in tasks
	not task_ref(task).pinned
}

# Returns if the list of trusted Tasks are missing
default missing_trusted_tasks_data := false

missing_trusted_tasks_data if {
	count(_trusted_tasks) == 0
}

# Returns a subset of tasks that use a trusted Task reference, but an updated Task reference exists.
out_of_date_task_refs(tasks) := {task |
	some task in tasks
	is_trusted_task(task)
	_newer_record_exists(task)
}

# Returns a subset of tasks that do not use a trusted Task reference.
untrusted_task_refs(tasks) := {task |
	some task in tasks
	not is_trusted_task(task)
}

# Returns true if the task uses a trusted Task reference.
is_trusted_task(task) if {
	ref := task_ref(task)
	records := _trusted_tasks[ref.key]

	some record in records

	# A trusted task reference is one that is recorded in the trusted tasks data, this is done by
	# matching its pinned reference; note no care is given to the expiry or freshness since expired
	# records have already been filtered out.
	record.ref == ref.pinned_ref
}

# Returns true if a newer record exists with a different digest.
_newer_record_exists(task) if {
	ref := task_ref(task)
	records := _trusted_tasks[ref.key]

	newest_record := time_lib.newest(records)
	newest_record.ref != ref.pinned_ref

	# newest record could have the same effective_on as the record for the given
	# task, in that case we can't claim that the newer record exists
	some record in records
	record.ref == ref.pinned_ref
	newest_record.effective_on != record.effective_on
}

# _trusted_tasks provides a safe way to access the list of trusted tasks. It prevents a policy rule
# from incorrectly not evaluating due to missing data. It also removes stale records.
_trusted_tasks[key] := pruned_records if {
	some key, records in _trusted_tasks_data
	pruned_records := time_lib.acceptable_items(records)
}

# Merging in the trusted_tasks rule data makes it easier for users to customize their trusted tasks
_trusted_tasks_data := object.union(data.trusted_tasks, lib_rule_data("trusted_tasks"))

data_errors contains error if {
	some e in j.validate_schema(
		_trusted_tasks_data,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "object",
			"patternProperties": {".*": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"effective_on": {"type": "string"},
						"expires_on": {"type": "string"},
						"ref": {"type": "string"},
					},
					"required": ["effective_on", "ref"],
					"additionalProperties": false,
				},
				"minItems": 1,
			}},
		},
	)

	error := {
		"message": sprintf("trusted_tasks data has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

data_errors contains error if {
	some task, refs in _trusted_tasks_data
	some i, ref in refs
	not time.parse_rfc3339_ns(ref.effective_on)
	error := {
		"message": sprintf(
			"trusted_tasks.%s[%d].effective_on is not valid RFC3339 format: %q",
			[task, i, ref.effective_on],
		),
		"severity": "failure",
	}
}

data_errors contains error if {
	some task, refs in _trusted_tasks_data
	some i, ref in refs
	not time.parse_rfc3339_ns(ref.expires_on)
	error := {
		"message": sprintf(
			"trusted_tasks.%s[%d].expires_on is not valid RFC3339 format: %q",
			[task, i, ref.expires_on],
		),
		"severity": "failure",
	}
}
