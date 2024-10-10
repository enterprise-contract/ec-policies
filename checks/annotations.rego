package checks

import rego.v1

# Required annotations on policy rules
required_annotations := {
	"title",
	"description",
	"custom.short_name",
	"custom.failure_msg",
}

# returns Rego files corresponding to policy rules
policy_rule_files(namespaces) := {rule |
	some namespace, files in namespaces
	startswith(namespace, "data.policy") # look only in the policy namespace
	rule := {"namespace": namespace, "files": {file |
		some file in files
		not endswith(file, "_test.rego") # disregard test Rego files
	}}
}

# for annotations defined as:
# {
#   "<ann>": "..."
# }
# return set with single element "<ann>"
flat(annotation_name, annotation_definition) := result if {
	is_string(annotation_definition)
	result := {annotation_name}
}

# for annotations defined as:
# {
#   "<ann1>": {
#     "<ann2>": "...",
#     "<ann3>": "..."
#  }
# return set with elements "<ann1>.<ann2>" and "<ann1>.<ann3>"
flat(annotation_name, annotation_definition) := result if {
	is_object(annotation_definition)
	result := {x |
		some nested_name, _ in annotation_definition
		x := concat(".", [annotation_name, nested_name])
	}
}

all_rule_names contains name if {
	some policy_files in policy_rule_files(input.namespaces)
	some file in policy_files.files
	some annotation in input.annotations

	annotation.location.file == file

	name := sprintf("%s.%s", [policy_files.namespace, annotation.annotations.custom.short_name])
}

all_rule_names_ary := [name |
	some policy_files in policy_rule_files(input.namespaces)
	some file in policy_files.files
	some annotation in input.annotations

	annotation.location.file == file

	name := sprintf("%s.%s", [policy_files.namespace, annotation.annotations.custom.short_name])
]

# Validates that the policy rules have all required annotations
violation contains msg if {
	some policy_files in policy_rule_files(input.namespaces)

	some file in policy_files.files
	some annotation in input.annotations

	# just examine Rego files that declare policies
	annotation.location.file == file

	# ... and ignore non-rule annotations, e.g. package, document.
	annotation.annotations.scope == "rule"

	# gather all annotations in a dotted format (e.g. "custom.short_name")
	declared_annotations := union({a |
		some key, _ in annotation.annotations
		a := flat(key, annotation.annotations[key])
	})

	# what required annotations are missing
	missing_annotations := required_annotations - declared_annotations

	# if we have any?
	count(missing_annotations) > 0

	msg := sprintf("ERROR: Missing annotation(s) %s at %s:%d", [
		concat(", ", missing_annotations),
		file, annotation.location.row,
	])
}

# Validates that the `depends_op` annotation points to an existing rule
violation contains msg if {
	some policy_files in policy_rule_files(input.namespaces)

	some file in policy_files.files
	some annotation in input.annotations

	annotation.location.file == file

	some depends_on in annotation.annotations.custom.depends_on
	dependency_rule_name := sprintf("data.policy.release.%s", [depends_on])

	count({dependency_rule_name} & all_rule_names) == 0
	msg := sprintf("ERROR: Missing dependency rule %q at %s:%d", [dependency_rule_name, file, annotation.location.row])
}

# Validates that package.short_name is unique
violation contains msg if {
	some policy_files in policy_rule_files(input.namespaces)

	some file in policy_files.files
	some annotation in input.annotations

	annotation.location.file == file

	code := sprintf("%s.%s", [policy_files.namespace, annotation.annotations.custom.short_name])

	duplicates := [r | some r in all_rule_names_ary; r == code]

	count(duplicates) > 1

	msg := sprintf("ERROR: Found non-unique code %q at %s:%d", [code, file, annotation.location.row])
}

# Validates that the `effective_on` annotation has the correct syntax
violation contains msg if {
	some policy_files in policy_rule_files(input.namespaces)

	some file in policy_files.files
	some annotation in input.annotations

	annotation.location.file == file

	effective_on := annotation.annotations.custom.effective_on
	not time.parse_rfc3339_ns(effective_on)

	msg := sprintf("ERROR: wrong syntax of effective_on value %q at %s:%d", [effective_on, file, annotation.location.row])
}
