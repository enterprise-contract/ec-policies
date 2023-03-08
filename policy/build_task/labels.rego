#
# METADATA
# title: Checks related to build tasks
# description: |-
#   Checks related to build tasks
#
package policy.build_task.labels

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.tkn

build_label := "build.appstudio.redhat.com/build_type"

# METADATA
# title: Build task does not contain required label
# description: |-
#   This policy enforces that a required build label is present in a build task
# custom:
#   short_name: build_task_label_missing
#   failure_msg: The required build label '%s' is missing
deny contains result if {
	not build_label in object.keys(tkn.task_labels(input))
	result := lib.result_helper(rego.metadata.chain(), [build_label])
}

# METADATA
# title: Build task does not contain any labels
# description: |-
#   This policy enforces that the task contains a label
# custom:
#   short_name: build_task_no_labels
#   failure_msg: The task does not contain labels
deny contains result if {
	not tkn.task_labels(input)
	result := lib.result_helper(rego.metadata.chain(), [])
}
