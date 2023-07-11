#
# METADATA
# description: >-
#   Check if the image has the expected labels set. The rules in this package
#   distinguish file-based catalog (FBC) images from all other images. When
#   checking an FBC image, a policy rule may use a different set of rule data.
#   An FBC image is detected by the presence of the
#   operators.operatorframework.io.index.configs.v1 label.
#
package policy.release.labels

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Deprecated labels
# description: >-
#   Check the image for the presence of labels that have been deprecated.
#   Use the rule data key "deprecated_labels" to set the list of labels
#   to check.
# custom:
#   short_name: deprecated_labels
#   failure_msg: The %q label is deprecated, replace with %q
#   solution: >-
#     Update the image build process to not set the deprecated labels.
#   collections:
#   - redhat
#
deny contains result if {
	some label in labels
	some deprecated_label in lib.rule_data("deprecated_labels")
	label.name == deprecated_label.name
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[label.name, deprecated_label.replacement],
		label.name,
	)
}

# METADATA
# title: Required labels
# description: >-
#   Check the image for the presence of labels that are required.
#   Use the rule data "required_labels" key to set the list of labels
#   to check, or the "fbc_required_labels" key for fbc images.
# custom:
#   short_name: required_labels
#   failure_msg: 'The required %q label is missing. Label description: %s'
#   solution: >-
#     Update the image build process to set the required labels.
#   collections:
#   - redhat
#
deny contains result if {
	found_labels := {name |
		some label in labels
		name := label.name
	}
	some required_label in required_labels
	name := required_label.name
	not name in found_labels
	description := required_label.description
	result := lib.result_helper_with_term(rego.metadata.chain(), [name, description], name)
}

# METADATA
# title: Optional labels
# description: >-
#   Check the image for the presence of labels that are recommended,
#   but not required. Use the rule data "optional_labels" key to set
#   the list of labels to check, or the "fbc_optional_labels" key for
#   fbc images.
# custom:
#   short_name: optional_labels
#   failure_msg: 'The optional %q label is missing. Label description: %s'
#   solution: >-
#     Update the image build process to set the optional labels.
#   collections:
#   - redhat
#
warn contains result if {
	found_labels := {name |
		some label in labels
		name := label.name
	}
	some optional_label in optional_labels
	name := optional_label.name
	not name in found_labels
	description := optional_label.description
	result := lib.result_helper_with_term(rego.metadata.chain(), [name, description], name)
}

# METADATA
# title: Disallowed inherited labels
# description: >-
#   Check that certain labels on the image have different values than the labels
#   from the parent image. If the label is inherited from the parent image but not
#   redefined for the image, it will contain an incorrect value for the image.
#   Use the rule data "disallowed_inherited_labels" key to set the list of labels
#   to check, or the "fbc_disallowed_inherited_labels" key for fbc images.
# custom:
#   short_name: disallowed_inherited_labels
#   failure_msg: The %q label should not be inherited from the parent image
#   solution: >-
#     Update the image build process to overwrite the inherited labels.
#   collections:
#   - redhat
#
deny contains result if {
	some inherited_label in disallowed_inherited_labels
	name := inherited_label.name
	_value(labels, name) == _value(parent_labels, name)
	result := lib.result_helper_with_term(rego.metadata.chain(), [name], name)
}

labels contains label if {
	some name, value in input.image.config.Labels
	count(value) > 0
	label := {"name": name, "value": value}
}

parent_labels contains label if {
	some name, value in input.image.parent.config.Labels
	count(value) > 0
	label := {"name": name, "value": value}
}

_value(labels, name) := value if {
	value := [v |
		some label in labels
		label.name == name
		v := label.value
	][0]
}

required_labels := lib.rule_data("required_labels") if {
	not is_fbc
} else := lib.rule_data("fbc_required_labels")

optional_labels := lib.rule_data("optional_labels") if {
	not is_fbc
} else := lib.rule_data("fbc_optional_labels")

disallowed_inherited_labels := lib.rule_data("disallowed_inherited_labels") if {
	not is_fbc
} else := lib.rule_data("fbc_disallowed_inherited_labels")

# A file-based catalog (FBC) image is just like a regular binary image, but
# with a very specific application in the operator framework ecosystem. Here
# we use heurisitics to determine whether or not the image is an FBC image.
is_fbc if {
	some label in labels
	label.name == "operators.operatorframework.io.index.configs.v1"
} else := false if {}
