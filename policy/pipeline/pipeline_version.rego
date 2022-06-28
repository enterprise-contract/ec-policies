package policy.pipeline.pipeline_version

import data.lib
import data.lib.time as time_lib

VERSION_REGEX := `^[0-9]+(\.[0-9]+){0,2}$`

# METADATA
# title: Pipeline defines a version
# description: |-
#   The Pipeline has an explicitly defined version value. The version is
#   expected to be defined by the "app.kubernetes.io/version" resource label.
#
# custom:
#   short_name: pipeline_version_exists
#   failure_msg: Pipeline %q does not define a version
#   effective_on: 2023-01-01T00:00:00Z
#
deny[result] {
	pipeline_name := input.metadata.name

	not input.metadata.labels["app.kubernetes.io/version"]

	result := lib.result_helper(rego.metadata.chain(), [pipeline_name])
}

# METADATA
# title: Pipeline version must be in a specific format
# description: |-
#   The Pipeline version is expected to be in one of the following formats:
#   1
#   1.2
#   1.2.3
#
#   Each part of the version must have 1 or more digits. All other characters are
#   not allowed.
#
# custom:
#   short_name: pipeline_version_format
#   failure_msg: Pipeline %q defines an invalid version format, %s. Use "." separated digits
#   effective_on: 2023-01-01T00:00:00Z
#
deny[result] {
	pipeline_name := input.metadata.name
	version := input.metadata.labels["app.kubernetes.io/version"]
	not regex.match(VERSION_REGEX, version)
	result := lib.result_helper(rego.metadata.chain(), [pipeline_name, version])
}

# METADATA
# title: Pipeline version is outdated
# description: |-
#   The Pipeline version is expected to meet a minimum required version.
#
# custom:
#   short_name: pipeline_version
#   failure_msg: Version of Pipeline %q is outdated, %s. Update to %s or newer
#   rule_data:
#     # TODO: Read this from another file?
#     minimum_version:
#     - version: "0.5"
#       effective_on: 2023-01-01T00:00:00Z
#     - version: "0.4"
#       effective_on: 2022-01-01T00:00:00Z
#   effective_on: 2023-01-01T00:00:00Z
#
deny[result] {
	pipeline_name := input.metadata.name
	expected_min_ver := time_lib.most_current(rego.metadata.rule().custom.rule_data.minimum_version).version
	actual_min_ver := input.metadata.labels["app.kubernetes.io/version"]
	expected_min_ver > actual_min_ver
	result := lib.result_helper(rego.metadata.chain(), [pipeline_name, actual_min_ver, expected_min_ver])
}
