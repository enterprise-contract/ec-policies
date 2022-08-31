package policy.release.java

import data.lib
import future.keywords.in

# METADATA
# title: Prevent Java builds from depending on foreign dependencies
# description: |-
#   The SBOM_JAVA_COMPONENTS_COUNT TaskResult finds dependencies that have
#   originated from foreign repositories, i.e. ones that are not rebuilt or
#   redhat.
# custom:
#   failure_msg: Found Java dependencies from '%s', expecting to find only from '%s'
#   rule_data:
#     allowed_component_sources:
#       - redhat
#       - rebuilt
deny_java_foreign_dependencies[result] {
	results := lib.results_named(lib.java_sbom_component_count_result_name)

	# convert to set
	allowed := {a | a := rego.metadata.rule().custom.rule_data.allowed_component_sources[_]}

	# contains names of dependency sources that are foreign, i.e. not one of
	# allowed_component_sources
	foreign := [name |
		results[_][name]
		not name in (allowed | {lib.task_name})
	]

	count(foreign) > 0

	result := lib.result_helper(rego.metadata.chain(), [concat(",", foreign), concat(",", allowed)])
}
