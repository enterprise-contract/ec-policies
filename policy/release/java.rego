#
# METADATA
# title: Java dependency checks
# description: |-
#   This package contains a rule to confirm that all Java dependencies
#   were rebuilt in house rather than imported directly from potentially
#   untrusted respositories.
#   The result must be reported by a Task that has been loaded from an
#   acceptable Tekton Bundle.
#   See xref:release_policy.adoc#attestation_task_bundle_package[Task bundle checks].
#   If the result is missing or provided via a task loaded from unacceptable no
#   issue is reported.
#
package policy.release.java

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.bundles

# METADATA
# title: Prevent Java builds from depending on foreign dependencies
# description: |-
#   The SBOM_JAVA_COMPONENTS_COUNT TaskResult finds dependencies that have
#   originated from foreign repositories, i.e. ones that are not rebuilt or
#   redhat.
# custom:
#   short_name: java_foreign_dependencies
#   failure_msg: Found Java dependencies from '%s', expecting to find only from '%s'
#   rule_data:
#     allowed_component_sources:
#       - redhat
#       - rebuilt
deny contains result if {
	allowed := {a | some a in lib.rule_data(rego.metadata.rule(), "allowed_component_sources")}
	foreign := _java_component_sources - allowed
	count(foreign) > 0
	result := lib.result_helper(rego.metadata.chain(), [concat(",", foreign), concat(",", allowed)])
}

_java_component_sources contains name if {
	some result in lib.results_named(lib.java_sbom_component_count_result_name)
	bundle := result[lib.key_bundle]
	bundles.is_acceptable(bundle)
	some name, _ in result[lib.key_value]
}
