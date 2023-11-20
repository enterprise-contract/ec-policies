#
# METADATA
# title: Java dependency checks
# description: >-
#   This package contains a rule to confirm that all Java dependencies
#   were rebuilt in house rather than imported directly from potentially
#   untrusted respositories.
#   If the result is missing no violation is reported.
#   The rules depend on the configuration under the key
#   'allowed_java_component_sources', the key lists all component sources that are
#   allowed by the policy. The values of the list can be 'rebuilt' for
#   dependencies that have been explicitly built from sources, or the name of the
#   Maven repository names where the dependency artifact was retrieved from. The
#   Maven repositories are configured using the 'JBSConfig' custom resources.
#   Default configuration in RHTAP currently includes Maven repositories with
#   names : 'jboss', 'confluent', 'redhat', 'jitpack' and 'gradle'.
#
package policy.release.java

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Java builds have no foreign dependencies
# description: >-
#   The SBOM_JAVA_COMPONENTS_COUNT task result finds dependencies that have
#   originated from foreign repositories, i.e. ones that are not rebuilt or
#   provided by Red Hat. Verify there are no dependencies from sources not
#   listed in the `allowed_java_component_sources` rule data.
# custom:
#   short_name: no_foreign_dependencies
#   failure_msg: Found Java dependencies from '%s', expecting to find only from '%s'
#   solution: >-
#     Make sure there are no build dependencies that originate from foreign repositories.
#     The allowed sources are in the rule_data under the key 'allowed_java_component_sources'.
#   collections:
#   - redhat
#   depends_on:
#   - java.trusted_dependencies_source_list_provided
#
deny contains result if {
	allowed := {a | some a in lib.rule_data("allowed_java_component_sources")}
	foreign := _java_component_sources - allowed
	count(foreign) > 0
	result := lib.result_helper(rego.metadata.chain(), [concat(",", foreign), concat(",", allowed)])
}

# METADATA
# title: Trusted Java dependency source list was provided
# description: >-
#   Confirm the `allowed_java_component_sources` rule data was provided, since it's
#   required by the policy rules in this package.
# custom:
#   short_name: trusted_dependencies_source_list_provided
#   failure_msg: Missing required allowed_java_component_sources rule data
#   solution: >-
#     Add a data source that contains allowable source repositories for build dependencies.
#     The source must be located under a key named 'allowed_java_component_sources'. More
#     information on adding xref:ec-cli:ROOT:configuration.adoc#_data_sources[data sources].
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	count(lib.rule_data("allowed_java_component_sources")) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

_java_component_sources contains name if {
	some result in lib.results_named(lib.java_sbom_component_count_result_name)
	some name, _ in result.value
}
