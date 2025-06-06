#
# METADATA
# title: RPM Packages
# description: >-
#   Rules used to verify different properties of specific RPM packages found in the SBOM of the
#   image being validated.
#
package rpm_packages

import rego.v1

import data.lib
import data.lib.image
import data.lib.sbom
import data.lib.tekton

# METADATA
# title: Unique Version
# description: >-
#   Check if there is more than one version of the same RPM installed across different
#   architectures. This check only applies for Image Indexes, aka multi-platform images.
#   Use the `non_unique_rpm_names` rule data key to ignore certain RPMs.
# custom:
#   short_name: unique_version
#   failure_msg: 'Multiple versions of the %q RPM were found: %s'
#   collections:
#   - redhat
#   # Pushed back due to https://issues.redhat.com/browse/EC-1232
#   effective_on: 2025-06-28T00:00:00Z
#
deny contains result if {
	image.is_image_index(input.image.ref)

	# Arguably this is a weird edge case that should be dealt with by changing
	# the build to not be multi-arch. But this avoids producing a confusing and
	# not useful violation in some cases.
	not _is_single_image_index(input.image.ref)

	some name, versions in grouped_rpm_purls
	count(versions) > 1
	not name in lib.rule_data("non_unique_rpm_names")
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[name, concat(", ", versions)],
		name,
	)
}

# grouped_rpm_purls groups the found RPMs by name to facilitate detecting different versions. It
# has the following structure:
# {
#     "spam-maps": {"1.2.3-0", "1.2.3-9"},
#     "bacon": {"7.8.8-8"},
# }
grouped_rpm_purls[name] contains version if {
	some rpm_purl in all_rpm_purls
	rpm := ec.purl.parse(rpm_purl)
	name := rpm.name

	# NOTE: This includes both version and release.
	version := rpm.version
}

all_rpm_purls contains rpm.purl if {
	some attestation in lib.pipelinerun_attestations
	some build_task in tekton.build_tasks(attestation)
	some result in tekton.task_results(build_task)
	result.name == "SBOM_BLOB_URL"
	url := result.value
	blob := ec.oci.blob(url)
	s := json.unmarshal(blob)
	some rpm in sbom.rpms_from_sbom(s)
}

# For detecting image indexes with just a single image in them.
# (I don't think there are any valid reasons for these to exist)
_is_single_image_index(ref) if {
	index := ec.oci.image_index(ref)
	count(index.manifests) == 1
} else := false
