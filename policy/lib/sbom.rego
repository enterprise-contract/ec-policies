package lib.sbom

import data.lib
import data.lib.tkn
import rego.v1

# cyclonedx_sboms returns a list of SBOMs associated with the image being validated. It will first
# try to find them as references in the SLSA Provenance attestation and as an SBOM attestation. If
# an SBOM is not found in those locations, then it will attempt to retrieve the SBOM from within the
# image's filesystem. This fallback exists for legacy purposes and support for it will be removed
# soon.
default cyclonedx_sboms := []

cyclonedx_sboms := sboms if {
	sboms := array.concat(_cyclonedx_sboms_from_attestations, _cyclonedx_sboms_from_oci)
	count(sboms) > 0
} else := _cyclonedx_sboms_from_image

_cyclonedx_sboms_from_image := [sbom] if {
	sbom := input.image.files[_sbom_image_path]
} else := [sbom] if {
	input.image.config.Labels.vendor == "Red Hat, Inc."
	sbom := ec.oci.image_files(input.image.ref, [_sbom_image_path])[_sbom_image_path]
}

_cyclonedx_sboms_from_attestations := [sbom |
	some att in input.attestations
	statement := att.statement

	# https://cyclonedx.org/specification/overview/#recognized-predicate-type
	statement.predicateType == "https://cyclonedx.org/bom"
	sbom := statement.predicate
]

_cyclonedx_sboms_from_oci := [sbom |
	some attestation in lib.pipelinerun_attestations
	some task in tkn.build_tasks(attestation)

	blob_ref := tkn.task_result(task, "SBOM_BLOB_URL")
	blob := ec.oci.blob(blob_ref)

	sbom := json.unmarshal(blob)
]

_sbom_image_path := "root/buildinfo/content_manifests/sbom-cyclonedx.json"
