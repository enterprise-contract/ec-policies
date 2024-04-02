package lib.sbom

import data.lib
import data.lib.tkn
import rego.v1

cyclonedx_sboms := array.concat(
	array.concat(_cyclonedx_sboms_from_image, _cyclonedx_sboms_from_attestations),
	_cyclonedx_sboms_from_oci,
)

_cyclonedx_sboms_from_image := [sbom |
	some path in ["root/buildinfo/content_manifests/sbom-cyclonedx.json"]
	sbom := input.image.files[path]
]

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
