package lib.sbom.oci

import data.lib
import data.lib.tkn
import rego.v1

_cyclonedx_sboms := [sbom |
	some attestation in lib.pipelinerun_attestations
	some task in tkn.build_tasks(attestation)

	blob_ref := tkn.task_result(task, "SBOM_BLOB_URL")
	blob := ec.oci.blob(blob_ref)

	sbom := json.unmarshal(blob)
]
