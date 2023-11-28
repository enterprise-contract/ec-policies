package lib.sbom

import future.keywords.in

cyclonedx_sboms := array.concat(_cyclonedx_sboms_from_image, _cyclonedx_sboms_from_attestations)

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
