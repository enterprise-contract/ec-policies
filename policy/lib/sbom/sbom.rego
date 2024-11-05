package lib.sbom

import data.lib
import data.lib.image
import data.lib.json as j
import data.lib.tekton
import rego.v1

# cyclonedx_sboms and spdx_sboms returns a list of SBOMs associated with the image being validated. It will first
# try to find them as references in the SLSA Provenance attestation and as an SBOM attestation. If
# an SBOM is not found in those locations, then it will attempt to retrieve the SBOM from within the
# image's filesystem. This fallback exists for legacy purposes and support for it will be removed
# soon.

all_sboms := array.concat(cyclonedx_sboms, spdx_sboms)

default cyclonedx_sboms := []

cyclonedx_sboms := sboms if {
	sboms := array.concat(_cyclonedx_sboms_from_attestations, _cyclonedx_sboms_from_oci)
	count(sboms) > 0
} else := _cyclonedx_sboms_from_image

_cyclonedx_sboms_from_image := [sbom] if {
	sbom := input.image.files[_sbom_cyclonedx_image_path]
} else := [sbom] if {
	input.image.config.Labels.vendor == "Red Hat, Inc."
	sbom := ec.oci.image_files(input.image.ref, [_sbom_cyclonedx_image_path])[_sbom_cyclonedx_image_path]
}

_cyclonedx_sboms_from_attestations := [statement.predicate |
	some att in input.attestations
	statement := att.statement

	# https://cyclonedx.org/specification/overview/#recognized-predicate-type
	statement.predicateType == "https://cyclonedx.org/bom"
]

_cyclonedx_sboms_from_oci := [sbom |
	some sbom in _fetch_oci_sbom
	sbom.bomFormat == "CycloneDX"
]

spdx_sboms := sboms if {
	sboms := array.concat(_spdx_sboms_from_attestations, _spdx_sboms_from_oci)
	count(sboms) > 0
} else := _spdx_sboms_from_image

default _spdx_sboms_from_image := []

_spdx_sboms_from_image := [sbom] if {
	sbom := input.image.files[_sbom_spdx_image_path]
}

_spdx_sboms_from_attestations := [statement.predicate |
	some att in input.attestations
	statement := att.statement
	statement.predicateType == "https://spdx.dev/Document"
]

_spdx_sboms_from_oci := [sbom |
	some sbom in _fetch_oci_sbom
	sbom.SPDXID == "SPDXRef-DOCUMENT"
]

_fetch_oci_sbom := [sbom |
	some attestation in lib.pipelinerun_attestations
	some task in tekton.build_tasks(attestation)

	# For multi-platform images, the same SLSA Provenance may describe all the platform specific
	# images. Each will have its own SBOM. Only select the SBOM for the image being evaluated.
	expected_image_digest := image.parse(input.image.ref).digest
	image_digest := tekton.task_result(task, "IMAGE_DIGEST")
	expected_image_digest == image_digest

	blob_ref := tekton.task_result(task, "SBOM_BLOB_URL")
	blob := ec.oci.blob(blob_ref)
	sbom := json.unmarshal(blob)
]

has_item(needle, haystack) if {
	needle_purl := ec.purl.parse(needle)

	some hay in haystack
	hay_purl := ec.purl.parse(hay.purl)

	needle_purl.type == hay_purl.type
	needle_purl.namespace == hay_purl.namespace
	needle_purl.name == hay_purl.name
	_matches_version(needle_purl.version, hay)

	not _excluded(needle_purl, object.get(hay, "exceptions", []))
} else := false

_excluded(purl, exceptions) if {
	matches := [exception |
		some exception in exceptions
		exception.subpath == purl.subpath
	]
	count(matches) > 0
}

_matches_version(version, matcher) if {
	matcher.format in {"semverv", "semver"}
	matcher.min != ""
	matcher.max != ""
	semver.compare(_to_semver(version), _to_semver(matcher.min)) != -1
	semver.compare(_to_semver(version), _to_semver(matcher.max)) != 1
} else if {
	matcher.format in {"semverv", "semver"}
	matcher.min != ""
	object.get(matcher, "max", "") == ""
	semver.compare(_to_semver(version), _to_semver(matcher.min)) != -1
} else if {
	matcher.format in {"semverv", "semver"}
	matcher.max != ""
	object.get(matcher, "min", "") == ""
	semver.compare(_to_semver(version), _to_semver(matcher.max)) != 1
} else := false

_to_semver(v) := trim_prefix(v, "v")

# Verify disallowed_packages is an array of objects
rule_data_errors contains error if {
	some e in j.validate_schema(lib.rule_data(rule_data_packages_key), {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"uniqueItems": true,
		"items": {
			"type": "object",
			"properties": {
				"purl": {"type": "string"},
				"format": {"enum": ["semver", "semverv"]},
				"min": {"type": "string"},
				"max": {"type": "string"},
				"exceptions": {
					"type": "array",
					"uniqueItems": true,
					"items": {
						"type": "object",
						"properties": {"subpath": {"type": "string"}},
					},
				},
			},
			"additionalProperties": false,
			"anyOf": [
				{"required": ["purl", "format", "min"]},
				{"required": ["purl", "format", "max"]},
			],
		},
	})
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [rule_data_packages_key, e.message]),
		"severity": e.severity,
	}
}

# Verify each item in disallowed_packages has a parseable PURL
rule_data_errors contains error if {
	some index, pkg in lib.rule_data(rule_data_packages_key)
	purl := pkg.purl
	not ec.purl.is_valid(purl)
	error := {
		"message": sprintf("Item at index %d in %s does not have a valid PURL: %q", [index, rule_data_packages_key, purl]),
		"severity": "failure",
	}
}

# Verify each item in disallowed_packages has a parseable min/max semver
rule_data_errors contains error if {
	some index, pkg in lib.rule_data(rule_data_packages_key)
	pkg.format in {"semver", "semverv"}
	some attr in ["min", "max"]

	version := _to_semver(object.get(pkg, attr, ""))
	version != ""

	not semver.is_valid(version)

	error := {
		"message": sprintf(
			"Item at index %d in %s does not have a valid %s semver value: %q",
			[index, rule_data_packages_key, attr, version],
		),
		"severity": "failure",
	}
}

# Verify disallowed_attributes is an array of name value pairs
rule_data_errors contains error if {
	some e in j.validate_schema(lib.rule_data(rule_data_attributes_key), {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"uniqueItems": true,
		"items": {
			"type": "object",
			"properties": {
				"name": {"type": "string"},
				"value": {"type": "string"},
				"effective_on": {"type": "string", "format": "date-time"},
			},
			"additionalProperties": false,
			"required": ["name"],
		},
	})
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [rule_data_attributes_key, e.message]),
		"severity": e.severity,
	}
}

# Verify allowed_external_references is an array of type/url pairs
rule_data_errors contains error if {
	some e in j.validate_schema(lib.rule_data(rule_data_allowed_external_references_key), {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"uniqueItems": true,
		"items": {
			"type": "object",
			"properties": {
				"type": {"type": "string"},
				"url": {"type": "string"},
			},
			"additionalProperties": false,
			"required": ["type", "url"],
		},
	})
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [rule_data_allowed_external_references_key, e.message]),
		"severity": e.severity,
	}
}

# Verify disallowed_external_references is an array of type/url pairs
rule_data_errors contains error if {
	some e in j.validate_schema(lib.rule_data(rule_data_disallowed_external_references_key), {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"uniqueItems": true,
		"items": {
			"type": "object",
			"properties": {
				"type": {"type": "string"},
				"url": {"type": "string"},
			},
			"additionalProperties": false,
			"required": ["type", "url"],
		},
	})

	error := {
		# regal ignore:line-length
		"message": sprintf("Rule data %s has unexpected format: %s", [rule_data_disallowed_external_references_key, e.message]),
		"severity": e.severity,
	}
}

# Verify allowed_package_sources is array of purl/regex list pairs
rule_data_errors contains error if {
	some e in j.validate_schema(
		lib.rule_data(rule_data_allowed_package_sources_key),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {
				"type": "object",
				"properties": {
					"type": {"type": "string"},
					"patterns": {
						"type": "array",
						"items": {
							"type": "string",
							"format": "regex",
						},
					},
				},
				"required": ["type", "patterns"],
				"additionalProperties": false,
			},
		},
	)

	error := {
		# regal ignore:line-length
		"message": sprintf("Rule data %s has unexpected format: %s", [rule_data_allowed_package_sources_key, e.message]),
		"severity": e.severity,
	}
}

_sbom_cyclonedx_image_path := "root/buildinfo/content_manifests/sbom-cyclonedx.json"

_sbom_spdx_image_path := "root/buildinfo/content_manifests/sbom-spdx.json"

rule_data_packages_key := "disallowed_packages"

rule_data_attributes_key := "disallowed_attributes"

rule_data_allowed_external_references_key := "allowed_external_references"

rule_data_disallowed_external_references_key := "disallowed_external_references"

rule_data_allowed_package_sources_key := "allowed_package_sources"
