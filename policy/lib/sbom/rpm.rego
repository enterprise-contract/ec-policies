package lib.sbom

import rego.v1

all_rpm_entities contains entity if {
	some sbom in all_sboms
	some entity in rpms_from_sbom(sbom)
}

rpms_from_sbom(s) := entities if {
	# CycloneDX
	entities := {entity |
		some component in s.components
		purl := component.purl
		_is_rpmish(purl)
		entity := {
			"purl": purl,
			"found_by_cachi2": _component_found_by_cachi2(component),
		}
	}
	count(entities) > 0
} else := entities if {
	# SPDX
	entities := {entity |
		some pkg in s.packages
		some ref in pkg.externalRefs
		ref.referenceType == "purl"
		ref.referenceCategory == "PACKAGE-MANAGER"
		purl := ref.referenceLocator
		_is_rpmish(purl)
		entity := {
			"purl": purl,
			"found_by_cachi2": _package_found_by_cachi2(pkg),
		}
	}
	count(entities) > 0
}

# Match rpms and modules
# (Use a string match instead of parsing it and checking the type)
_is_rpmish(purl) if {
	startswith(purl, "pkg:rpm/")
} else if {
	startswith(purl, "pkg:rpmmod/")
}

_component_found_by_cachi2(component) if {
	some property in component.properties
	property == cachi2_found_by_property
} else := false

# This is what cachi2 produces in the component property list
cachi2_found_by_property := {
	"name": "cachi2:found_by",
	"value": "cachi2",
}

_package_found_by_cachi2(pkg) if {
	some annotation in pkg.annotations
	regex.match(`.*cachi2.*`, annotation.annotator)
	annotation.annotationType == "OTHER"
	# `comment` contains additional information, but that is not needed for the purpose of
	# simply filtering what was found by cachi2.
} else := false
