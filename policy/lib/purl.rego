package lib.purl

import rego.v1

# Extract a repository id from a purl. These are often
# called "repoids" so we'll follow that convention.
repoid(purl) := _named_qualifier("repository_id", purl)

# (Qualifiers are similar to url params)
_named_qualifier(key, purl) := result if {
	ec.purl.is_valid(purl)
	parsed_purl := ec.purl.parse(purl)
	some qualifier in parsed_purl.qualifiers
	qualifier.key == key
	result := qualifier.value
}
