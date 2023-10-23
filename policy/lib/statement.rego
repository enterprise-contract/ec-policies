package lib

import future.keywords.if

# statement returns the statement for the given attestation. This is a stop gap until
# https://github.com/enterprise-contract/ec-policies/issues/756 is addressed. A good place for this
# function would be in attestations.rego. However, this function is also used in dependencies of
# attestations.rego which would cause circular imports and make everyone sad.
statement(att) := statement if {
	statement := att.statement
} else := att
