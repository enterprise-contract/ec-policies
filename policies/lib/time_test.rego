# METADATA
# custom:
#   effective_on: 2001-02-03T00:00:00Z
#   scope: package
package lib.time

# METADATA
# custom:
#   effective_on: 2004-05-06T00:00:00Z
test_when_rule_precedence {
	when(rego.metadata.chain()) == "2004-05-06T00:00:00Z"
}

test_when_package_precedence {
	when(rego.metadata.chain()) == "2001-02-03T00:00:00Z"
}
