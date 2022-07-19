package policy.release.signature

import data.lib

# METADATA
# title: Signatures is a valid email address
# description: |-
#   Enterprise Contract verifies if a valid email address was used to sign a commit 
# custom:
#   short_name: disallowed_commit_signature_email
#   failure_msg: Signature %s in commit %s is not a valid email address
warn[result] {
	signature := input.signatures[_]
	email := split(signature, "@")
	count(email) != 2
	result := lib.result_helper(rego.metadata.chain(), [signature, input.body.sha])
}

# METADATA
# title: Signatures in a commit that are disallowed
# description: |-
#   Enterprise Contract has a list of allowed domains that a commit can be signed
#   off with.
# custom:
#   short_name: disallowed_commit_signature_domain
#   failure_msg: Signature %s in commit %s has disallowed domain
#   rule_data:
#     allowed_email_domains:
#     - redhat.com
warn[result] {
	signature := input.signatures[_]
	domain := split(signature, "@")
	not known_domains(domain[1], rego.metadata.rule().custom.rule_data.allowed_email_domains)
	result := lib.result_helper(rego.metadata.chain(), [signature, input.body.sha])
}

known_domains(domain, allowed_email_domains) {
	lib.item_in_list(lower(domain), allowed_email_domains)
}
