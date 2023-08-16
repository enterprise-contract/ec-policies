#
# METADATA
# title: GitHub Certificate Checks
# description: >-
#   Verify attributes on the certificate involved in the image signature when using
#   slsa-github-generator on GitHub Actions with Sigstore Fulcio
#
package policy.release.github_certificate

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: GitHub Workflow Certificate Extensions
# description: >-
#   Check if the image signature certificate contains the expected GitHub
#   extensions. These are the extensions that represent the GitHub workflow
#   trigger, sha, name, repository, and ref.
# custom:
#   short_name: gh_workflow_extensions
#   failure_msg: 'Missing extension %q'
#
warn contains result if {
	some extension in [_TRIGGER, _SHA, _NAME, _REPOSITORY, _REF]
	not _fulcio_extension_value(extension)
	result := lib.result_helper(rego.metadata.chain(), [extension.name])
}

# METADATA
# title: GitHub Workflow Repository
# description: >-
#   Check if the value of the GitHub Workflow Repository extension in the image
#   signature certificate matches one of the allowed values. Use the rule data
#   key `allowed_gh_workflow_repos` to specify the list of allowed values.
#   An empty allow list, which is the default value, causes this check to succeeded.
# custom:
#   short_name: gh_workflow_repository
#   failure_msg: 'Repository %q not in allowed list: %v'
#
deny contains result if {
	result := _check_extension(rego.metadata.chain(), "allowed_gh_workflow_repos", _REPOSITORY)
}

# METADATA
# title: GitHub Workflow Repository
# description: >-
#   Check if the value of the GitHub Workflow Ref extension in the image
#   signature certificate matches one of the allowed values. Use the rule data
#   key `allowed_gh_workflow_refs` to specify the list of allowed values.
#   An empty allow list, which is the default value, causes this check to succeeded.
# custom:
#   short_name: gh_workflow_ref
#   failure_msg: 'Ref %q not in allowed list: %v'
#
deny contains result if {
	result := _check_extension(rego.metadata.chain(), "allowed_gh_workflow_refs", _REF)
}

# METADATA
# title: GitHub Workflow Name
# description: >-
#   Check if the value of the GitHub Workflow Name extension in the image
#   signature certificate matches one of the allowed values. Use the rule data
#   key `allowed_gh_workflow_names` to specify the list of allowed values.
#   An empty allow list, which is the default value, causes this check to succeeded.
# custom:
#   short_name: gh_workflow_name
#   failure_msg: 'Name %q not in allowed list: %v'
#
deny contains result if {
	result := _check_extension(rego.metadata.chain(), "allowed_gh_workflow_names", _NAME)
}

# METADATA
# title: GitHub Workflow Trigger
# description: >-
#   Check if the value of the GitHub Workflow Trigger extension in the image
#   signature certificate matches one of the allowed values. Use the rule data
#   key `allowed_gh_workflow_triggers` to specify the list of allowed values.
#   An empty allow list, which is the default value, causes this check to succeeded.
# custom:
#   short_name: gh_workflow_trigger
#   failure_msg: 'Trigger %q not in allowed list: %v'
#
deny contains result if {
	result := _check_extension(rego.metadata.chain(), "allowed_gh_workflow_triggers", _TRIGGER)
}

_check_extension(chain, key, extension) := result if {
	value := _fulcio_extension_value(extension)
	allowed := lib.rule_data(key)
	count(allowed) > 0
	not value in allowed
	result := lib.result_helper(chain, [value, allowed])
}

_certs contains cert if {
	some sig in input.image.signatures
	cert := crypto.x509.parse_certificates(sig.certificate)[0]
	cert.KeyUsage == 1
	cert.ExtKeyUsage == [3]
}

_fulcio_extension_value(ext) := value if {
	id := [1, 3, 6, 1, 4, 1, 57264, 1, ext.id]
	some cert in _certs
	some extension in cert.Extensions
	extension.Id == id
	value := base64.decode(extension.Value)
}

_TRIGGER := {"id": 2, "name": "GitHub Workflow Trigger"}

_SHA := {"id": 3, "name": "GitHub Workflow SHA"}

_NAME := {"id": 4, "name": "GitHub Workflow Name"}

_REPOSITORY := {"id": 5, "name": "GitHub Workflow Repository"}

_REF := {"id": 6, "name": "GitHub Workflow Ref"}
