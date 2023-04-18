#
# METADATA
# title: Provenance Materials
# description: >-
#   This package provides rules for verifying the contents of the materials section
#   of the SLSA Provenance attestation.
#
package policy.release.provenance_materials

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.tkn

# METADATA
# title: Task git-clone missing
# description: >-
#   The attestation must contain a git-clone task with the expected commit and url results.
# custom:
#   short_name: missing_git_clong_task
#   failure_msg: Task git-clone not found
#   collections:
#   - minimal
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	not tkn.git_clone_task(attestation)
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Git repo materials mismatch
# description: >-
#   The result of the git-clone task must be included in the materials section of the SLSA
#   provenance attestation.
# custom:
#   short_name: git_repo_materials_mismatch
#   failure_msg: Entry in materials for the git repo %q and commit %q not found
#   collections:
#   - minimal
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations

	t := tkn.git_clone_task(attestation)
	url := _normalize_git_url(tkn.task_result(t, "url"))
	commit := tkn.task_result(t, "commit")

	materials := [m |
		some m in attestation.predicate.materials
		m.uri == url
		m.digest.sha1 == commit
	]
	count(materials) == 0

	result := lib.result_helper(rego.metadata.chain(), [url, commit])
}

_normalize_git_url(url) := normalized if {
	normalized := _suffix_git_url(_prefix_git_url(url))
}

_prefix_git_url(url) := normalized if {
	prefix := "git+"
	not strings.any_prefix_match(url, prefix)
	normalized := concat("", [prefix, url])
} else := normalized if {
	normalized := url
}

_suffix_git_url(url) := normalized if {
	suffix := ".git"
	not strings.any_suffix_match(url, suffix)
	normalized := concat("", [url, suffix])
} else := normalized if {
	normalized := url
}
