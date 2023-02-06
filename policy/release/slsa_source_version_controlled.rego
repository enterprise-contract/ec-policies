#
# METADATA
# title: SLSA - Source - Version Controlled
# description: |-
#   The SLSA requirement states the following:
#
#   "Every change to the source is tracked in a version control system
#   that meets the following requirements:
#
#     [Change history] There exists a record of the history of changes
#     that went into the revision. Each change must contain: the
#     identities of the uploader and reviewers (if any), timestamps of
#     the reviews (if any) and submission, the change
#     description/justification, the content of the change, and the
#     parent revisions.
#
#     [Immutable reference] There exists a way to indefinitely reference
#     this particular, immutable revision. In git, this is the {repo URL +
#     branch/tag/ref + commit ID}.
#
#   Most popular version control system meet this requirement, such as git,
#   Mercurial, Subversion, or Perforce."
#
#   This package verifies the requirement by asserting the image was built
#   from a git repository.
#
package policy.release.slsa_source_version_controlled

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Material format
# description: |-
#   At least one entry in the predicate.materials array of the attestation contains
#   the expected attributes: uri and digest.sha1.
# custom:
#   short_name: missing_materials
#   failure_msg: No materials match expected format
#   collections:
#   - minimal
#   - slsa2
#   - slsa3
#
deny contains result if {
	count(lib.pipelinerun_attestations) > 0
	count(materials) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Material from a git repository
# description: |-
#   Each entry in the predicate.materials array of the attestation uses
#   a git URI.
# custom:
#   short_name: material_non_git_uri
#   failure_msg: Material URI %q is not a git URI
#   collections:
#   - minimal
#   - slsa2
#   - slsa3
#
deny contains result if {
	some material in materials
	not startswith(material.uri, "git+")
	result := lib.result_helper(rego.metadata.chain(), [material.uri])
}

# METADATA
# title: Material with git commit digest
# description: |-
#   Each entry in the predicate.materials array of the attestation includes
#   a SHA1 digest which corresponds to a git commit.
# custom:
#   short_name: material_without_git_commit
#   failure_msg: Material digest %q is not a git commit
#   collections:
#   - minimal
#   - slsa2
#   - slsa3
#
deny contains result if {
	some material in materials
	commit := material.digest.sha1
	not regex.match("^[a-f0-9]{40}$", commit)
	result := lib.result_helper(rego.metadata.chain(), [commit])
}

materials contains material if {
	some material in lib.pipelinerun_attestations[_].predicate.materials
	material.uri
	material.digest.sha1
}
