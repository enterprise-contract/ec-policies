#
# METADATA
# description: >-
#   Checks for Operator Lifecycle Manager (OLM) bundles.
#
package policy.release.olm

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.image

olm_manifestv1 := "operators.operatorframework.io.bundle.manifests.v1"

# METADATA
# title: ClusterServiceVersion semver format
# description: >-
#   Check the `spec.version` value in the ClusterServiceVersion manifest of the OLM bundle uses a
#   properly formatted semver.
# custom:
#   short_name: csv_semver_format
#   failure_msg: 'The ClusterServiceVersion spec.version, %q, is not a valid semver'
#   solution: >-
#     Update the ClusterServiceVersion manifest of the OLM bundle to set the spec.version value to
#     a valid semver.
#   collections:
#   - redhat
#
deny contains result if {
	some manifest in _csv_manifests
	version := object.get(manifest, ["spec", "version"], "<MISSING>")
	not semver.is_valid(version)
	result := lib.result_helper(rego.metadata.chain(), [version])
}

# METADATA
# title: Unpinned images in OLM bundle
# description: >-
#   Check the OLM bundle image for the presence of unpinned image references.
#   Unpinned image pull references are references to images found in
#   link:https://osbs.readthedocs.io/en/latest/users.html#pullspec-locations[varying
#   locations] that do not contain a digest -- uniquely identifying the version of
#   the image being pulled.
# custom:
#   short_name: unpinned_references
#   failure_msg: The %q image reference is not pinned at %s.
#   solution: >-
#     Update the OLM bundle replacing the unpinned image reference with pinned image
#     reference. Pinned image reference contains the image digest.
#   collections:
#   - redhat
#
deny contains result if {
	some manifest in _csv_manifests

	some i in all_image_ref(manifest)
	i.ref.digest == "" # unpinned image references have no digest

	result := lib.result_helper_with_term(rego.metadata.chain(), [image.str(i.ref), i.path], image.str(i.ref))
}

# METADATA
# title: Feature annotations have expected value
# description: >-
#   Check the feature annotations in the ClusterServiceVersion manifest of the OLM bundle. All of
#   required feature annotations must be present and set to either the string `"true"` or the string
#   `"false"`. The list of feature annotations can be customize via the
#   `required_olm_features_annotations` rule data.
# custom:
#   short_name: feature_annotations_format
#   failure_msg: The annotation %q is either missing or has an unexpected value
#   solution: >-
#     Update the ClusterServiceVersion manifest of the OLM bundle to set the feature annotations
#     to the expected value.
#   collections:
#   - redhat
#
deny contains result if {
	some manifest in _csv_manifests
	some annotation in lib.rule_data(_rule_data_key)
	value := object.get(manifest.metadata.annotations, annotation, "")
	not value in {"true", "false"}
	result := lib.result_helper_with_term(rego.metadata.chain(), [annotation], annotation)
}

# METADATA
# title: Required OLM feature annotations list provided
# description: >-
#   Confirm the `required_olm_features_annotations` rule data was provided, since it's
#   required by the policy rules in this package.
# custom:
#   short_name: required_olm_features_annotations_provided
#   failure_msg: "%s"
#   collections:
#   - redhat
#   - policy_data
#
deny contains result if {
	some error in _rule_data_errors
	result := lib.result_helper(rego.metadata.chain(), [error])
}

_name(o) := n if {
	n := o.name
} else := "unnamed"

# Finds all image references and their locations (paths). Returns all image
# references (parsed into components) found in locations as specified by:
# regal ignore:line-length
# https://github.com/containerbuildsystem/operator-manifest/blob/f24cd9374f5ad9fed04f47701acffa16837d940e/README.md#pull-specifications
# and https://osbs.readthedocs.io/en/latest/users.html#pullspec-locations
all_image_ref(manifest) := [e |
	# NOTE: use comprehensions in here, trying to set a value for `imgs` that
	# could be undefined will lead to the whole block being undefined, i.e.
	# don't do:
	# [
	#	{
	#      "path": "manifest.metadata.annotations.containerImage",
	#      "ref":image.parse(manifest.metadata.annotations.containerImage)
	#   }
	# ]
	# as the components of manifest.metadata.annotations.containerImage could be undefined!
	some imgs in [
		[r |
			# regal ignore:prefer-snake-case
			some i, related in manifest.spec.relatedImages
			r := {"path": sprintf("spec.relatedImages[%d].image", [i]), "ref": image.parse(related.image)}
		],
		[r |
			# regal ignore:prefer-snake-case
			manifest.metadata.annotations.containerImage
			r := {
				"path": "annotations.containerImage",
				"ref": image.parse(manifest.metadata.annotations.containerImage),
			}
		],
		[r |
			some _, values in walk(manifest)
			some key, val in values.metadata.annotations
			some annotation in regex.split(`(,|;|\n|\s+)`, val)
			ref := image.parse(trim_space(annotation))
			ref.repo # ones that are parsed as image reference, detected by having "repo" property set
			r := {"path": sprintf("annotations[%q]", [key]), "ref": ref}
		],
		[r |
			some d, deployment in manifest.spec.install.spec.deployments
			some c, container in deployment.spec.template.spec.containers
			ref := image.parse(container.image)
			r := {
				"path": sprintf(
					"spec.install.spec.deployments[%d (%q)].spec.template.spec.containers[%d (%q)].image",
					[d, _name(deployment), c, _name(container)],
				),
				"ref": ref,
			}
		],
		[r |
			some d, deployment in manifest.spec.install.spec.deployments

			# regal ignore:prefer-snake-case
			some c, initContainer in deployment.spec.template.spec.initContainers
			ref := image.parse(initContainer.image)
			r := {
				"path": sprintf(
					"spec.install.spec.deployments[%d (%q)].spec.template.spec.initContainers[%d (%q)].image",
					[d, _name(deployment), c, _name(initContainer)],
				),
				"ref": ref,
			}
		],
		[r |
			some d, deployment in manifest.spec.install.spec.deployments
			some c, container in deployment.spec.template.spec.containers
			some e in container.env
			startswith(e.name, "RELATED_IMAGE_")
			ref := image.parse(e.value)
			r := {
				"path": sprintf(
					"spec.install.spec.deployments[%d (%q)].spec.template.spec.containers[%d (%q)].env[%q]",
					[d, _name(deployment), c, _name(container), e.name],
				),
				"ref": ref,
			}
		],
		[r |
			some d, deployment in manifest.spec.install.spec.deployments

			# regal ignore:prefer-snake-case
			some c, initContainer in deployment.spec.template.spec.initContainers
			some e in initContainer.env
			startswith(e.name, "RELATED_IMAGE_")
			ref := image.parse(e.value)
			r := {
				"path": sprintf(
					"spec.install.spec.deployments[%d (%q)].spec.template.spec.initContainers[%d (%q)].env[%q]",
					[d, _name(deployment), c, _name(initContainer), e.name],
				),
				"ref": ref,
			}
		],
	]
	some i in imgs
	e := {"ref": i.ref, "path": i.path}
]

# Returns the ClusterServiceVersion manifests found in the OLM bundle.
_csv_manifests contains manifest if {
	manifest_dir := input.image.config.Labels[olm_manifestv1]

	some path, manifest in input.image.files

	# only consider files in the manifest path as determined by the OLM manifest v1 label
	startswith(path, manifest_dir)

	# only consider this API prefix, disregard the version
	# regal ignore:prefer-snake-case
	startswith(manifest.apiVersion, "operators.coreos.com/")

	# only consider CSV manifests
	manifest.kind == "ClusterServiceVersion"
}

# Verify allowed_registry_prefixes is a non-empty list of strings
_rule_data_errors contains msg if {
	# match_schema expects either a marshaled JSON resource (String) or an Object. It doesn't
	# handle an Array directly.
	value := json.marshal(lib.rule_data(_rule_data_key))
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
			"minItems": 1,
		},
	)[1]
	msg := sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, violation.error])
}

_rule_data_key := "required_olm_features_annotations"
