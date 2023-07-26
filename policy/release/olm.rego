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
# title: Unpinned images in OLM bundle
# description: >-
#   Checks the OLM bundle image for the presence of unpinned image references.
#   Unpinned image pull refernces are references to images found in
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
	manifestDir := input.image.config.Labels[olm_manifestv1]

	some path, manifest in input.image.files

	# only consider files in the manifest path as determined by the OLM manifest v1 label
	startswith(path, manifestDir)

	# only consider this API prefix, disregard the version
	startswith(manifest.apiVersion, "operators.coreos.com/")

	# only consider CSV manifests
	manifest.kind == "ClusterServiceVersion"

	some i in all_image_ref(manifest)
	i.ref.digest == "" # unpinned image references have no digest

	result := lib.result_helper_with_term(rego.metadata.chain(), [image.str(i.ref), i.path], image.str(i.ref))
}

_name(o) := n if {
	n := o.name
} else := "unnamed"

# Finds all image references and their locations (paths). Returns all image
# references (parsed into components) found in locations as specified by:
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
			some i, related in manifest.spec.relatedImages
			r := {"path": sprintf("spec.relatedImages[%d].image", [i]), "ref": image.parse(related.image)}
		],
		[r |
			manifest.metadata.annotations.containerImage
			r := {"path": "annotations.containerImage", "ref": image.parse(manifest.metadata.annotations.containerImage)}
		],
		[r |
			some _, values in walk(manifest)
			some key, val in values.metadata.annotations
			some annotation in regex.split("(,|;|\\n|\\s+)", val)
			ref := image.parse(trim_space(annotation))
			ref.repo # ones that are parsed as image reference, detected by having "repo" property set
			r := {"path": sprintf("annotations[%q]", [key]), "ref": ref}
		],
		[r |
			some d, deployment in manifest.spec.install.spec.deployments
			some c, container in deployment.spec.template.spec.containers
			ref := image.parse(container.image)
			r := {"path": sprintf("spec.install.spec.deployments[%d (%q)].spec.template.spec.containers[%d (%q)].image", [d, _name(deployment), c, _name(container)]), "ref": ref}
		],
		[r |
			some d, deployment in manifest.spec.install.spec.deployments
			some c, initContainer in deployment.spec.template.spec.initContainers
			ref := image.parse(initContainer.image)
			r := {"path": sprintf("spec.install.spec.deployments[%d (%q)].spec.template.spec.initContainers[%d (%q)].image", [d, _name(deployment), c, _name(initContainer)]), "ref": ref}
		],
		[r |
			some d, deployment in manifest.spec.install.spec.deployments
			some c, container in deployment.spec.template.spec.containers
			some e in container.env
			startswith(e.name, "RELATED_IMAGE_")
			ref := image.parse(e.value)
			r := {"path": sprintf("spec.install.spec.deployments[%d (%q)].spec.template.spec.containers[%d (%q)].env[%q]", [d, _name(deployment), c, _name(container), e.name]), "ref": ref}
		],
		[r |
			some d, deployment in manifest.spec.install.spec.deployments
			some c, initContainer in deployment.spec.template.spec.initContainers
			some e in initContainer.env
			startswith(e.name, "RELATED_IMAGE_")
			ref := image.parse(e.value)
			r := {"path": sprintf("spec.install.spec.deployments[%d (%q)].spec.template.spec.initContainers[%d (%q)].env[%q]", [d, _name(deployment), c, _name(initContainer), e.name]), "ref": ref}
		],
	]
	some i in imgs
	e := {"ref": i.ref, "path": i.path}
]
