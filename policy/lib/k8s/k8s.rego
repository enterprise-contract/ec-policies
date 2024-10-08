package lib.k8s

import rego.v1

# name returns the name of the resource. If a name is not defined, "noname" is returned. This
# function always returns a value.
name(resource) := name if {
	name := resource.metadata.name
} else := "noname"

# version returns the version of the resource as defined via the "app.kubernetes.io/version" label.
# This is NOT the API Version of the resource. More info about this label in
# https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/#labels
# If a version is not defined, "noversion" is returned. This function always returns a value.
version(resource) := version if {
	version := resource.metadata.labels["app.kubernetes.io/version"]
} else := "noversion"

# name_version is a convenience function that returns the resource's name and version. This
# function always returns a value.
name_version(resource) := sprintf("%s/%s", [name(resource), version(resource)])
