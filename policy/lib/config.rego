package lib.config

#
# The expected type for attestations
#
expected_attestation_types := ["https://in-toto.io/Statement/v0.1"]

#
# List of allowed registries for task images used to run task steps
# This is placeholder since I have no idea what the real policy should be
#
allowed_registries := [
	"quay.io/buildah",
	"quay.io/redhat-appstudio",
	"registry.access.redhat.com/ubi8",
	"registry.access.redhat.com/ubi8-minimal",
	"registry.redhat.io/ocp-tools-4-tech-preview",
	"registry.redhat.io/openshift4",
	"registry.redhat.io/openshift-pipelines",
]
