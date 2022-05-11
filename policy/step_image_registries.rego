package policies.step_image_registries

import data.allowed_registries

#
# Check the image used by a particular task step and ensure it
# comes from an allowed image repo
#

deny[msg] {
	some step_index
	step := input.predicate.buildConfig.steps[step_index]
	registry := concat("/", array.slice(split(step.environment.image, "/"), 0, 2))
	registry_without_tag := split(registry, "@")[0]
	not registry_is_allowed(registry_without_tag)

	msg := sprintf(
		"Step %d has disallowed registry '%s' for attestation.",
		[step_index, registry],
	)
}

registry_is_allowed(registry) {
	allowed_registries[_] == registry
}
