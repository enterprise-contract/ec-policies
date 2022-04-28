package hacbs.contract.step_image_registries

import data.lib

#
# Check the image used by a particular task step and ensure it
# comes from an allowed image repo
#
deny[{"msg": msg}] {
	att := data.attestations[_]

	some step_index
	step := att.predicate.buildConfig.steps[step_index]
	registry := concat("/", array.slice(split(step.environment.image, "/"), 0, 2))
	registry_without_tag := split(registry, "@")[0]
	not registry_is_allowed(registry_without_tag)

	msg := lib.messages.fail_message("step_image_disallowed", [step_index, registry])
}

registry_is_allowed(registry) {
	lib.config.allowed_registries[_] == registry
}
