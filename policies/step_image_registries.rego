package hacbs.contract.step_image_registries

import data.lib

#
# Check the image used by a particular task step and ensure it
# comes from an allowed image repo
#
deny[{"msg": msg}] {
	att := lib.all_rekor_attestations[_]

	some step_index
	step = att.data.predicate.buildConfig.steps[step_index]
	registry := concat("/", array.slice(split(step.environment.image, "/"), 0, 2))
	registry_without_tag := split(registry, "@")[0]
	not registry_is_allowed(registry_without_tag)

	msg := sprintf(
		"Step %d has disallowed registry '%s' for transparency log entry %s on %s.",
		[step_index, registry, att.log_index, att.rekor_host],
	)
}

registry_is_allowed(registry) {
	lib.config.allowed_registries[_] = registry
}
