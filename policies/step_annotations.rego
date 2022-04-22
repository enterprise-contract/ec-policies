package hacbs.contract.step_annotations

import data.lib

deny[{"msg": msg}] {
	att := data.attestations[_]

	some step_index

	# null annotations show up when there are none defined
	# can there be null annotations?
	att.predicate.buildConfig.steps[step_index].annotations != null

	# if an annotations is defined, it shows up in a list
	annotations := [x | x := att.predicate.buildConfig.steps[step_index].annotations[_]; not valid_annotation(x)]
	annotations != []
	msg := sprintf(
		"step %d has invalid annotations(s): %s",
		[step_index, annotations],
	)
}

valid_annotation(annotation) {
	lib.config.allowed_annotations[_] == annotation
}
