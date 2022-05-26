package lib

pipelinerun_att_build_type := "https://tekton.dev/attestations/chains/pipelinerun@v2"

taskrun_att_build_type := "https://tekton.dev/attestations/chains@v2"

# These are the ones we're interested in
pipelinerun_attestations := result {
	result := [att |
		att := input.attestations[_]
		att.predicate.buildType == pipelinerun_att_build_type
	]
}

# These ones we don't care about any more
taskrun_attestations := result {
	result := [att |
		att := input.attestations[_]
		att.predicate.buildType == taskrun_att_build_type
	]
}
