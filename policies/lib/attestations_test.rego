package lib

pr_build_type := "https://tekton.dev/attestations/chains/pipelinerun@v2"

tr_build_type := "https://tekton.dev/attestations/chains@v2"

mock_pr_att := {"predicate": {"buildType": pr_build_type}}

mock_tr_att := {"predicate": {"buildType": tr_build_type}}

garbage_att := {"predicate": {"buildType": "garbage"}}

test_pr_attestations {
	assert_equal([mock_pr_att], pipelinerun_attestations) with input.attestations as [mock_tr_att, mock_pr_att, garbage_att]
	assert_equal([], pipelinerun_attestations) with input.attestations as [mock_tr_att, garbage_att]
}

test_tr_attestations {
	assert_equal([mock_tr_att], taskrun_attestations) with input.attestations as [mock_tr_att, mock_pr_att, garbage_att]
	assert_equal([], taskrun_attestations) with input.attestations as [mock_pr_att, garbage_att]
}
