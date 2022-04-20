package hacbs.contract.main

test_main {
	deny with data.hacbs.contract.attestation_type.deny as {{"msg": "foo"}}
	deny with data.hacbs.contract.step_image_registries.deny as {{"msg": "foo"}}
	deny with data.hacbs.contract.not_useful.deny as {{"msg": "foo"}} with data.config.policy.non_blocking_checks as []
}

test_skipping {
	skip("attestation_type") with data.config.policy.non_blocking_checks as ["attestation_type"]
	not skip("attestation_type") with data.config.policy.non_blocking_checks as []
}
