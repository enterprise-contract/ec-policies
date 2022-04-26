package hacbs.contract.main

all_tests := {"chains_config", "cluster_sanity", "transparency_urls", "transparency_log_attestations", "not_useful", "test"}

test_main {
	deny with data.hacbs.contract.attestation_type.deny as {{"msg": "foo"}}
	deny with data.hacbs.contract.step_image_registries.deny as {{"msg": "foo"}}
	deny with data.hacbs.contract.not_useful.deny as {{"msg": "foo"}} with data.config.policy.non_blocking_checks as []
}

test_failing_without_skipping {
	count(deny) > 0 with data.config.policy as {"non_blocking_checks": {}}
}

test_succeeding_when_skipping_all {
	count(deny) == 0 with data.config.policy as {"non_blocking_checks": all_tests}
}

test_test_can_be_skipped {
	count(deny) > 0 with data.config.policy as {"non_blocking_checks": all_tests - {"test"}}
}

test_test_succeeds {
	count(deny) == 0 with data.test as [{"result": "SUCCESS"}] with data.config.policy as {"non_blocking_checks": all_tests - {"test"}}
}

test_test_fails {
	count(deny) > 0 with data.test as [{"result": "FAILURE"}] with data.config.policy as {"non_blocking_checks": all_tests - {"test"}}
}
