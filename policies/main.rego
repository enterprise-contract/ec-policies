package hacbs.contract.main

import data.hacbs.contract.attestation_type
import data.hacbs.contract.not_useful
import data.hacbs.contract.step_image_registries

deny[msg] {
	not skip("attestation_type")
	count(attestation_type.deny[msg]) > 0
}

deny[msg] {
	not skip("step_image_registries")
	count(step_image_registries.deny[msg]) > 0
}

deny[msg] {
	not skip("not_useful")
	count(not_useful.deny[msg]) > 0
}

skip(test_name) {
	data.config.policy.non_blocking_checks[_] == test_name
}
