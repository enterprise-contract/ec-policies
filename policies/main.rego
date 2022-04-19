package hacbs.contract.main

import data.hacbs.contract.not_useful
import data.hacbs.contract.transparency_log_attestations

deny[msg] {
	not skip("transparency_log_attestations")
	count(transparency_log_attestations.deny[msg]) > 0
}

deny[msg] {
	not skip("not_useful")
	count(not_useful.deny[msg]) > 0
}

skip(test_name) {
	data.config.policy.non_blocking_checks[_] == test_name
}
