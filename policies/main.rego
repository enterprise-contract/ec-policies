package hacbs.contract.main

import data.hacbs.contract.chains_config
import data.hacbs.contract.cluster_sanity
import data.hacbs.contract.not_useful
import data.hacbs.contract.transparency_log_attestations
import data.hacbs.contract.transparency_urls

deny[msg] {
	not skip("chains_config")
	count(chains_config.deny[msg]) > 0
}

deny[msg] {
	not skip("cluster_sanity")
	count(cluster_sanity.deny[msg]) > 0
}

deny[msg] {
	not skip("transparency_urls")
	count(transparency_urls.deny[msg]) > 0
}

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
