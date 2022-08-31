package lib

import data.lib.time

result_helper(chain, failure_sprintf_params) := result {
	# The first entry in the chain always points to the active rule, even if it has
	# no declared annotations (in which case the annotations member is not present).
	# Thus, result_helper assumes every rule defines annotations.
	rule_annotations := chain[0].annotations
	rule_name := chain[0].path[count(chain[0].path) - 1]
	result := {
		"code": trim_prefix(trim_prefix(rule_name, "deny_"), "warn_"),
		"msg": sprintf(rule_annotations.custom.failure_msg, failure_sprintf_params),
		"effective_on": time.when(chain),
	}
}
