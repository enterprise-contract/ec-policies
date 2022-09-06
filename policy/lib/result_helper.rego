package lib

import data.lib.time as time_lib

result_helper(chain, failure_sprintf_params) := result {
	# The first entry in the chain always points to the active rule, even if it has
	# no declared annotations (in which case the annotations member is not present).
	# Thus, result_helper assumes every rule defines annotations.
	rule_annotations := chain[0].annotations
	result := {
		"code": rule_annotations.custom.short_name,
		"msg": sprintf(rule_annotations.custom.failure_msg, failure_sprintf_params),
		"effective_on": time_lib.when(chain),
	}
}
