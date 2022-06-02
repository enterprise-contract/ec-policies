package lib

import data.lib.time

import future.keywords.in

item_in_list(item, list_or_set) {
	# Without the in keyword it could be done like this:
	# list_or_set[_] == item
	item in list_or_set
}

list_includes_item(list_or_set, item) {
	item_in_list(item, list_or_set)
}

quoted_values_string(value_list) = result {
	quoted_list := [quoted_item |
		item := value_list[_]
		quoted_item := sprintf("'%s'", [item])
	]

	result := concat(", ", quoted_list)
}

result_helper(chain, failure_sprintf_params) = result {
	# The first entry in the chain always points to the active rule, even if it has
	# no declared annotations (in which case the annotations member is not present).
	# Thus, results_helper assumes every rule defines annotations.
	rule_annotations := chain[0].annotations
	result := {
		"code": rule_annotations.custom.short_name,
		"msg": sprintf(rule_annotations.custom.failure_msg, failure_sprintf_params),
		"effective_on": time.when(chain),
	}
}
