package lib

import rego.v1

import data.lib.time as time_lib

result_helper(chain, failure_sprintf_params) := result if {
	with_collections := {"collections": _rule_annotations(chain).custom.collections}
	result := object.union(_basic_result(chain, failure_sprintf_params), with_collections)
} else := result if {
	result := _basic_result(chain, failure_sprintf_params)
}

result_helper_with_term(chain, failure_sprintf_params, term) := object.union(
	result_helper(chain, failure_sprintf_params),
	{"term": term},
)

_basic_result(chain, failure_sprintf_params) := {
	"code": _code(chain),
	"msg": sprintf(_rule_annotations(chain).custom.failure_msg, failure_sprintf_params),
	"effective_on": time_lib.when(chain),
}

_code(chain) := code if {
	rule_path := chain[0].path
	pkg_name := _pkg_name(rule_path)

	# Todo someday maybe: Conftest supports denies named deny_some_name,
	# so we could use that format and ditch the short name annotation.
	rule_name := _rule_annotations(chain).custom.short_name

	# Put them together
	code := sprintf("%s.%s", [pkg_name, rule_name])
}

# The first entry in the chain always points to the active rule, even if it has
# no declared annotations (in which case the annotations member is not present).
# Thus, result_helper assumes every rule defines annotations. At the very least
# custom.short_name must be present.
_rule_annotations(chain) := chain[0].annotations

# This is meant to match the special handling done in ec-cli, see here:
# https://github.com/enterprise-contract/ec-cli/blob/014a488a4/internal/opa/rule/rule.go#L161-L186
_pkg_name(rule_path) := name if {
	# Seems to not work if I keep assigning to a single var, so
	# that's why the many different pN vars.

	# Strip off the first element which is always "data"
	p1 := _left_strip_elements(["data"], rule_path)

	# Strip off policy.release or policy.pipeline to match what ec-cli
	# does. (There are some edge cases where the behavior is not exactly
	# the same, but I think this version is better.)
	p2 := _left_strip_elements(["release"], p1)
	p3 := _left_strip_elements(["pipeline"], p2)

	# Actually ec-cli doesn't remove these, but lots of tests in this repo
	# assume it will be removed, so let's go with the flow for now.
	# (We might want to revist this behavior in future.)
	p4 := _left_strip_elements(["task"], p3)
	p5 := _left_strip_elements(["build_task"], p4)

	# Strip off "policy" no matter what
	p6 := _left_strip_elements(["policy"], p5)

	# Remove the "deny" or "warn" element
	p7 := _right_strip_elements(["deny"], p6)
	p8 := _right_strip_elements(["warn"], p7)

	# Put it all together with dots in between
	name := concat(".", p8)
}

_left_strip_elements(items_to_strip, list) := new_list if {
	items_to_strip_count := count(items_to_strip)
	array.slice(list, 0, items_to_strip_count) == items_to_strip
	new_list := array.slice(list, items_to_strip_count, count(list))
} else := list

_right_strip_elements(items_to_strip, list) := array.reverse(_left_strip_elements(items_to_strip, array.reverse(list)))
