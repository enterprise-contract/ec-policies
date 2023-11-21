package lib

import future.keywords.if

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
	pkg_path := chain[count(chain) - 1].path
	pkg_name := pkg_path[count(pkg_path) - 1]
	rule_name := _rule_annotations(chain).custom.short_name
	code := sprintf("%s.%s", [pkg_name, rule_name])
}

# The first entry in the chain always points to the active rule, even if it has
# no declared annotations (in which case the annotations member is not present).
# Thus, result_helper assumes every rule defines annotations.
_rule_annotations(chain) := chain[0].annotations
