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

	# rule_path examples:
	# ["data", "some_package", "deny"]
	# ["data", "some_package_namespace", "some_package", "deny"]
	# ["data", "namespace", "another_namespace", "some_package", "deny"]
	#
	# Our convention in the ec-policies is something like ["data", "policy",
	# "release", "some_package", "deny"], but we should stop making the
	# assumption that all the rules follow that convention.
	#
	# For now we'll just use "some_package" and hope there are no name clashes.
	# Todo: In the longer term we'll probably need the fully qualified package
	# path in some consistent way.
	pkg_name := rule_path[count(rule_path) - 2]

	# For the rule name we use the short_name annotation.
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
