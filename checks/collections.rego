package checks

import future.keywords.contains
import future.keywords.if
import future.keywords.in

violation contains msg if {
	some collection, def in data.rule_collections
	missing := [r |
		some r in array.concat(def.include, def.exclude)
		r != "*"
		not input.namespaces[sprintf("data.policy.release.%s", [r])]
	]
	count(missing) > 0
	msg := sprintf("ERROR: The collection `%s` references non-existant package(s): %s", [collection, concat(", ", missing)])
}
