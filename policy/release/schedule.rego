#
# METADATA
# title: Schedule related checks
# description: >-
#   Rules that verify the current date conform to a given schedule.
#
package policy.release.schedule

import rego.v1

import data.lib

# METADATA
# title: Weekday Restriction
# description: >-
#   Check if the current weekday is allowed based on the rule data value from the key
#   `disallowed_weekdays`. By default, the list is empty in which case *any* weekday is allowed.
# custom:
#   short_name: weekday_restriction
#   failure_msg: '%s is a disallowed weekday: %s'
#   solution: Try again on a different weekday.
#   collections:
#   - redhat
#
deny contains result if {
	today := lower(time.weekday(lib.time.effective_current_time_ns))
	disallowed := {lower(w) | some w in lib.rule_data("disallowed_weekdays")}
	count(disallowed) > 0
	today in disallowed
	result := lib.result_helper(rego.metadata.chain(), [today, concat(", ", disallowed)])
}

# METADATA
# title: Date Restriction
# description: >-
#   Check if the current date is not allowed based on the rule data value
#   from the key `disallowed_dates`. By default, the list is empty in which
#   case *any* day is allowed.
# custom:
#   short_name: date_restriction
#   failure_msg: '%s is a disallowed date: %s'
#   solution: Try again on a different day.
#   collections:
#   - redhat
#
deny contains result if {
	today := time.format([lib.time.effective_current_time_ns, "UTC", "2006-01-02"])
	disallowed := lib.rule_data("disallowed_dates")
	today in disallowed
	result := lib.result_helper(rego.metadata.chain(), [today, concat(", ", disallowed)])
}

# METADATA
# title: Rule data provided
# description: >-
#   Confirm the expected rule data keys have been provided in the expected format. The keys are
#   `disallowed_weekdays` and `disallowed_dates`.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#   collections:
#   - redhat
#   - policy_data
#
deny contains result if {
	some error in _rule_data_errors
	result := lib.result_helper(rego.metadata.chain(), [error])
}

_rule_data_errors contains msg if {
	key := "disallowed_weekdays"

	# JSON Schema doesn't allow case insensitive enum types. So here we define a list of all the
	# weekdays as "title-case", lower case, and upper case.
	titled_weekdays := ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
	weekdays := array.concat(
		array.concat(
			titled_weekdays,
			[lower(d) | some d in titled_weekdays],
		),
		[upper(d) | some d in titled_weekdays],
	)

	# match_schema expects either a marshaled JSON resource (String) or an Object. It doesn't
	# handle an Array directly.
	value := json.marshal(lib.rule_data(key))
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"enum": weekdays},
			"uniqueItems": true,
		},
	)[1]
	msg := sprintf("Rule data %s has unexpected format: %s", [key, violation.error])
}

_rule_data_errors contains msg if {
	# IMPORTANT: Although the JSON schema spec does allow specifying a regular expression to match
	# values, via the "pattern" attribute, rego's JSON schema validator does not:
	# https://github.com/open-policy-agent/opa/issues/6089
	key := "disallowed_dates"

	# match_schema expects either a marshaled JSON resource (String) or an Object. It doesn't
	# handle an Array directly.
	value := json.marshal(lib.rule_data(key))
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
		},
	)[1]
	msg := sprintf("Rule data %s has unexpected format: %s", [key, violation.error])
}

_rule_data_errors contains msg if {
	key := "disallowed_dates"
	some index, date in lib.rule_data(key)
	not time.parse_ns("2006-01-02", date)
	msg := sprintf("Rule data %s has unexpected format: %d: Invalid date %q", [key, index, date])
}
