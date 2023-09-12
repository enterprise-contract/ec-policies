#
# METADATA
# title: Schedule related checks
# description: >-
#   Rules that verify the current date conform to a given schedule.
#
package policy.release.schedule

import future.keywords.contains
import future.keywords.if
import future.keywords.in

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
