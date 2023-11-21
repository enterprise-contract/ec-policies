package lib

import future.keywords.if
import future.keywords.in

quoted_values_string(value_list) := result if {
	quoted_list := [quoted_item |
		some item in value_list
		quoted_item := sprintf("'%s'", [item])
	]

	result := concat(", ", quoted_list)
}
