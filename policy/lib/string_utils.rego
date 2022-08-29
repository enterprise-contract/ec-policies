package lib

quoted_values_string(value_list) = result {
	quoted_list := [quoted_item |
		item := value_list[_]
		quoted_item := sprintf("'%s'", [item])
	]

	result := concat(", ", quoted_list)
}
