package lib

# Will define built-in default values here.
# They can be overridden if required.
#
rule_data_defaults := {}

# Returns the "first found" of the following:
#   data.rule_data_custom[key_name]
#   data.rule_data[key_name]
#   rule_data_defaults[key_name]
#
# And falls back to an empty list if the key is not found anywhere.
#
rule_data(key_name) := value {
	value := data.rule_data_custom[key_name]
} else := value {
	value := data.rule_data[key_name]
} else := value {
	value := rule_data_defaults[key_name]
} else := value {
	value := []
}
