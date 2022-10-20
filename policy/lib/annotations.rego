package lib

rule_data(metadata, name) = value {
	value := metadata.custom.rule_data[name]
}
