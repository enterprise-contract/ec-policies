package examples.attestation_checks

accepted_attestation_types := ["https://in-toto.io/Statement/v0.1"]

attestation_type_ok(attestation_type) {
	accepted_attestation_types[_] = attestation_type
}

deny = {"msg": msg} {
	not attestation_type_ok(data.attestation._type)

	quoted_list := [quoted_type |
		t := accepted_attestation_types[_]
		quoted_type := sprintf("'%s'", [t])
	]

	msg := sprintf(
		"Invalid value in attestation _type field: '%s'. Expecting one of the following: %s",
		[data.attestation._type, concat(", ", quoted_list)],
	)
}
