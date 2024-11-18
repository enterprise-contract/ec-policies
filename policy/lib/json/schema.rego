package lib.json

import rego.v1

# Validates schema reporting the error message as well as the severity
validate_schema(doc, schema) := issues if {
	count(_arg_issues(doc, schema)) == 0
	issues := _validation_issues(doc, schema)
} else := _arg_issues(doc, schema)

_validation_issues(doc, schema) := issues if {
	not is_null(doc)
	not is_null(schema)
	d := _prepare_document(doc)
	ok_error := json.match_schema(d, schema)
	ok := ok_error[0]
	not ok
	errors := ok_error[1]
	issues := [i |
		some e in errors
		i := {
			"message": e.error, # e.desc is ignored, seems to repeat what is in e.error
			"severity": _severity(e),
		}
	]
}

_arg_issues(doc, schema) := [i |
	some check in [
		{is_null(doc) == false: "Provided empty document for schema validation"},
		{is_null(schema) == false: "Provided empty schema for schema validation"},
		_check_schema(schema),
	]
	some ok, msg in check
	not ok
	i := {
		"message": msg,
		"severity": "failure",
	}
]

_check_schema(schema) := ok_msg if {
	not is_null(schema)
	ok_error := json.verify_schema(schema)
	ok := ok_error[0]
	not ok
	error := ok_error[1]
	ok_msg := {false: sprintf("Provided schema is not a valid JSON Schema: %s", [error])}
} else := {true, ""}

_prepare_document(doc) := d if {
	is_array(doc)

	# match_schema expects either a marshaled JSON resource (String) or an
	# Object. It doesn't handle an Array directly.
	d := json.marshal(doc)
} else := doc

_severity(e) := "warning" if {
	startswith(e.desc, "Additional property")
} else := "failure"
