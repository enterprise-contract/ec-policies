package lib.messages

import data.lib

#
# If we extract the static parts this could become a big yaml file maybe...
# Ps, wtf is opa fmt doing here.. :/
messages := {"step_image_disallowed": {
	"fail_message": "Step %d has disallowed registry '%s' for attestation.",
	"pass_message": sprintf(
		"All task steps run on images from the allowed registries: %s",
		[lib.quoted_values_string(lib.config.allowed_registries)],
	),
}}

# Imagine many other keys in this hash, one for each kind of failure,
# and then imagine (somehow) producing a list of all the pass_messages
# that are not already included in the failure output.

fail_message(message_key, sprintf_values) = message {
	# Could return a hash with a keys like "fail_code" and "reason" in future maybe instead
	# of just a string by itself
	full_message_template := concat("", ["[%s] ", messages[message_key].fail_message])
	message := sprintf(full_message_template, array.concat([message_key], sprintf_values))
}

pass_message(message_key) = message {
	full_message_template := concat("", ["[%s] ", messages[message_key].pass_message])
	message := sprintf(full_message_template, [message_key])
}
