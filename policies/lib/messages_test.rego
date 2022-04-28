package lib.messages

mock_messages = {"foo": {
	"fail_message": "You have a foo problem in %s",
	"pass_message": "Your foo is looking great!",
}}

test_fail_message {
	"[foo] You have a foo problem in the kitchen" == fail_message("foo", ["the kitchen"]) with data.lib.messages.messages as mock_messages
}

test_pass_message {
	"[foo] Your foo is looking great!" == pass_message("foo") with data.lib.messages.messages as mock_messages
}
