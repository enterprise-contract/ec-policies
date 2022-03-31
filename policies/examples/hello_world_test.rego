package examples.hello_world

test_hello_world {
	allow with input as {"msg": "hello world"}
}

test_hello_werld {
	not allow with input as {"msg": "hello werld"}
}

test_hi_there {
	allow with input as {"msg": "hi there"}
}
