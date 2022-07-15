package commit.main

import data.lib

test_deny {
	lib.assert_empty(deny) with input as {"signatures": ["ec@redhat.com"]}
}

test_warn {
	lib.assert_empty(warn) with input as {"signatures": ["ec@redhat.com"]}
}
