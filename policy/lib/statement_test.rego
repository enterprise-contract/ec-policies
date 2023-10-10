package lib_test

import future.keywords.if

import data.lib

test_statement if {
	stmt := {"predicateType": "spam"}
	lib.assert_equal(stmt, lib.statement(stmt))
	lib.assert_equal(stmt, lib.statement({"statement": stmt}))
}
