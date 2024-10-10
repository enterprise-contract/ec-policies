package lib.k8s_test

import rego.v1

import data.lib
import data.lib.k8s

test_name if {
	lib.assert_equal(k8s.name({}), "noname")
	lib.assert_equal(k8s.name(""), "noname")
	lib.assert_equal(k8s.name(123), "noname")

	lib.assert_equal(k8s.name({"metadata": {"name": "spam"}}), "spam")
}

test_version if {
	lib.assert_equal(k8s.version({}), "noversion")
	lib.assert_equal(k8s.version(""), "noversion")
	lib.assert_equal(k8s.version(123), "noversion")

	lib.assert_equal(
		k8s.version({"metadata": {"labels": {"app.kubernetes.io/version": "1.0"}}}),
		"1.0",
	)
}

test_name_version if {
	lib.assert_equal(k8s.name_version({}), "noname/noversion")
	lib.assert_equal(k8s.name_version(""), "noname/noversion")
	lib.assert_equal(k8s.name_version(123), "noname/noversion")

	lib.assert_equal(k8s.name_version({"metadata": {"name": "spam"}}), "spam/noversion")

	lib.assert_equal(
		k8s.name_version({"metadata": {"labels": {"app.kubernetes.io/version": "1.0"}}}),
		"noname/1.0",
	)

	lib.assert_equal(
		k8s.name_version({"metadata": {"name": "spam", "labels": {"app.kubernetes.io/version": "1.0"}}}),
		"spam/1.0",
	)
}
