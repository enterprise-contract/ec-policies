package lib.purl_test

import rego.v1

import data.lib
import data.lib.purl

# regal ignore:line-length
_good := "pkg:rpm/rhel/bash@5.1.8-9.el9?arch=aarch64&upstream=bash-5.1.8-9.el9.src.rpm&distro=rhel-9.4&repository_id=some-repo-id"

_bad := [
	# regal ignore:line-length
	"pkg:rpm/rhel/bash@5.1.8-9.el9?arch=aarch64&upstream=bash-5.1.8-9.el9.src.rpm&distro=rhel-9.4&repostory_id=some-repo-id",
	"pkg:rpm/rhel/bash@5.1.8-9.el9?arch=aarch64&upstream=bash-5.1.8-9.el9.src.rpm&distro=rhel-9.4",
	"pkg:golang/k8s.io/client-go@v0.29.4",
	"this-is-not-a-valid-purl",
]

test_purl_repoid if {
	lib.assert_equal("some-repo-id", purl.repoid(_good))
	lib.assert_empty([purl.repoid(p) | some p in _bad])
}

# This behavior has test coverage in the ec-cli repo already but let's
# exercise it here anyway since it's low cost and serves as a handy demo
test_purl_parse if {
	parsed := ec.purl.parse(_good)
	lib.assert_equal("rpm", parsed.type)
	lib.assert_equal("rhel", parsed.namespace)
	lib.assert_equal("bash", parsed.name)
	lib.assert_equal("", parsed.subpath)
	lib.assert_equal("5.1.8-9.el9", parsed.version)
	lib.assert_equal("arch", parsed.qualifiers[0].key)
	lib.assert_equal("aarch64", parsed.qualifiers[0].value)
}
