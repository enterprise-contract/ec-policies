package lib.image_test

import data.lib
import data.lib.image
import future.keywords.if

# regal ignore:rule-length
test_parse if {
	repository := "registry.com/re/po"
	repository_with_port := "registry.com:8443/re/po"
	tag := "latest"
	digest := "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"

	lib.assert_equal(
		image.parse(concat("", [repository, ":", tag, "@", digest])),
		{"repo": repository, "tag": tag, "digest": digest},
	)

	lib.assert_equal(
		image.parse(concat("", [repository, "@", digest])),
		{"repo": repository, "tag": "", "digest": digest},
	)

	lib.assert_equal(
		image.parse(concat("", [repository, ":", tag])),
		{"repo": repository, "tag": tag, "digest": ""},
	)

	lib.assert_equal(
		image.parse(concat("", [repository_with_port, ":", tag, "@", digest])),
		{"repo": repository_with_port, "tag": tag, "digest": digest},
	)

	lib.assert_equal(
		image.parse(concat("", [repository_with_port, "@", digest])),
		{"repo": repository_with_port, "tag": "", "digest": digest},
	)

	lib.assert_equal(
		image.parse(concat("", [repository_with_port, ":", tag])),
		{"repo": repository_with_port, "tag": tag, "digest": ""},
	)
}

test_equal if {
	image.equal_ref("registry.com/re/po", "registry.com/re/po")
	image.equal_ref("registry.com/re/po:tag", "registry.com/re/po:tag")
	image.equal_ref("registry.com/re/po:tag@digest", "registry.com/re/po:tag@digest")
	image.equal_ref("registry.com/re/po:different@digest", "registry.com/re/po:tag@digest")
	image.equal_ref("registry.com/re/po@digest", "registry.com/re/po:tag@digest")
	image.equal_ref("registry.com/re/po:tag@digest", "registry.com/re/po@digest")
	not image.equal_ref("registry.com/re/po", "different.com/re/po")
	not image.equal_ref("registry.com/different/po", "registry.com/re/po")
	not image.equal_ref("registry.com/re/different", "registry.com/re/po")
	not image.equal_ref("registry.com/re/po:different", "registry.com/re/po:tag")
	not image.equal_ref("registry.com/re/po:tag@different", "registry.com/re/po:tag@digest")
	not image.equal_ref("registry.com/re/po@different", "registry.com/re/po:tag@digest")
	not image.equal_ref("registry.com/re/po:tag@different", "registry.com/re/po@digest")
	not image.equal_ref("registry.com/re/po@different", "registry.com/re/po@digest")
	not image.equal_ref("registry.com/re/po@digest", "different.com/re/po@digest")
	not image.equal_ref("registry.com/re/po@digest", "registry.com/different/po@digest")
	not image.equal_ref("registry.com/re/po@digest", "registry.com/re/different@digest")
}

test_str if {
	lib.assert_equal(
		"registry.io/repository:tag@digest",
		image.str({"repo": "registry.io/repository", "tag": "tag", "digest": "digest"}),
	)
	lib.assert_equal("registry.io/repository:tag", image.str({"repo": "registry.io/repository", "tag": "tag"}))
	lib.assert_equal("registry.io/repository@digest", image.str({"repo": "registry.io/repository", "digest": "digest"}))
}
