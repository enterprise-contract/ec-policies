package lib.image

import data.lib

test_parse {
	repository := "registry.com/re/po"
	repository_with_port := "registry.com:8443/re/po"
	tag := "latest"
	digest := "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"

	lib.assert_equal(
		parse(concat("", [repository, ":", tag, "@", digest])),
		{"repo": repository, "tag": tag, "digest": digest},
	)

	lib.assert_equal(
		parse(concat("", [repository, "@", digest])),
		{"repo": repository, "tag": "", "digest": digest},
	)

	lib.assert_equal(
		parse(concat("", [repository, ":", tag])),
		{"repo": repository, "tag": tag, "digest": ""},
	)

	lib.assert_equal(
		parse(concat("", [repository_with_port, ":", tag, "@", digest])),
		{"repo": repository_with_port, "tag": tag, "digest": digest},
	)

	lib.assert_equal(
		parse(concat("", [repository_with_port, "@", digest])),
		{"repo": repository_with_port, "tag": "", "digest": digest},
	)

	lib.assert_equal(
		parse(concat("", [repository_with_port, ":", tag])),
		{"repo": repository_with_port, "tag": tag, "digest": ""},
	)
}
