package lib_test

import rego.v1

import data.lib

test_sigstore_opts if {
	lib.assert_equal(lib.sigstore_opts, {
		"certificate_identity": "",
		"certificate_identity_regexp": "",
		"certificate_oidc_issuer": "",
		"certificate_oidc_issuer_regexp": "",
		"ignore_rekor": false,
		"public_key": "",
		"rekor_url": "",
	})

	opts := {
		"certificate_identity": "subject",
		"certificate_identity_regexp": "subject-regexp",
		"certificate_oidc_issuer": "issuer",
		"certificate_oidc_issuer_regexp": "issuer-regexp",
		"ignore_rekor": true,
		"public_key": "public-key",
		"rekor_url": "https://rekor.local",
	}
	lib.assert_equal(lib.sigstore_opts, opts) with data.config.default_sigstore_opts as opts
}
