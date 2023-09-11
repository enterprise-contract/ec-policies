package policy.release.slsa_source_correlated

import future.keywords.in

import data.lib

test_warn_missing_source_code_happy_day {
	lib.assert_empty(warn) with input.image as {"source": {"something": "here"}}
}

test_warn_missing_expected_source_code_reference {
	expected := {{
		"code": "slsa_source_correlated.expected_source_code_reference",
		"msg": "Expected source code reference was not provided for verification",
	}}
	lib.assert_equal_results(warn, expected) with input as {}
	lib.assert_equal_results(warn, expected) with input.image as {}
	lib.assert_equal_results(warn, expected) with input.image as {"source": {}}
}

test_deny_material_code_reference {
	# no source materials
	lib.assert_equal_results(deny, {{"code": "slsa_source_correlated.attested_source_code_reference", "msg": "The attested material contains no source code reference"}}) with input.image as expected
		with input.attestations as [_material_attestation([]), _resolvedDependencies_attestation([])]

	# unsupported scm SLSA Provenance v0.2
	lib.assert_equal_results(deny, {{"code": "slsa_source_correlated.attested_source_code_reference", "msg": "The attested material contains no source code reference"}}) with input.image as expected
		with input.attestations as [_source_material_attestation("xyz+https://some.repository", "ref")]

	# unsupported scm SLSA Provenance v1.0
	lib.assert_equal_results(deny, {{"code": "slsa_source_correlated.attested_source_code_reference", "msg": "The attested material contains no source code reference"}}) with input.image as expected
		with input.attestations as [_source_resolvedDependencies_attestation("xyz+https://some.repository", "ref")]
}

test_deny_expected_source_code_reference_happy_day {
	# one material matches expected SLSA Provenance v0.2
	lib.assert_empty(deny) with input.image as expected
		with input.attestations as [_source_material_attestation("git+https://git.repository", "ref")]

	# one material matches expected SLSA Provenance v1.0
	lib.assert_empty(deny) with input.image as expected
		with input.attestations as [_source_resolvedDependencies_attestation("git+https://git.repository", "ref")]

	dependencies := [
		{
			"uri": "registry.io/repository/image",
			"digest": {"sha256": "cafe"},
		},
		{
			"uri": "git+https://git.repository",
			"digest": {"sha1": "ref"},
		},
		{
			"uri": "registry.io/repository/image2",
			"digest": {"sha256": "dada"},
		},
	]

	# more than one material, one matches expected the others are unrelated
	lib.assert_empty(deny) with input.image as expected
		with input.attestations as [
			_material_attestation(dependencies),
			_resolvedDependencies_attestation(dependencies),
		]

	# more than one material, one matches expected the other doesn't, this is,
	# currently not a failure SLSA Provenance v0.2
	#
	# TODO: most likely we want to distinguish what source was built from what
	# source references were used by the build
	lib.assert_empty(deny) with input.image as expected
		with input.attestations as [_source_material_attestation("git+https://git.repository", "ref"), _source_material_attestation("git+https://unexpected.repository", "unexpected")]

	# more than one material, one matches expected the other doesn't, this is,
	# currently not a failure SLSA Provenance v1.0
	#
	# TODO: most likely we want to distinguish what source was built from what
	# source references were used by the build
	lib.assert_empty(deny) with input.image as expected
		with input.attestations as [_source_resolvedDependencies_attestation("git+https://git.repository", "ref"), _source_material_attestation("git+https://unexpected.repository", "unexpected")]

	# the `gitCommit` support as digest algorithm in SLSA Provenance v1.0
	lib.assert_empty(deny) with input.image as expected
		with input.attestations as [_resolvedDependencies_attestation([{
			"uri": "git+https://git.repository",
			"digest": {"gitCommit": "ec74e6310316babc451947a1a749a233e8da0585"}, # printf 'commit 3\0ref' | sha1sum
			"name": "inputs/result",
		}])]
}

test_deny_expected_source_code_reference_v02 {
	# different scm SLSA Provenance v0.2
	lib.assert_equal_results(deny, {{"code": "slsa_source_correlated.expected_source_code_reference", "msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested", "term": "svn+https://git.repository@sha1:ref"}}) with input.image as expected
		with input.attestations as [_source_material_attestation("svn+https://git.repository", "ref")]

	# different repository SLSA Provenance v0.2
	lib.assert_equal_results(deny, {{"code": "slsa_source_correlated.expected_source_code_reference", "msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested", "term": "git+https://unexpected.repository@sha1:ref"}}) with input.image as expected
		with input.attestations as [_source_material_attestation("git+https://unexpected.repository", "ref")]

	# different revision SLSA Provenance v0.2
	lib.assert_equal_results(deny, {{"code": "slsa_source_correlated.expected_source_code_reference", "msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested", "term": "git+https://git.repository@sha1:unexpected"}}) with input.image as expected
		with input.attestations as [_source_material_attestation("git+https://git.repository", "unexpected")]

	# multiple mismatches SLSA Provenance v0.2
	lib.assert_equal_results(deny, {{"code": "slsa_source_correlated.expected_source_code_reference", "msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested", "term": "git+https://git.repository@sha1:unexpected"}, {"code": "slsa_source_correlated.expected_source_code_reference", "msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested", "term": "git+https://unexpected.repository@sha1:ref"}, {"code": "slsa_source_correlated.expected_source_code_reference", "msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested", "term": "svn+https://git.repository@sha1:ref"}}) with input.image as expected
		with input.attestations as [_source_material_attestation("svn+https://git.repository", "ref"), _source_material_attestation("git+https://unexpected.repository", "ref"), _source_material_attestation("git+https://git.repository", "unexpected")]
}

test_deny_expected_source_code_reference_v10 {
	# different scm SLSA Provenance v1.0
	lib.assert_equal_results(deny, {{"code": "slsa_source_correlated.expected_source_code_reference", "msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested", "term": "svn+https://git.repository@sha1:ref"}}) with input.image as expected
		with input.attestations as [_source_resolvedDependencies_attestation("svn+https://git.repository", "ref")]

	# different repository SLSA Provenance v1.0
	lib.assert_equal_results(deny, {{"code": "slsa_source_correlated.expected_source_code_reference", "msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested", "term": "git+https://unexpected.repository@sha1:ref"}}) with input.image as expected
		with input.attestations as [_source_resolvedDependencies_attestation("git+https://unexpected.repository", "ref")]

	# different revision SLSA Provenance v1.0
	lib.assert_equal_results(deny, {{"code": "slsa_source_correlated.expected_source_code_reference", "msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested", "term": "git+https://git.repository@sha1:unexpected"}}) with input.image as expected
		with input.attestations as [_source_resolvedDependencies_attestation("git+https://git.repository", "unexpected")]

	# multiple mismatches SLSA Provenance v1.0
	lib.assert_equal_results(deny, {{"code": "slsa_source_correlated.expected_source_code_reference", "msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested", "term": "git+https://git.repository@sha1:unexpected"}, {"code": "slsa_source_correlated.expected_source_code_reference", "msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested", "term": "git+https://unexpected.repository@sha1:ref"}, {"code": "slsa_source_correlated.expected_source_code_reference", "msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested", "term": "svn+https://git.repository@sha1:ref"}}) with input.image as expected
		with input.attestations as [_source_resolvedDependencies_attestation("svn+https://git.repository", "ref"), _source_resolvedDependencies_attestation("git+https://unexpected.repository", "ref"), _source_resolvedDependencies_attestation("git+https://git.repository", "unexpected")]
}

test_slsa_v02_source_references {
	lib.assert_empty(_source_references)
	lib.assert_empty(_source_references) with input.attestations as [_material_attestation([])]
	lib.assert_empty(_source_references) with input.attestations as [_source_material_attestation("https://something:somewhere", "cafe")]

	# no digest
	lib.assert_empty(_source_references) with input.attestations as [_material_attestation([{"uri": "git+https://git.repository"}])]

	# unsupported digest algorithm
	lib.assert_empty(_source_references) with input.attestations as [_material_attestation([{"uri": "git+https://git.repository", "digest": {"md2": "unsupported"}}])]

	# no uri
	lib.assert_empty(_source_references) with input.attestations as [_material_attestation([{"digest": {"sha256": "cafe"}}])]
	lib.assert_equal({"git+ssh://git.repository@sha1:cafe"}, _source_references) with input.attestations as [_source_material_attestation("git+ssh://git.repository", "cafe")]
	lib.assert_equal({"git+ssh://git.repository@sha1:cafe", "hg+https://hg.repository@sha1:dada"}, _source_references) with input.attestations as [_source_material_attestation("git+ssh://git.repository", "cafe"), _source_material_attestation("hg+https://hg.repository", "dada")]
}

test_slsa_v10_source_references {
	lib.assert_empty(_source_references) with input.attestations as [_resolvedDependencies_attestation([])]
	lib.assert_empty(_source_references) with input.attestations as [_source_resolvedDependencies_attestation("https://something:somewhere", "cafe")]

	# no digest
	lib.assert_empty(_source_references) with input.attestations as [_resolvedDependencies_attestation([{"uri": "git+https://git.repository"}])]

	# unsupported digest algorithm
	lib.assert_empty(_source_references) with input.attestations as [_resolvedDependencies_attestation([{"uri": "git+https://git.repository", "digest": {"md2": "unsupported"}}])]

	# no uri
	lib.assert_empty(_source_references) with input.attestations as [_resolvedDependencies_attestation([{"digest": {"sha256": "cafe"}}])]
	lib.assert_equal({"git+ssh://git.repository@sha1:cafe"}, _source_references) with input.attestations as [_source_resolvedDependencies_attestation("git+ssh://git.repository", "cafe")]
	lib.assert_equal({"git+ssh://git.repository@sha1:cafe", "hg+https://hg.repository@sha1:dada"}, _source_references) with input.attestations as [_source_resolvedDependencies_attestation("git+ssh://git.repository", "cafe"), _source_resolvedDependencies_attestation("hg+https://hg.repository", "dada")]
}

expected := {"source": {"git": {"url": "https://git.repository", "revision": "ref"}}}

# SLSA Provenance v0.2
_material_attestation(materials) := {"statement": {"predicate": {
	"buildType": lib.pipelinerun_att_build_types[0],
	"materials": materials,
}}}

# SLSA Provenance v0.2
_source_material_attestation(uri, sha1) := _material_attestation([{
	"uri": uri,
	"digest": {"sha1": sha1},
}])

# SLSA Provenance v1.0
_resolvedDependencies_attestation(dependencies) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {"buildDefinition": {
		"buildType": "https://tekton.dev/chains/v2/slsa",
		"externalParameters": {"runSpec": {"pipelineSpec": {}}},
		"resolvedDependencies": dependencies,
	}},
}}

# SLSA Provenance v1.0
_source_resolvedDependencies_attestation(uri, sha1) := _resolvedDependencies_attestation([{
	"uri": uri,
	"digest": {"sha1": sha1},
	"name": "inputs/result",
}])
