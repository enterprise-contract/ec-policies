package hacbs.contract.step_annotations

good_annotation := "Red Hat"

bad_annotation := "evil annotation"

prepare_mock_attestation_data(annotation_specifier) = result {
	result := [{"predicate": {"buildConfig": {"steps": [{"annotations": [annotation_specifier]}]}}}]
}

# A valid annotation
test_annotation_valid {
	result := deny with data.attestations as prepare_mock_attestation_data(good_annotation)
	count(result) == 0
}

# An invalid annotation
test_attestation_invalid {
	result := deny with data.attestations as prepare_mock_attestation_data(bad_annotation)
	result == {{"msg": "step 0 has invalid annotations(s): [\"evil annotation\"]"}}
}
