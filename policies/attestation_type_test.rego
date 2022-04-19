package hacbs.contract.attestation_type

test_attestation_type_ok {
	attestation_type_valid("https://in-toto.io/Statement/v0.1")
	not attestation_type_valid("http://in-toto.io/Statement/v0.1")
	not attestation_type_valid("foobar")
}

prepare_mock_rekor_data(att_type) = result {
	result := {"example.com": {"index": {"123": {"entry": {"Attestation": base64.encode(json.marshal({"_type": att_type}))}}}}}
}

test_attestation_type_valid {
	deny_set := deny with data.rekor as prepare_mock_rekor_data("https://in-toto.io/Statement/v0.1")
	count(deny_set) == 0
}

test_attestation_type_invalid {
	deny_set := deny with data.rekor as prepare_mock_rekor_data("https://in-toto.io/Statement/v6.283")
	count(deny_set) == 1
	expected_msg := "Unexpected attestation type in transparency log entry 123 on example.com. Expecting 'https://in-toto.io/Statement/v0.1' but found https://in-toto.io/Statement/v6.283"
	deny_set == {{"msg": expected_msg}}
}
