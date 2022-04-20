package lib

test_all_rekor_attestations {
	expected := [{"rekor_host": "example.com", "log_index": "123", "data": {"foo": 10}}]
	expected == all_rekor_attestations with data.rekor as {"example.com": {"index": {"123": {"entry": {"Attestation": base64.encode("{\"foo\":10}")}}}}}
}
