
clamav-task.json:
	curl -sL https://raw.githubusercontent.com/redhat-appstudio/build-definitions/main/task/clamav-scan/0.1/clamav-scan.yaml | yq '.' -o json > $@

v02-sample-attestation.json:
	curl -sL https://raw.githubusercontent.com/enterprise-contract/hacks/main/provenance/recordings/01-SLSA-v0-2-Pipeline-in-cluster/attestation.json -o $@

v1-sample-attestation.json:
	curl -sL https://raw.githubusercontent.com/enterprise-contract/hacks/main/provenance/recordings/05-SLSA-v1-0-tekton-build-type-Pipeline-in-cluster/attestation.json -o $@

all: clamav-task.json v02-sample-attestation.json v1-sample-attestation.json

refresh:
	$(MAKE) -B --no-print-directory all
