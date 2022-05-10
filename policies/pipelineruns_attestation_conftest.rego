package hacbs.contract.pipelineruns_attestation_conftest


# match successful test results by service account
deny[msg] {
    pr_filter := input[i].contents.kind == "PipelineRun"
    pr := input[i].contents

    not pipelinerun_filter(pr.spec.serviceAccountName)
    msg := sprintf("There are no passing test results ran by user: %v", [pr.spec.serviceAccountName])
}

pipelinerun_filter(sa_name) {
    input[tests].contents.HACBS_TEST_OUTPUT.result == "SUCCESS"
    input[tests].contents.HACBS_TEST_OUTPUT.sa_name == sa_name
}

# $ conftest test pipelinerun.yaml test.yaml --policy ./policies --namespace hacbs.contract.pipelineruns_attestation_conftest -o json --combine
# [
# 	{
# 		"filename": "Combined",
# 		"namespace": "hacbs.contract.pipelineruns_attestation_conftest",
# 		"successes": 0,
# 		"failures": [
# 			{
# 				"msg": "There are no passing test results ran by user: pipeline"
# 			}
# 		]
# 	}
# ]