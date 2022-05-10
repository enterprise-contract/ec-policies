package hacbs.contract.pipelinerun_attestation_conftest

import data.services

# conftest test at_conftest.json --data data/config.yaml --policy policies/ --namespace hacbs.contract.pipelinerun_attestation_conftest -o json
# conftest test at.json at_conftest.json --data data/config.yaml --policy policies/ --namespace hacbs.contract.pipelinerun_attestation_conftest -o json
#[
#  {
#    "bad": "bad",
#    "good": "good"
#  },
#  {
#    "bad": "bad",
#    "good": "good"
#  }
#]
deny[msg] {
    input.bad == "good"
    msg := "bad"
}

warn[msg] {
  t := input.good == "good"
  t
  msg := "good"
}

deny[msg] {
    input.good != "good"
    services.ports != 25
    msg := "ports bad"
}

# $ conftest test at.json at_conftest.json --data data/config.yaml --policy policies/ --namespace hacbs.contract.pipelinerun_attestation_conftest -o json
# [
# 	{
# 		"filename": "at_conftest.json",
# 		"namespace": "hacbs.contract.pipelinerun_attestation_conftest",
# 		"successes": 4,
# 		"warnings": [
# 			{
# 				"msg": "good"
# 			}
# 		],
# 		"failures": [
# 			{
# 				"msg": "bad"
# 			},
# 			{
# 				"msg": "ports bad"
# 			},
# 			{
# 				"msg": "bad"
# 			},
# 			{
# 				"msg": "ports bad"
# 			}
# 		]
# 	},
# 	{
# 		"filename": "at.json",
# 		"namespace": "hacbs.contract.pipelinerun_attestation_conftest",
# 		"successes": 2,
# 		"failures": [
# 			{
# 				"msg": "ports bad"
# 			}
# 		]
# 	}
# ]


