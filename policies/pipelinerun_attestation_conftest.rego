package hacbs.contract.pipelinerun_attestation_conftest

import data.services

# conftest test at_conftest.json --data data/config.yaml --policy policies/ --namespace hacbs.contract.pipelinerun_attestation_conftest -o json
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
