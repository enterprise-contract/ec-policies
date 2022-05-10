package hacbs.contract.pipelinerun_attestation


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
    some i
    t := input[i].bad == "bad"
    not t
    msg := "bad"
}

warn[msg] {
  some i
  t := input[i].good == "good"
  t
  msg := "good"
}

