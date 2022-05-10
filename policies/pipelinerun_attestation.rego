package hacbs.contract.pipelinerun_attestation


deny[msg] {
    t := input.bad == 0
    not t
    msg := "bad"
}
