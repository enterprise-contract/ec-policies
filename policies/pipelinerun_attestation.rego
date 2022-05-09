package hacbs.contract.attestation


deny[msg] {
    t := input.bad == 1
    not t
    msg := "bad"
}
