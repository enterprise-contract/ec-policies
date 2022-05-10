package hacbs.contract.pipelineruns_attestation


deny[msg] {
    some i
    t := input[i].contents.bad == 0
    not t
    msg := "bad"
}
