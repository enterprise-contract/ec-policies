package hacbs.contract.not_useful

#
# This is demoing the concept of being able to conveniently exclude
# pieces of the EC policy without modifying the rego files.
#
# It's expected this will be skipped due to
# data.config.policy.non_blocking_checks being set to ["not_useful"].
#
# See the skip rule in main.rego
#
deny[{"msg": msg}] {
	true
	msg := "It just feels like a bad day to do a release"
}
