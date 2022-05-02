package hacbs.contract.policies.not_useful

test_not_useful {
	count(deny) == 1
	deny == {{"msg": "It just feels like a bad day to do a release"}}
}
