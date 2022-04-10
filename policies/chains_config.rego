package hacbs.contract.chains_config

#
# Sanity check the configuration of tekton-chains in the cluster
#
# Actually this is a weak test since the configuration might have changed
# since the pipeline ran.
#
# Todo:
# - This doesn't fail if the key is entirely absent, which is bad.
# - Maybe it should check other fields in the chains configuration.
#
deny[{"msg": msg}] {
	data.cluster.ConfigMap["chains-config"].data["transparency.enabled"] != "true"

	msg := "Chains configuration has transparency disabled"
}
