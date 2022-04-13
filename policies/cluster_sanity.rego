package hacbs.contract.cluster_sanity

#
# It's not likely this would ever fail but it serves as
# a reasonable sanity check of the cluster data that was fetched,
# and it shows an example how we can validate some data with
# a descriptive message.
#
deny[{"msg": msg}] {
	some expected_kind, object_name
	actual_kind := data.cluster[expected_kind][object_name].kind
	actual_kind != expected_kind

	msg := sprintf("Unexpected kind '%s' in %s/%s'!", [actual_kind, expected_kind, object_name])
}
