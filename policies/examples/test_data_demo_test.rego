package examples.test_data_demo

import data.test_data

test_using_unmodified_test_data {
	# This gives a rego_recursion_error
	#not deny with data as test_data.data

	# These all work though
	not deny with data.cluster as test_data.data.cluster
	not deny with data.cluster.ConfigMap as test_data.data.cluster.ConfigMap
	not deny with data.cluster.ConfigMap["chains-config"] as test_data.data.cluster.ConfigMap["chains-config"]
}

test_using_object_union {
	expected_msg = "Unexpected chains config: artifacts.taskrun.format should be 'in-toto' but is currently 'in-kansas'"

	# Using object.union to modify test data
	# Not pretty but it does work
	deny == {"msg": expected_msg} with data.cluster.ConfigMap["chains-config"].data as object.union(test_data.data.cluster.ConfigMap["chains-config"].data, {"artifacts.taskrun.format": "in-kansas"})
}

test_using_json_patch {
	expected_msg = "Unexpected chains config: artifacts.taskrun.format should be 'in-toto' but is currently 'in-africa'"

	# Using json.patch to modify test data
	# It's tidier than object.union
	deny == {"msg": expected_msg} with data.cluster as json.patch(test_data.data.cluster, [{
		"op": "replace",
		"path": "/ConfigMap/chains-config/data/artifacts.taskrun.format",
		"value": "in-africa",
	}])
}
