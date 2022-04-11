package examples.test_data_demo

# Demonstrate how we we can use the data in
# policies/test_data.rego to write tests
# (See test_data_demo_test.rego)

deny = {"msg": msg} {
	chains_config := data.cluster.ConfigMap["chains-config"]
	taskrun_format := chains_config.data["artifacts.taskrun.format"]
	required_taskrun_format := "in-toto"

	taskrun_format != required_taskrun_format

	msg := sprintf(
		"Unexpected chains config: artifacts.taskrun.format should be '%s' but is currently '%s'",
		[required_taskrun_format, taskrun_format],
	)
}
