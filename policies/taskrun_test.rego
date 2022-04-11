package hacbs.contract.taskrun

test_deny_task_kind {
	deny with data.kind as "taskblah"
}

test_deny_task_name {
	deny with data.metadata as {"name": "mybadtask"}
}

test_deny_image_registry {
	deny with data.status as {"steps": {"name": {"imageID": "gcr.io"}}}
}
