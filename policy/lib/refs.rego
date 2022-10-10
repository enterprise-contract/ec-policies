package lib.refs

import future.keywords.in

# Return an object that represents the task "name", "kind", and "bundle". "bundle" is
# omitted if a bundle is not used.
#
# As task reference can take different shapes depending on which resolver is being used.
# When a bundle reference is used, there are two mechanisms. The old-style which uses
# the .bundle attribute, and the new-style via the Bundle Resolver. It is technically
# possible to create a task reference that contains both styles. In such cases, Tekton
# gives precedence to the old-style. Further, Tekton falls back to the local resolver if
# a bundle is not used in neither format. The "else" usage in this function ensures the
# same precendence order is honored.
task_ref(task) = i {
	# Handle old-style bundle reference
	r := _ref(task)
	i := {
		"bundle": r.bundle,
		"name": object.get(r, "name", ""),
		"kind": lower(object.get(r, "kind", "task")),
	}
} else = i {
	# Handle bundle-resolver reference
	r := _ref(task)
	r.resolver == "bundles"
	i := {
		"bundle": _param(r, "bundle", ""),
		"name": _param(r, "name", ""),
		"kind": lower(_param(r, "kind", "task")),
	}
} else = i {
	# Handle local reference
	r := _ref(task)
	i := {
		"name": object.get(r, "name", ""),
		"kind": lower(object.get(r, "kind", "task")),
	}
}

_param(taskRef, name, fallback) = value {
	some param in taskRef.params
	param.name == name
	value := param.value
} else = fallback {
	true
}

_ref(task) = r {
	# Reference from within a PipelineRun attestation
	r := task.ref
} else = r {
	# Reference from within a Pipeline definition
	r := task.taskRef
}
