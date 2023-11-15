package slsa.tekton

import data.slsa.tekton.v02
import data.slsa.tekton.v1

tasks(slsa_predicate) := _tasks {
	_tasks := v02.tasks(slsa_predicate)
} else := _tasks {
	_tasks := v1.tasks(slsa_predicate)
} else := []
