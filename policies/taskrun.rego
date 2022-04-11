package hacbs.contract.taskrun

validAnnotations := ["Red Hat", null]
validRegistries := ["docker.io", "registry.access.redhat.com"]

deny[msg] {
	invalidAnnotations := [x | x := data.predicate.buildConfig.steps[_].annotations; not valid_annotation(x)]
	invalidAnnotations != []
	msg := print_list_data("annotations", invalidAnnotations)
}

deny[msg] {
	imageData := [split(x, "/")[0] | x := data.predicate.buildConfig.steps[_].environment.image]
	invalidImage := [x | x := imageData[_]; not valid_registry(x)]
	invalidImage != []
	msg := print_list_data("registries", invalidImage)
}

print_list_data(name, list_data) = msg {
	msg := sprintf("%d invalid %s used: \n%s", [
		name,
		count(list_data),
		concat("\n", [sprintf("- %s", [m]) | m := list_data[_]]),
	])
}

valid_annotation(annotation) {
	validAnnotations[_] == annotation
}

valid_registry(registry) {
	validRegistries[_] == registry
}
