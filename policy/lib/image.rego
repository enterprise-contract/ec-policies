package lib.image

# parse returns a data structure representing the different portions
# of the OCI image reference.
parse(ref) = d {
	digest_parts := split(ref, "@")
	digest := _get(digest_parts, 1, "")

	contains(digest_parts[0], "/")
	repo_parts := split(digest_parts[0], "/")

	tag_parts := split(repo_parts[count(repo_parts) - 1], ":")
	count(tag_parts) <= 2
	tag := _get(tag_parts, 1, "")

	repo := concat(
		"/",
		array.concat(
			array.slice(repo_parts, 0, count(repo_parts) - 1),
			[tag_parts[0]],
		),
	)

	d := {
		"digest": digest,
		"repo": repo,
		"tag": tag,
	}
}

_get(array, index, default_value) = value {
	value := array[index]
} else = default_value {
	true
}
