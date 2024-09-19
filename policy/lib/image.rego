package lib.image

import rego.v1

# parse returns a data structure representing the different portions
# of the OCI image reference.
parse(ref) := d if {
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

	not contains(repo, "://")

	d := {
		"digest": digest,
		"repo": repo,
		"tag": tag,
	}
}

# Formats the parsed reference as string
str(d) := s1 if {
	d.repo != ""
	d.digest != ""
	d.tag != ""
	s1 := sprintf("%s:%s@%s", [d.repo, d.tag, d.digest])
} else := s2 if {
	d.repo != ""
	d.digest != ""
	s2 := sprintf("%s@%s", [d.repo, d.digest])
} else := s3 if {
	d.repo != ""
	d.tag != ""
	s3 := sprintf("%s:%s", [d.repo, d.tag])
}

# equal_ref returns true if two image references point to the same image. The
# algorithm first checks if the constituent parts repository, tag and digest are
# all equal
equal_ref(ref1, ref2) if {
	img1 := parse(ref1)
	img2 := parse(ref2)

	img1 == img2
}

# equal_ref returns true if two image references point to the same image,
# ignoring the tag. This complements the case where all parts of the reference
# need to be equal.
equal_ref(ref1, ref2) if {
	img1 := parse(ref1)
	img2 := parse(ref2)

	# need to make sure that the digest of one reference is present, otherwise we
	# might end up comparing image references without tags and digests. equal_ref is
	# commutative, so we can check that the digest exists for one of the references,
	# in this case img1
	img1.digest != ""
	object.remove(img1, ["tag"]) == object.remove(img2, ["tag"])
}

_get(ary, index, default_value) := value if {
	value := ary[index]
} else := default_value
