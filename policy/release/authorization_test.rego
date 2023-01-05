package policy.release.authorization

import data.lib

mock_data(changeId, repo, authorizers) = d {
	d := [{"repoUrl": repo, "changeId": changeId, "authorizers": [authorizers]}]
}

mock_empty_data = d {
	d := []
}

git_repo := "https://github.com/hacbs-contract/ec-policies.git"

commit_sha := "1234"

test_no_authorization {
	expected_msg := "No authorization data found"
	lib.assert_equal(deny, {{
		"code": "authorization.disallowed_no_authorization",
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as lib.att_mock_materials(git_repo, commit_sha) with data.authorization as mock_empty_data
}

test_commit_does_not_match {
	expected_msg := sprintf("Commit %s does not match authorized commit %s", [commit_sha, "2468"])
	lib.assert_equal(deny, {{
		"code": "authorization.disallowed_commit_does_not_match",
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as lib.att_mock_materials(git_repo, commit_sha) with data.authorization as mock_data("2468", git_repo, "ec@redhat.com")
}

test_repo_does_not_match {
	expected_msg := sprintf("Repo url %s does not match authorized repo url %s", [git_repo, "https://github.com/hacbs-contract/authorized.git"])
	lib.assert_equal(deny, {{
		"code": "authorization.disallowed_repo_url_does_not_match",
		"msg": expected_msg,
		"effective_on": "2022-01-01T00:00:00Z",
	}}) with input.attestations as lib.att_mock_materials(git_repo, commit_sha) with data.authorization as mock_data(commit_sha, "https://github.com/hacbs-contract/authorized.git", "ec@redhat.com")
}
