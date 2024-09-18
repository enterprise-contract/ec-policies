package policy.release.rpm_repos_test

import rego.v1

import data.lib
import data.policy.release.rpm_repos

test_repo_id_data_empty if {
	expected := {
		"code": "rpm_repos.rule_data_provided",
		"msg": "Rule data 'known_rpm_repositories' has unexpected format: (Root): Array must have at least 1 items",
	}

	lib.assert_equal_results({expected}, rpm_repos.deny) with data.rule_data.known_rpm_repositories as []
}

test_repo_id_data_not_an_array if {
	expected := {
		"code": "rpm_repos.rule_data_provided",
		"msg": sprintf("%s %s", [
			"Rule data 'known_rpm_repositories' has unexpected format:",
			"(Root): Invalid type. Expected: array, given: object",
		]),
	}

	lib.assert_equal_results({expected}, rpm_repos.deny) with data.rule_data.known_rpm_repositories as {"chunky": "bacon"}
}

test_repo_id_data_not_strings if {
	expected := {
		"code": "rpm_repos.rule_data_provided",
		"msg": "Rule data 'known_rpm_repositories' has unexpected format: 1: Invalid type. Expected: string, given: integer",
	}

	lib.assert_equal_results({expected}, rpm_repos.deny) with data.rule_data.known_rpm_repositories as ["spam", 42]
}

test_repo_id_all if {
	lib.assert_equal_results(
		{p1, p2, p3, p4, p5},
		rpm_repos.all_rpm_purls,
	) with rpm_repos._all_sboms as fake_sboms
}

test_repo_id_all_with_repo_id if {
	lib.assert_equal_results(
		{p1, p2, p3},
		rpm_repos._plain_purls(rpm_repos.all_purls_with_repo_ids),
	) with rpm_repos._all_sboms as fake_sboms
}

test_repo_id_all_known if {
	lib.assert_equal_results(
		{p1, p2},
		rpm_repos._plain_purls(rpm_repos.all_purls_with_known_repo_ids),
	) with rpm_repos._all_sboms as fake_sboms with data.rule_data.known_rpm_repositories as fake_repo_id_list
}

test_repo_id_purls_missing_repo_ids if {
	expected := {
		{
			"code": "rpm_repos.ids_known",
			"msg": sprintf("%s %s", [
				"RPM repo id check failed: An RPM component in the SBOM did not specify a repository_id value in its purl:",
				"pkg:rpm/redhat/spam@1.2.3?arch=amd64&pastry_id=puff",
			]),
		},
		{
			"code": "rpm_repos.ids_known",
			"msg": sprintf("%s %s", [
				"RPM repo id check failed: An RPM component in the SBOM did not specify a repository_id value in its purl:",
				"pkg:rpm_borken",
			]),
		},
	}

	lib.assert_equal_results(expected, rpm_repos.deny) with rpm_repos._all_sboms as [fake_sbom({p1, p2, p4, p5, p6})]
		with data.rule_data.known_rpm_repositories as fake_repo_id_list
}

test_repo_id_purls_missing_repo_ids_truncated if {
	expected := {
		{
			"code": "rpm_repos.ids_known",
			"msg": sprintf("%s %s", [
				"RPM repo id check failed: An RPM component in the SBOM did not specify a repository_id value in its purl:",
				"pkg:rpm/redhat/spam@1.2.3?arch=amd64&pastry_id=puff",
			]),
		},
		{
			"code": "rpm_repos.ids_known",
			"msg": sprintf("%s %s", [
				"RPM repo id check failed: An RPM component in the SBOM did not specify a repository_id value in its purl:",
				"1 additional similar violations not separately listed",
			]),
		},
	}

	lib.assert_equal_results(expected, rpm_repos.deny) with rpm_repos._all_sboms as [fake_sbom({p1, p2, p4, p5, p6})]
		with data.rule_data.known_rpm_repositories as fake_repo_id_list
		with rpm_repos._truncate_threshold as 1 with rpm_repos._min_remainder_count as 0
}

test_repo_id_purls_unknown_repo_ids if {
	expected := {
		"code": "rpm_repos.ids_known",
		"msg": sprintf("%s %s", [
			"RPM repo id check failed: An RPM component in the SBOM specified an unknown or disallowed repository_id:",
			"pkg:rpm/redhat/spam@1.2.3?arch=amd64&repository_id=rhel-23-unrecognized-2-rpms",
		]),
	}

	lib.assert_equal_results({expected}, rpm_repos.deny) with rpm_repos._all_sboms as [fake_sbom({p1, p2, p3, p6})]
		with data.rule_data.known_rpm_repositories as fake_repo_id_list
}

test_clamp_violation_strings if {
	lib.assert_equal(
		["a", "b", "c", "2 additional similar violations not separately listed"],
		rpm_repos._truncated_msg_list(["a", "b", "c", "d", "e"]),
	) with rpm_repos._truncate_threshold as 3 with rpm_repos._min_remainder_count as 0

	lib.assert_equal(
		["a", "b", "c", "d", "e"],
		rpm_repos._truncated_msg_list(["a", "b", "c", "d", "e"]),
	) with rpm_repos._truncate_threshold as 5

	lib.assert_equal(
		["a", "b", "3 additional similar violations not separately listed"],
		rpm_repos._truncated_msg_list(["a", "b", "c", "d", "e"]),
	) with rpm_repos._truncate_threshold as 2 with rpm_repos._min_remainder_count as 3
}

test_all_sboms if {
	# (Needed for 100% coverage)
	lib.assert_equal("spam-1000", rpm_repos._all_sboms) with lib.sbom.cyclonedx_sboms as "spam-1000"
}

fake_sboms := [fake_sbom({p1, p2, p3, p4, p5, p6})]

fake_sbom(fake_purls) := {"components": [{"purl": p} | some p in fake_purls]}

fake_repo_id_list := ["rhel-23-for-spam-9-rpms", "rhel-42-for-bacon-12-rpms"]

p1 := "pkg:rpm/redhat/spam@1.2.3?arch=amd64&repository_id=rhel-23-for-spam-9-rpms"

p2 := "pkg:rpm/redhat/spam@1.2.3?arch=amd64&repository_id=rhel-42-for-bacon-12-rpms"

p3 := "pkg:rpm/redhat/spam@1.2.3?arch=amd64&repository_id=rhel-23-unrecognized-2-rpms"

p4 := "pkg:rpm/redhat/spam@1.2.3?arch=amd64&pastry_id=puff"

p5 := "pkg:rpm_borken"

p6 := "pkg:golang/gitplanet.com/bacon@1.2.3?arch=amd64"
