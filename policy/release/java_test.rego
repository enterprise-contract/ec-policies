package policy.release.java

import data.lib

test_all_good {
	attestations := [lib.att_mock_helper(lib.java_sbom_component_count_result_name, {"redhat": 12, "rebuilt": 42}, "java-task-1")]
	lib.assert_empty(deny_java_foreign_dependencies) with input.attestations as attestations
}

test_has_foreign {
	attestations := [lib.att_mock_helper(lib.java_sbom_component_count_result_name, {"redhat": 12, "rebuilt": 42, "central": 1}, "java-task-1")]
	lib.assert_equal(deny_java_foreign_dependencies, {{"code": "java_foreign_dependencies", "effective_on": "2022-01-01T00:00:00Z", "msg": "Found Java dependencies from 'central', expecting to find only from 'rebuilt,redhat'"}}) with input.attestations as attestations
}
