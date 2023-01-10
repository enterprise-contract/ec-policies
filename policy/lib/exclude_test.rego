package lib

import data.lib

test_exclude_default_value {
	lib.assert_empty(exclude)
	lib.assert_empty(exclude) with data.config as {"policy": {}}
	lib.assert_empty(exclude) with data.config as {"policy": {"exclude": []}}
}

test_exclude_policy {
	config := {"policy": {"exclude": ["oatmeal", "porridge"]}}
	lib.assert_equal({"oatmeal", "porridge"}, exclude) with data.config as config
}

test_deprecated_exclude_policy {
	config := {"policy": {"non_blocking_checks": ["oatmeal", "porridge"]}}
	lib.assert_equal({"oatmeal", "porridge"}, exclude) with data.config as config
}

test_mixed_deprecated_exclude_policy {
	config := {"policy": {
		"non_blocking_checks": ["porridge"],
		"exclude": ["oatmeal"],
	}}
	lib.assert_equal({"oatmeal", "porridge"}, exclude) with data.config as config
}
