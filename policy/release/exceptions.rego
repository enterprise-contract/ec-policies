package release

exception[rules] {
    # TODO: Here we can pull the data from the config to populate the rules list dynamically.
    # We should avoid rule names like "deny", "violation", or "warn". Instead, use "deny_foo",
    # "violation_foo", "warn_foo". This is so the exception list can be precise. An empty string,
    # means exclude any rule named "deny", "violation", or "warn", which is very heavy handed, so
    # avoid that.
    # rules := ["bad_day"]
    rules := []
}
