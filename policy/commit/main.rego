package commit.main

import data.lib

all_denies := lib.current_and_future_denies("commit")

all_warns := lib.current_and_future_warns("commit")

deny := lib.current_rules(all_denies)

warn := lib.future_rules(all_denies) | lib.current_rules(all_warns)
