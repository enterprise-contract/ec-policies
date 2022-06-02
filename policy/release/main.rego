package release.main

import data.lib

all_denies := lib.current_and_future_denies("release")

deny := lib.current_denies(all_denies)

warn := lib.future_denies(all_denies)
