package pipeline.main

import data.lib

all_denies := lib.current_and_future_denies("pipeline")

deny := lib.current_denies(all_denies)

warn := lib.future_denies(all_denies)
