SHELL := /bin/bash
COVERAGE = @opa test . --threshold 100 2>&1 | sed -e '/^Code coverage/!d' -e 's/^/ERROR: /'; exit $${PIPESTATUS[0]}

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'function ww(s) {\
		if (length(s) < 59) {\
			return s;\
		}\
		else {\
			r="";\
			l="";\
			split(s, arr, " ");\
			for (w in arr) {\
				if (length(l " " arr[w]) > 59) {\
					r=r l "\n                     ";\
					l="";\
				}\
				l=l " " arr[w];\
			}\
			r=r l;\
			return r;\
		}\
	} BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", "make " $$1, ww($$2) } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

test: ## Run all tests in verbose mode and check coverage
	@opa test . -v
	$(COVERAGE)

coverage: ## Show which lines of rego are not covered by tests
	@opa test . --coverage --format json | jq -r '.files | to_entries | map("\(.key): Uncovered:\(.value.not_covered)") | .[]' | grep -v "Uncovered:null"

quiet-test: ## Run all tests in quiet mode and check coverage
	@opa test .
	$(COVERAGE)

# Do `dnf install entr` then run this a separate terminal or split window while hacking
live-test: ## Continuously run tests on changes to any `*.rego` files, `entr` needs to be installed
	@trap exit SIGINT; \
	while true; do \
	  git ls-files -c -o '*.rego' | entr -d -c $(MAKE) --no-print-directory quiet-test; \
	done

fmt: ## Apply default formatting to all rego files. Use before you commit
	@opa fmt . --write

opa-check: ## Check Rego files with strict mode (https://www.openpolicyagent.org/docs/latest/strict/)
	@opa check . --strict

##@ CI

fmt-check: ## Check formatting of Rego files. Used in CI.
	@opa fmt . --list | xargs -r -n1 echo 'Incorrect formatting found in'
	@opa fmt . --list --fail >/dev/null 2>&1

ci: fmt-check quiet-test opa-check ## Runs all checks and tests. Used in CI.

#--------------------------------------------------------------------

##@ Data helpers

clean-data: ## Removes everything from the `./data` directory
	@rm -rf $(DATA_DIR)

dummy-config: ## Changes the configuration to mark the `not_useful` check as non-blocking to avoid a "feels like a bad day.." violation
	@mkdir -p $(DATA_DIR)/config/policy
	@echo '{"non_blocking_checks":["not_useful"]}' | jq > $(DATA_DIR)/config/policy/data.json

# Set IMAGE as required like this:
#   make fetch-att IMAGE=<someimage>
#
# The format and file path is intended to match what is used in the
# verify-attestation-with-policy script in the build-definitions repo
# so you can test your rules as they would be applied by the
# verify-enterprise-contract task.
#
ifndef IMAGE
  # Default value for convenience/laziness. You're encouraged to specify your own IMAGE.
  # (The default has no special significance other than it's known to have an attestation.)
  IMAGE="quay.io/lucarval/tekton-test@sha256:3dde9d48a4ba03187d7a7f5768672fd1bc0eda754afaf982f0768983bb95a06f"
endif

fetch-att: clean-data dummy-config ## Fetches attestation data for IMAGE, use `make fetch-att IMAGE=<ref>`. Note: This is compatible with the 'verify-enterprise-contract' task
	@mkdir -p $(DATA_DIR)/attestations
	cosign download attestation $(IMAGE) | \
	  jq -s '[.[].payload | @base64d | fromjson]' > \
	    $(DATA_DIR)/attestations/data.json

#--------------------------------------------------------------------

# Assume you have the build-definitions repo checked out close by
#
THIS_DIR=$(shell git rev-parse --show-toplevel)
BUILD_DEFS=$(THIS_DIR)/../build-definitions
BUILD_DEFS_SCRIPTS=$(BUILD_DEFS)/appstudio-utils/util-scripts
DATA_DIR=$(THIS_DIR)/data

define BD_SCRIPT
.PHONY: $(1)-$(2)
$(1)-$(2):
	@cd $(BUILD_DEFS_SCRIPTS) && env DATA_DIR=$(DATA_DIR) ./$(1)-ec-data.sh $(2) $(3)
endef
$(eval $(call BD_SCRIPT,fetch,,$(PR)))
$(eval $(call BD_SCRIPT,show,files))
$(eval $(call BD_SCRIPT,show,keys))
$(eval $(call BD_SCRIPT,show,json))
$(eval $(call BD_SCRIPT,show,yaml))

show-data: show-yaml ## Dump available data in `./data` as YAML
fetch-data: fetch- ## Fetch data for the most recent pipeline run. Add `PR=<prname>` to fetch a specific pipeline run. Note: This is compatible with the deprecated 'enterprise-contract' task and requires the build-definitions repo checked out in ../build-definitions

#--------------------------------------------------------------------

##@ Running

POLICIES_DIR=$(THIS_DIR)/policies
OPA_FORMAT=pretty
OPA_QUERY=data.main.deny
check: ## Run policy evaluation with currently fetched data in `./data` and policy rules in `./policies`
	@opa eval \
	  --data $(DATA_DIR) \
	  --data $(POLICIES_DIR) \
	  --format $(OPA_FORMAT) \
	  $(OPA_QUERY)

#--------------------------------------------------------------------

OPA_VER=v0.40.0
OPA_SHA_darwin_amd64=bbd2b41ce8ce3f2cbe06e06a2d05c66185a5e099ff7ac0edcce30116e5cd7831
OPA_SHA_darwin_arm64_static=4b3f54b8dd45e5cc0c2b4242b94516f400202aa84f9e91054145853cfbba4d5f
OPA_SHA_linux_amd64_static=73e96d8071c6d71b4a9878d7f55bcb889173c40c91bbe599f9b7b06d3a472c5f
OPA_SHA_windows_amd64=120ac24bde96cb022028357045edb5680b983c7cfb253b81b4270aedcf9bdf59
OPA_OS_ARCH=$(shell go env GOOS)_$(shell go env GOARCH)
OPA_STATIC=$(if $(OPA_SHA_${OPA_OS_ARCH}_static),_static)
OPA_FILE=opa_$(OPA_OS_ARCH)$(OPA_STATIC)
OPA_URL=https://openpolicyagent.org/downloads/$(OPA_VER)/$(OPA_FILE)
OPA_SHA=$(OPA_SHA_${OPA_OS_ARCH}${OPA_STATIC})
ifndef OPA_BIN
  OPA_BIN=$(HOME)/bin
endif
OPA_DEST=$(OPA_BIN)/opa

##@ Utility

install-opa: ## Install `opa` CLI from GitHub releases
	curl -s -L -O $(OPA_URL)
	echo "$(OPA_SHA) $(OPA_FILE)" | sha256sum --check
	mkdir -p $(OPA_BIN)
	cp $(OPA_FILE) $(OPA_DEST)
	chmod 755 $(OPA_DEST)
	rm $(OPA_FILE)

#--------------------------------------------------------------------

.PHONY: help test coverage quiet-test live-test fmt fmt-check ci clean-data \
  dummy-config fetch-att show-data fetch-data check install-opa
