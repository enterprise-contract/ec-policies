SHELL := /bin/bash

help:
	@echo "Usage:"
	@echo "  make test             # Run all tests"
	@echo "  make fmt              # Apply default formatting to all rego files"
	@echo "  make ci               # Check formatting and run all tests"
	@echo
	@echo "  make install-conftest # Install conftest if you don't have it already (Linux and OSX only)"
	@echo
	@echo "  make fetch-att        # Fetch an attestation for an image"
	@echo "                        # Add \`IMAGE=<someimage>\` to fetch a specific attestation"
	@echo "                        # Note: This is compatible with the 'verify-enterprise-contract' task"
	@echo
	@echo "  make fetch-data       # Fetch data for the most recent pipeline run"
	@echo "                        # Add \`PR=<prname>\` to fetch a specific pipeline run"
	@echo "                        # Note: This is compatible with the deprecated 'enterprise-contract' task"
	@echo "                        # and requires the build-definitions repo checked out in ../build-definitions"
	@echo
	@echo "  make show-files       # List data files"
	@echo "  make show-data        # Show all data visible to conftest in one big object"
	@echo "  make show-keys        # List all the keys in the data"
	@echo
	@echo "  make check            # Check rego policies against the fetched data"

test:
	@conftest verify -d policy/data --report full

# Do `dnf install entr` then run this a separate terminal or split window while hacking
live-test:
	@trap exit SIGINT; \
	while true; do \
	  git ls-files -c -o '*.rego' | entr -d -c $(MAKE) --no-print-directory test; \
	done

# Rewrite all rego files with the preferred format
# Use before you commit
fmt:
	@conftest fmt .

# Return non-zero exit code if formatting is needed
# Used in CI
fmt-check:
	@conftest fmt . --check 

ci: fmt-check test

#--------------------------------------------------------------------

clean-data:
	@rm -rf $(INPUT_DIR)

# Avoid a "feels like a bad day.." violation
dummy-config:
	@mkdir -p $(DATA_DIR)
	@echo '{"non_blocking_checks":["not_useful"]}' | jq > $(DATA_DIR)/data.json

# Set IMAGE as required like this:
#   make fetch-attestation IMAGE=<someimage>
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

fetch-att: clean-data dummy-config
	@mkdir -p $(INPUT_DIR)
	cosign download attestation $(IMAGE) | \
	  jq -s '[.[].payload | @base64d | fromjson]' > \
	    $(INPUT_DIR)/attestations.json

#--------------------------------------------------------------------

# Assume you have the build-definitions repo checked out close by
#
THIS_DIR=$(shell git rev-parse --show-toplevel)
BUILD_DEFS=$(THIS_DIR)/../build-definitions
BUILD_DEFS_SCRIPTS=$(BUILD_DEFS)/appstudio-utils/util-scripts
DATA_DIR=$(THIS_DIR)/data
INPUT_DIR=$(THIS_DIR)/input

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

show-data: show-yaml
fetch-data: fetch-

#--------------------------------------------------------------------

POLICIES_DIR=$(THIS_DIR)/policy
DATA_DIR=$(POLICIES_DIR)/data
CONFTEST_FORMAT=pretty
CONFTEST_QUERY="policy.step_image_registries,policy.attestation_type"
INPUT_FILE=$(INPUT_DIR)/attestations.json
check-att:
	@conftest test \
	$(INPUT_FILE) \
	--data $(DATA_DIR) \
	--namespace $(CONFTEST_QUERY) \
	-o json

#--------------------------------------------------------------------

CONFTEST_VER=0.32.0
CONFTEST_SHA_darwin_amd64=a692cd676cbcdc318d16f261c353c69e0ef69aff5fb0442f3cb909df13beb895
CONFTEST_SHA_linux_amd64=e368ef4fcb49885e9c89052ec0c29cf4d4587707a589fefcaa3dc9cc72065055
CONFTEST_GOOS=$(shell go env GOOS)
ifeq ($(CONFTEST_GOOS),darwin)
	CONFTEST_GOOS=Darwin
endif
CONFTEST_GOARCH=$(shell go env GOARCH)
ifeq ($(CONFTEST_GOARCH),amd64)
	CONFTEST_GOARCH=x86_64
endif

CONFTEST_OS_ARCH=$(CONFTEST_GOOS)_$(CONFTEST_GOARCH)
CONFTEST_URL=https://github.com/open-policy-agent/conftest/releases/download/v$(CONFTEST_VER)/conftest_$(CONFTEST_VER)_$(CONFTEST_OS_ARCH).tar.gz
ifndef CONFTEST_BIN
  CONFTEST_BIN=$(HOME)/bin
endif

install-conftest:
	curl -L $(CONFTEST_URL) > /tmp/conftest.tar.gz
	tar xzf /tmp/conftest.tar.gz conftest
	mv conftest $(CONFTEST_BIN)

#--------------------------------------------------------------------

.PHONY: help test quiet-test live-test fmt fmt-check ci clean-data \
  dummy-config fetch-att show-data fetch-data check install-conftest
