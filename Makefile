SHELL := /bin/bash
COVERAGE = @opa test . --threshold 100 2>&1 | sed -e '/^Code coverage/!d' -e 's/^/ERROR: /'; exit $${PIPESTATUS[0]}

help:
	@echo "Usage:"
	@echo "  make test         # Run all tests"
	@echo "  make fmt          # Apply default formatting to all rego files"
	@echo "  make ci           # Check formatting and run all tests"
	@echo "  make coverage     # Show which lines of rego are not covered by tests"
	@echo
	@echo "  make install-opa  # Install opa if you don't have it already (Linux only)"
	@echo
	@echo "  make fetch-att    # Fetch an attestation for an image"
	@echo "                    # Add \`IMAGE=<someimage>\` to fetch a specific attestation"
	@echo "                    # Note: This is compatible with the 'verify-enterprise-contract' task"
	@echo
	@echo "  make fetch-data   # Fetch data for the most recent pipeline run"
	@echo "                    # Add \`PR=<prname>\` to fetch a specific pipeline run"
	@echo "                    # Note: This is compatible with the deprecated 'enterprise-contract' task"
	@echo "                    # and requires the build-definitions repo checked out in ../build-definitions"
	@echo
	@echo "  make show-files   # List data files"
	@echo "  make show-data    # Show all data visible to opa in one big object"
	@echo "  make show-keys    # List all the keys in the data"
	@echo
	@echo "  make check        # Check rego policies against the fetched data"

test:
	@opa test . -v
	$(COVERAGE)

# Show which lines of code are not covered
coverage:
	@opa test . --coverage --format json | jq -r '.files | to_entries | map("\(.key): Uncovered:\(.value.not_covered)") | .[]' | grep -v "Uncovered:null"

quiet-test:
	@opa test .
	$(COVERAGE)

# Do `dnf install entr` then run this a separate terminal or split window while hacking
live-test:
	@trap exit SIGINT; \
	while true; do \
	  git ls-files -c -o '*.rego' | entr -d -c $(MAKE) --no-print-directory quiet-test; \
	done

# Rewrite all rego files with the preferred format
# Use before you commit
fmt:
	@opa fmt . --write

# Return non-zero exit code if formatting is needed
# Used in CI
fmt-check:
	@opa fmt . --list | xargs -r -n1 echo 'Incorrect formatting found in'
	@opa fmt . --list --fail >/dev/null 2>&1

opa-check:
	@opa check . --strict

# For convenience. If this passes then it should pass in GitHub
ci: fmt-check quiet-test opa-check

#--------------------------------------------------------------------

clean-data:
	@rm -rf $(DATA_DIR)

# Avoid a "feels like a bad day.." violation
dummy-config:
	@mkdir -p $(DATA_DIR)/config/policy
	@echo '{"non_blocking_checks":["not_useful"]}' | jq > $(DATA_DIR)/config/policy/data.json

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

show-data: show-yaml
fetch-data: fetch-

#--------------------------------------------------------------------

POLICIES_DIR=$(THIS_DIR)/policies
OPA_FORMAT=pretty
OPA_QUERY=data.main.deny
check:
	@opa eval \
	  --data $(DATA_DIR) \
	  --data $(POLICIES_DIR) \
	  --format $(OPA_FORMAT) \
	  $(OPA_QUERY)

#--------------------------------------------------------------------

OPA_VER=v0.39.0
OPA_FILE=opa_linux_amd64_static
OPA_URL=https://openpolicyagent.org/downloads/$(OPA_VER)/$(OPA_FILE)
OPA_SHA=19a24f51d954190c02aafeac5867c9add286c6ab12ea85b3d8d348c98d633319
ifndef OPA_BIN
  OPA_BIN=$(HOME)/bin
endif
OPA_DEST=$(OPA_BIN)/opa

install-opa:
	curl -s -L -O $(OPA_URL)
	echo "$(OPA_SHA) $(OPA_FILE)" | sha256sum --check
	mkdir -p $(OPA_BIN)
	cp $(OPA_FILE) $(OPA_DEST)
	chmod 755 $(OPA_DEST)
	rm $(OPA_FILE)

#--------------------------------------------------------------------

.PHONY: help test coverage quiet-test live-test fmt fmt-check ci clean-data \
  dummy-config fetch-att show-data fetch-data check install-opa
