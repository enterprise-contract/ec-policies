
help:
	@echo "Usage:"
	@echo "  make test         # Run all tests"
	@echo "  make fmt          # Apply default formatting to all rego files"
	@echo "  make ci           # Check formatting and run all tests"
	@echo "  make install-opa  # Install opa if you don't have it already (Linux only)"
	@echo "  make fetch-data   # Fetch data for the most recent pipeline run"
	@echo "                    # Add \`PR=prname\` to fetch a specific pipeline run"
	@echo "  make show-files   # List data files"
	@echo "  make show-data    # Show all data visible to opa in one big object"
	@echo "  make show-keys    # List all the keys in the data"
	@echo "  make check        # Check rego policies against the fetched data"
	@echo "  make data-to-rego # Regenerate the policies/test_data.rego file"

test:
	@opa test . -v

quiet-test:
	@opa test .

# Rewrite all rego files with the preferred format
# Use before you commit
fmt:
	@opa fmt . --write

# Return non-zero exit code if formatting is needed
# Used in CI
fmt-check:
	@opa fmt . --list | xargs -r -n1 echo 'Incorrect formatting found in'
	@opa fmt . --list --fail >/dev/null 2>&1

# For convenience. If this passes then it should pass in GitHub
ci: fmt-check quiet-test

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

POLICIES_DIR=$(THIS_DIR)/policies
OPA_FORMAT=pretty
OPA_QUERY=data.hacbs.contract.main.deny
check:
	@opa eval \
	  --data $(DATA_DIR) \
	  --data $(POLICIES_DIR) \
	  --format $(OPA_FORMAT) \
	  $(OPA_QUERY)

# Generate a rego file that contains a full and complete set of realistic
# data in a rego var. This is useful for writing tests.
#
TEST_DATA_REGO_FILE=$(POLICIES_DIR)/test_data.rego

data-to-rego:
	@( \
	  echo "package test_data"; \
	  echo "# Generated automatically with \`make data-to-rego\`"; \
	  echo -n "data :="; \
	  $(MAKE) --no-print-directory show-json | jq; \
	) > $(TEST_DATA_REGO_FILE)
	@$(MAKE) --no-print-directory fmt
	@echo "To stage changes:"
	@echo "  git add $$(realpath --relative-to=$$(pwd) $(TEST_DATA_REGO_FILE))"

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

.PHONY: help test fmt fmt-check ci install-opa fetch-data show-data check data-to-rego
