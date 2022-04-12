
help:
	@echo "Usage:"
	@echo "  make test         # Run all tests"
	@echo "  make fmt          # Apply default formatting to all rego files"
	@echo "  make ci           # Check formatting and run all tests"
	@echo "  make install-opa  # Install opa if you don't have it already (Linux only)"

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

.PHONY: help test fmt fmt-check ci install-opa
