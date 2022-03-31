
help:
	@echo "Usage:"
	@echo "  make test         # Run all tests"
	@echo "  make fmt          # Apply default formatting to all rego files"
	@echo "  make ci           # Check formatting and run all tests"
	@echo "  make install-opa  # Install opa if you don't have it already (Linux only)"

test:
	@opa test . -v

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
ci: fmt-check test

OPA_VER=v0.39.0
OPA_URL=https://openpolicyagent.org/downloads/$(OPA_VER)/opa_linux_amd64_static
OPA_DEST=/usr/bin/opa

install-opa:
	sudo curl -s -L -o $(OPA_DEST) $(OPA_URL)
	sudo chmod 755 $(OPA_DEST)

.PHONY: help test fmt fmt-check ci install-opa
