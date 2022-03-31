
help:
	@echo "Usage:"
	@echo "  make test         # Run all tests"
	@echo "  make install-opa  # Install opa if you don't have it already (Linux only)"

test:
	@opa test . -v

OPA_VER=v0.39.0
OPA_URL=https://openpolicyagent.org/downloads/$(OPA_VER)/opa_linux_amd64_static
OPA_DEST=/usr/bin/opa

install-opa:
	sudo curl -s -L -o $(OPA_DEST) $(OPA_URL)
	sudo chmod 755 $(OPA_DEST)

.PHONY: help test install-opa
