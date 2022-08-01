SHELL := /bin/bash
COVERAGE = @opa test . --ignore '.*' --threshold 100 2>&1 | sed -e '/^Code coverage/!d' -e 's/^/ERROR: /'; exit $${PIPESTATUS[0]}

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

.PHONY: test
test: ## Run all tests in verbose mode and check coverage
	@opa test . -v --ignore '.*'
	$(COVERAGE)

.PHONY: coverage
coverage: ## Show which lines of rego are not covered by tests
	@opa test . --ignore '.*' --coverage --format json | jq -r '.files | to_entries | map("\(.key): Uncovered:\(.value.not_covered)") | .[]' | grep -v "Uncovered:null"

.PHONY: quiet-test
quiet-test: ## Run all tests in quiet mode and check coverage
	@opa test . --ignore '.*'
	$(COVERAGE)

# Do `dnf install entr` then run this a separate terminal or split window while hacking
.PHONY: live-test
live-test: ## Continuously run tests on changes to any `*.rego` files, `entr` needs to be installed
	@trap exit SIGINT; \
	while true; do \
	  git ls-files -c -o '*.rego' | entr -d -c $(MAKE) --no-print-directory quiet-test; \
	done

##
## Fixme: Currently conftest verify produces a error:
##   "rego_type_error: package annotation redeclared"
## In these two files:
##   policy/release/examples/time_based.rego
##   policy/lib/time_test.rego:1
## The error only appears when running the tests.
##
## Since the metadata support is a new feature in opa, it might be this
## is a bug that will go away in a future release of conftest. So for now
## we will ignore the error and not use conftest verify in the CI.
##
.PHONY: conftest-test
conftest-test: ## Run all tests with conftest instead of opa
	@conftest verify \
	  --policy $(POLICY_DIR)

.PHONY: fmt
fmt: ## Apply default formatting to all rego files. Use before you commit
	@opa fmt . --write

.PHONY: fmt-amend
fmt-amend: fmt ## Apply default formatting to all rego files then amend the current commit
	@git --no-pager diff $$(git ls-files '*.rego')
	@echo "Amend commit '$$(git log -n1 --oneline)' with the above diff?"
	@read -p "Hit enter to continue, Ctrl-C to abort."
	git add $$(git ls-files '*.rego')
	git commit --amend --no-edit

.PHONY: opa-check
opa-check: ## Check Rego files with strict mode (https://www.openpolicyagent.org/docs/latest/strict/)
	@opa check . --strict --ignore '.*'

.PHONY: conventions-check
conventions-check: ## Check Rego policy files for convention violations
	@OUT=$$(opa eval --data checks --data $(POLICY_DIR)/lib --input <(opa inspect . -a -f json) 'data.checks.violation[_]' --format raw); \
	if [[ -n "$${OUT}" ]]; then echo "$${OUT}"; exit 1; fi

.PHONY: ready
ready: fmt-amend docs-amend ## Amend current commit with fmt and docs changes

##@ Documentation

DOCSRC=./docsrc
DOCS_TMP_JSON=$(DOCSRC)/annotations-data.json
# Asciidoc format for Antora
DOCS_ADOC=./antora-docs/modules/ROOT/pages/index.adoc
# (Only one generated doc file currently)
DOCS_ALL=$(DOCS_ADOC)

build-docs: ## Generate documentation. Use this before commit if you modified any rules or annotations
	@opa inspect --annotations --format json $(POLICY_DIR) > $(DOCS_TMP_JSON)
	@gomplate -d rules=$(DOCS_TMP_JSON) -f $(DOCSRC)/$$( basename $(DOCS_ADOC) ).tmpl | cat -s > $(DOCS_ADOC)
	@rm $(DOCS_TMP_JSON)

.PHONY: docs-amend
docs-amend: docs-build ## Update the docs and amend the current commit
	@git --no-pager diff $(DOCS_ALL)
	@echo "Amend commit '$$(git log -n1 --oneline)' with the above diff?"
	@read -p "Hit enter to continue, Ctrl-C to abort."
	git add $(DOCS_ALL)
	git commit --amend --no-edit

.PHONY: docs-render
docs-render: ## Builds the Antora documentation with the local changes
	@npm exec -y --quiet antora generate --clean --fetch antora-playbook.yml

# Do `dnf install entr` then run this a separate terminal or split window while hacking
.ONESHELL:
.SHELLFLAGS=-e -c
docs-preview: ## Run the preview of the website, reload to see the changes
	@$(MAKE) docs-build-local
	@xdg-open public/index.html || true
	@trap exit SIGINT
	while true; do
	  git ls-files --exclude-standard -c -o 'antora-*' | entr -d -c $(MAKE) --no-print-directory docs-build-local
	done

##@ CI

fmt-check: ## Check formatting of Rego files
	@opa fmt . --list | xargs -r -n1 echo 'FAIL: Incorrect formatting found in'
	@opa fmt . --list --fail >/dev/null 2>&1

docs-check: ## Check if the generated docs are up to date
	@cp $(DOCS_ADOC) $(DOCS_ADOC).check
	@$(MAKE) --no-print-directory docs-build
	@if [[ -n $$( git diff --name-only -- $(DOCS_ALL) ) ]]; then \
	  mv $(DOCS_ADOC).check $(DOCS_ADOC); \
	  echo "FAIL: A docs update is needed"; \
	  exit 1; \
	fi
	@mv $(DOCS_ADOC).check $(DOCS_ADOC)

ci: conventions-check quiet-test opa-check fmt-check docs-check ## Runs all checks and tests

#--------------------------------------------------------------------

##@ Data helpers

.PHONY: clean-input
clean-input: ## Removes everything from the `./input` directory
	@rm -rf $(INPUT_DIR)
	@mkdir $(INPUT_DIR)

.PHONY: clean-data
clean-data: ## Removes ephemeral files from the `./data` directory
	@rm -rf $(CONFIG_DATA_FILE)

.PHONY: dummy-config
dummy-config: ## Changes the configuration to mark the `not_useful` check as non-blocking to avoid a "feels like a bad day.." violation
	@echo '{"config":{"policy":{"non_blocking_checks":["not_useful"]}}}' | jq > $(CONFIG_DATA_FILE)

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
  IMAGE="quay.io/lucarval/single-nodejs-app:demo"
endif

.PHONY: fetch-att
fetch-att: clean-input ## Fetches attestation data for IMAGE, use `make fetch-att IMAGE=<ref>`. Note: This is compatible with the 'verify-enterprise-contract' task
	cosign download attestation $(IMAGE) | \
	  jq -s '{ "attestations": [.[].payload | @base64d | fromjson] }' > $(INPUT_FILE)

#--------------------------------------------------------------------

# A convenient way to populate input/input.json with a pipeline definition
# Specify PIPELINE as an environment var to use something other than the default.
#
ifndef PIPELINE
  PIPELINE=s2i-nodejs -n openshift
endif

.PHONY: fetch-pipeline
fetch-pipeline: clean-input ## Fetches pipeline data for PIPELINE from your local cluster, use `make fetch-pipeline PIPELINE=<name>`
	oc get pipeline $(PIPELINE) -o json > $(INPUT_FILE)

#--------------------------------------------------------------------

##@ Running

DATA_DIR=./data
CONFIG_DATA_FILE=$(DATA_DIR)/config.json

INPUT_DIR=./input
INPUT_FILE=$(INPUT_DIR)/input.json

RELEASE_NAMESPACE=release.main
PIPELINE_NAMESPACE=pipeline.main

POLICY_DIR=./policy
OPA_FORMAT=pretty

.PHONY: check-release
check-release: ## Run policy evaluation for release
	@conftest test $(INPUT_FILE) \
	  --namespace $(RELEASE_NAMESPACE) \
	  --policy $(POLICY_DIR) \
	  --data $(DATA_DIR) \
	  --no-fail \
	  --output json

.PHONY: check-pipeline
check-pipeline: ## Run policy evaluation for pipeline definition
	@conftest test $(INPUT_FILE) \
	  --namespace $(PIPELINE_NAMESPACE) \
	  --policy $(POLICY_DIR) \
	  --data $(DATA_DIR) \
	  --no-fail \
	  --output json

.PHONY: check
check: check-release

#--------------------------------------------------------------------

.PHONY: check-release-opa
check-release-opa: ## Run policy evaluation for release using opa. Deprecated.
	@opa eval \
	  --input $(INPUT_FILE) \
	  --data $(DATA_DIR) \
	  --data $(POLICY_DIR) \
	  --format $(OPA_FORMAT) \
	  data.$(RELEASE_NAMESPACE).deny

.PHONY: check-pipeline-opa
check-pipeline-opa: ## Run policy evaluation for pipeline using opa. Deprecated.
	@opa eval \
	  --input $(INPUT_FILE) \
	  --data $(DATA_DIR) \
	  --data $(POLICY_DIR) \
	  --format $(OPA_FORMAT) \
	  data.$(PIPELINE_NAMESPACE).deny

#--------------------------------------------------------------------

##@ Utility

CONFTEST_VER=0.32.0
CONFTEST_SHA_Darwin_x86_64=a692cd676cbcdc318d16f261c353c69e0ef69aff5fb0442f3cb909df13beb895
CONFTEST_SHA_Darwin_arm64=a52365dffe6a424a3e72517fb987a45accd736540e792625a44d9d10f4d527fe
CONFTEST_SHA_Linux_x86_64=e368ef4fcb49885e9c89052ec0c29cf4d4587707a589fefcaa3dc9cc72065055
CONFTEST_GOOS=$(shell go env GOOS | sed 's/./\u&/' )
CONFTEST_GOARCH=$(shell go env GOARCH | sed 's/amd64/x86_64/' )
CONFTEST_OS_ARCH=$(CONFTEST_GOOS)_$(CONFTEST_GOARCH)
CONFTEST_FILE=conftest_$(CONFTEST_VER)_$(CONFTEST_OS_ARCH).tar.gz
CONFTEST_URL=https://github.com/open-policy-agent/conftest/releases/download/v$(CONFTEST_VER)/$(CONFTEST_FILE)
CONFTEST_SHA=$(CONFTEST_SHA_${CONFTEST_OS_ARCH})
ifndef CONFTEST_BIN
  CONFTEST_BIN=$(HOME)/bin
endif
CONFTEST_DEST=$(CONFTEST_BIN)/conftest

.PHONY: install-conftest
install-conftest: ## Install `conftest` CLI from GitHub releases
	curl -s -L -O $(CONFTEST_URL)
	echo "$(CONFTEST_SHA) $(CONFTEST_FILE)" | sha256sum --check
	tar xzf $(CONFTEST_FILE) conftest
	@mkdir -p $(CONFTEST_BIN)
	mv conftest $(CONFTEST_DEST)
	chmod 755 $(CONFTEST_DEST)
	rm $(CONFTEST_FILE)

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

.PHONY: install-opa
install-opa: ## Install `opa` CLI from GitHub releases
	curl -s -L -O $(OPA_URL)
	echo "$(OPA_SHA) $(OPA_FILE)" | sha256sum --check
	@mkdir -p $(OPA_BIN)
	cp $(OPA_FILE) $(OPA_DEST)
	chmod 755 $(OPA_DEST)
	rm $(OPA_FILE)

GOMPLATE_VER=3.10.0
GOMPLATE_OS_ARCH=$(shell go env GOOS)-$(shell go env GOARCH)
GOMPLATE_FILE=gomplate_$(GOMPLATE_OS_ARCH)
GOMPLATE_URL=https://github.com/hairyhenderson/gomplate/releases/download/v$(GOMPLATE_VER)/$(GOMPLATE_FILE)
ifndef GOMPLATE_BIN
  GOMPLATE_BIN=$(HOME)/bin
endif
GOMPLATE_DEST=$(GOMPLATE_BIN)/gomplate

.PHONY: install-gomplate
install-gomplate: ## Install `gomplate` from GitHub releases
	curl -s -L -O $(GOMPLATE_URL)
	@mkdir -p $(GOMPLATE_BIN)
	cp $(GOMPLATE_FILE) $(GOMPLATE_DEST)
	chmod 755 $(GOMPLATE_DEST)
	rm $(GOMPLATE_FILE)

.PHONY: install-tools
install-tools: install-conftest install-opa install-gomplate ## Install all three tools
