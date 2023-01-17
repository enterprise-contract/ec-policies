SHELL := /bin/bash

DATA_DIR=./data
CONFIG_DATA_FILE=$(DATA_DIR)/config.json

POLICY_DIR=./policy

TEST_FILES = $(DATA_DIR)/rule_data.yml $(POLICY_DIR) checks
define COVERAGE
@opa test --coverage --format json $(TEST_FILES) | { \
	T=$$(mktemp); tee "$${T}"; opa eval --format pretty \
	--input "$${T}" \
	--data hack/simplecov.rego \
	data.simplecov.from_opa > coverage.json; \
	rm -f "$${T}" || true ;\
} \
| jq -j -r 'if .coverage < 100 then "ERROR: Code coverage threshold not met: got \(.coverage) instead of 100.00\n" | halt_error(1) else "" end'
endef

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
test: soft-install-tools ## Run all tests in verbose mode and check coverage
	@opa test $(TEST_FILES) -v
	$(COVERAGE)

.PHONY: coverage
# The cat does nothing but avoids a non-zero exit code from grep -v
coverage: soft-install-tools ## Show which lines of rego are not covered by tests
	@opa test $(TEST_FILES) --coverage --format json | jq -r '.files | to_entries | map("\(.key): Uncovered:\(.value.not_covered)") | .[]' | grep -v "Uncovered:null" | cat

.PHONY: quiet-test
quiet-test: soft-install-tools ## Run all tests in quiet mode and check coverage
	@opa test $(TEST_FILES)
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
conftest-test: soft-install-tools ## Run all tests with conftest instead of opa
	@conftest verify \
	  --policy $(POLICY_DIR)

.PHONY: fmt
fmt: soft-install-tools ## Apply default formatting to all rego files. Use before you commit
	@opa fmt . --write

.PHONY: fmt-amend
fmt-amend: fmt ## Apply default formatting to all rego files then amend the current commit
	@git --no-pager diff $$(git ls-files '*.rego')
	@echo "Amend commit '$$(git log -n1 --oneline)' with the above diff?"
	@read -p "Hit enter to continue, Ctrl-C to abort."
	git add $$(git ls-files '*.rego')
	git commit --amend --no-edit

.PHONY: opa-check
opa-check: soft-install-tools ## Check Rego files with strict mode (https://www.openpolicyagent.org/docs/latest/strict/)
	@opa check $(TEST_FILES) --strict

.PHONY: conventions-check
conventions-check: soft-install-tools ## Check Rego policy files for convention violations
	@OUT=$$(opa eval --data checks --data $(POLICY_DIR)/lib --data data --input <(opa inspect . -a -f json) 'data.checks.violation[_]' --format raw); \
	if [[ -n "$${OUT}" ]]; then echo "$${OUT}"; exit 1; fi

.PHONY: ready
ready: fmt-amend ## Amend current commit with fmt changes

##@ Documentation

.PHONY: annotations-opa
annotations-opa: soft-install-tools
	@opa inspect --annotations --format json ./policy | jq '.annotations | sort_by(.location.file, .location.row)'

SHORT_SHA=$(shell git rev-parse --short HEAD)

# (The git checkout is so we don't leave the preid diff in package.json)
npm-publish: ## Publish the antora extension npm package. Requires a suitable NPM_TOKEN env var
	cd antora/ec-policies-antora-extension && \
	  npm version prerelease --preid $(SHORT_SHA) && \
	  npm publish --access=public && \
	  git checkout package.json

HACBS_DOCS_DIR=../hacbs-contract.github.io
HACBS_DOCS_REPO=git@github.com:hacbs-contract/hacbs-contract.github.io.git
$(HACBS_DOCS_DIR):
	mkdir $(HACBS_DOCS_DIR) && cd $(HACBS_DOCS_DIR) && git clone $(HACBS_DOCS_REPO) .

# Beware: This will build from your local main branch, which might not be what
# you're expecting. Change the branch in antora-playbook.yml manually if needed.
# (The second sed won't always be needed, but it should be okay to do it anyway.)
docs-preview: $(HACBS_DOCS_DIR) ## Build a preview of the documentation
	cd $(HACBS_DOCS_DIR) && \
	  sed -i 's|url: https://github.com/hacbs-contract/ec-policies.git|url: ../ec-policies|' antora-playbook.yml && \
	  sed -i "s|require: '@hacbs-contract/ec-policies-antora-extension'|require: ../ec-policies/antora/ec-policies-antora-extension|" antora-playbook.yml && \
	  npm ci && npm run build

##@ CI

.PHONY: fmt-check
fmt-check: soft-install-tools ## Check formatting of Rego files
	@opa fmt . --list | xargs -r -n1 echo 'FAIL: Incorrect formatting found in'
	@opa fmt . --list --fail >/dev/null 2>&1

.PHONY: ci
ci: quiet-test opa-check conventions-check fmt-check ## Runs all checks and tests

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
dummy-config: ## Create an empty configuration
	@echo '{"config":{"policy":{}}}' | jq > $(CONFIG_DATA_FILE)

# Set IMAGE as required like this:
#   make fetch-att IMAGE=<someimage>
#
ifndef IMAGE
  IMAGE="quay.io/redhat-appstudio/ec-golden-image:latest"
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

INPUT_DIR=./input
INPUT_FILE=$(INPUT_DIR)/input.json

RELEASE_NAMESPACE=release.main
PIPELINE_NAMESPACE=pipeline.main

.PHONY: check-release
check-release: soft-install-tools ## Run policy evaluation for release
	@conftest test $(INPUT_FILE) \
	  --namespace $(RELEASE_NAMESPACE) \
	  --policy $(POLICY_DIR) \
	  --data $(DATA_DIR) \
	  --no-fail \
	  --output json

.PHONY: check-pipeline
check-pipeline: soft-install-tools ## Run policy evaluation for pipeline definition
	@conftest test $(INPUT_FILE) \
	  --namespace $(PIPELINE_NAMESPACE) \
	  --policy $(POLICY_DIR) \
	  --data $(DATA_DIR) \
	  --no-fail \
	  --output json

.PHONY: check
check: check-release

#--------------------------------------------------------------------

##@ Bundles

update-bundles: ## Push policy bundles to quay.io and generate infra-deployments PRs if required
	@hack/update-bundles.sh

#--------------------------------------------------------------------

##@ Utility

CONFTEST_VER=0.37.0
CONFTEST_SHA_Darwin_x86_64=8cbac190f519fff0acbf70e2fa5cdbec0fd1a6e2a03cf6e5eecdca89f470b678
CONFTEST_SHA_Darwin_arm64=9646567f3b9978efa2c34ffdba1edee2b44a7e2760ed4a605742a26fe668eb18
CONFTEST_SHA_Linux_x86_64=3a3d56163b27c4641b0fab112171d76176bd084331825e5da549dd881f0bd4f0
CONFTEST_GOOS=$(shell go env GOOS | awk '{ print toupper( substr( $$0, 1, 1 ) ) substr( $$0, 2 ); }')
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

OPA_VER=v0.47.0
OPA_SHA_darwin_amd64=9d6cf8cfe0f6273b60076557f416b15213fe54ff5d72e4903543c573c32c395d
OPA_SHA_darwin_arm64_static=ad9abbffde89ad1aaf3fca565504174be3b28c35e8a48990454b3ec071b0a13d
OPA_SHA_linux_amd64_static=dfcb9c220448b3311d7199f4e7f586345079dd8732e8edc3afe748a48e8fd9c3
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

.PHONY: install-tools soft-install-tools
install-tools: install-conftest install-opa ## Force a reinstall of all tools
soft-install-tools: ## Install all tools if not installed
ifeq ("$(wildcard $(OPA_DEST))","")
	@$(MAKE) -s install-opa
endif
ifeq ("$(wildcard $(CONFTEST_DEST))","")
	@$(MAKE) -s install-conftest
endif
