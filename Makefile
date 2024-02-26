SHELL := /bin/bash

DATA_DIR=./example/data
CONFIG_DATA_FILE=$(DATA_DIR)/config.json

POLICY_DIR=./policy

OPA=go run github.com/enterprise-contract/ec-cli opa
CONFTEST=go run github.com/open-policy-agent/conftest
TKN=go run github.com/tektoncd/cli/cmd/tkn

TEST_FILES = $(DATA_DIR)/rule_data.yml $(POLICY_DIR) checks
define COVERAGE
@$(OPA) test --coverage --format json $(TEST_FILES) | { \
	T=$$(mktemp); tee "$${T}"; $(OPA) eval --format pretty \
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
test: ## Run all tests in verbose mode and check coverage
	@$(OPA) test $(TEST_FILES) -v
	$(COVERAGE)

.PHONY: coverage
# The cat does nothing but avoids a non-zero exit code from grep -v
coverage: ## Show which lines of rego are not covered by tests
	@$(OPA) test $(TEST_FILES) --coverage --format json | jq -r '.files | to_entries | map("\(.key): Uncovered:\(.value.not_covered)") | .[]' | grep -v "Uncovered:null" | cat

.PHONY: quiet-test
quiet-test: ## Run all tests in quiet mode and check coverage
	@$(OPA) test $(TEST_FILES)
	$(COVERAGE)

# Do `dnf install entr` then run this a separate terminal or split window while hacking
.PHONY: live-test
live-test: ## Continuously run tests on changes to any `*.rego` files, `entr` needs to be installed
	@trap exit SIGINT; \
	while true; do \
	  git ls-files -c -o '*.rego' | entr -r -d -c $(MAKE) --no-print-directory quiet-test; \
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
	@$(CONFTEST) verify \
	  --policy $(POLICY_DIR)

.PHONY: fmt
fmt: ## Apply default formatting to all rego files. Use before you commit
	@$(OPA) fmt . --write

.PHONY: fmt-amend
fmt-amend: fmt ## Apply default formatting to all rego files then amend the current commit
	@git --no-pager diff $$(git ls-files '*.rego')
	@echo "Amend commit '$$(git log -n1 --oneline)' with the above diff?"
	@read -p "Hit enter to continue, Ctrl-C to abort."
	git add $$(git ls-files '*.rego')
	git commit --amend --no-edit

.PHONY: opa-check
opa-check: ## Check Rego files with strict mode (https://www.openpolicyagent.org/docs/latest/strict/)
	@$(OPA) check $(TEST_FILES) --strict

.PHONY: conventions-check
conventions-check: ## Check Rego policy files for convention violations
	@OUT=$$($(OPA) eval --data checks --data $(POLICY_DIR)/lib --input <($(OPA) inspect . -a -f json) 'data.checks.violation[_]' --format raw); \
	if [[ -n "$${OUT}" ]]; then echo "$${OUT}"; exit 1; fi

.PHONY: ready
ready: fmt-amend ## Amend current commit with fmt changes

##@ Documentation

.PHONY: annotations-opa
annotations-opa:
	@$(OPA) inspect --annotations --format json ./policy | jq '.annotations | sort_by(.location.file, .location.row)'

SHORT_SHA=$(shell git rev-parse --short HEAD)

# (The git checkout is so we don't leave the preid diff in package.json)
npm-publish: ## Publish the antora extension npm package. Requires a suitable NPM_TOKEN env var
	cd antora/ec-policies-antora-extension && \
	  npm version prerelease --preid $(SHORT_SHA) && \
	  npm publish --access=public && \
	  git checkout package.json

EC_DOCS_DIR=../enterprise-contract.github.io
EC_DOCS_REPO=git@github.com:enterprise-contract/enterprise-contract.github.io.git
$(EC_DOCS_DIR):
	mkdir $(EC_DOCS_DIR) && cd $(EC_DOCS_DIR) && git clone $(EC_DOCS_REPO) .

# See also the hack/local-build.sh script in the
# enterprise-contract.github.io repo which does something similar
CURRENT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
docs-preview: $(EC_DOCS_DIR) ## Build a preview of the documentation
	cd antora/ec-policies-antora-extension && \
	  npm ci
	cd $(EC_DOCS_DIR)/antora && \
	  yq e -i '.content.sources[] |= select(.url == "*ec-policies*").url |= "../../ec-policies"' antora-playbook.yml && \
	  yq e -i '.content.sources[] |= select(.url == "*ec-policies*").branches |= "$(CURRENT_BRANCH)"' antora-playbook.yml && \
	  yq e -i '.antora.extensions[] |= select(.require == "*ec-policies-antora-extension").require |= "../../ec-policies/antora/ec-policies-antora-extension"' antora-playbook.yml && \
	  npm ci && npm run build

##@ CI

.PHONY: fmt-check
fmt-check: ## Check formatting of Rego files
	@$(OPA) fmt . --list | xargs -r -n1 echo 'FAIL: Incorrect formatting found in'
	@$(OPA) fmt . --list --fail >/dev/null 2>&1

# See config in .regal/config.yaml
.PHONY: lint
lint: ## Runs Rego linter
	@go run github.com/styrainc/regal lint . $(if $(GITHUB_ACTIONS),--format=github)

.PHONY: ci
ci: quiet-test acceptance opa-check conventions-check fmt-check lint ## Runs all checks and tests

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

# jq snippets to massage the various pieces of data into the shape we want.
# Each part gets deep merged together into a single object similar to the
# input that ec-cli would present to the conftest evaluator. (Note that it
# doesn't include everything - the `attestations[].extra.signatures` and
# `image.signatures` fields are missing.)
#
JQ_COSIGN={"attestations": [.[].payload | @base64d | fromjson]}
JQ_SKOPEO={"image": {"ref": "\(.Name)@\(.Digest)"}}
JQ_SKOPEO_CONFIG={"image": {"config": .config}}
JQ_SKOPEO_RAW={"image": {"parent": {"ref": .annotations["org.opencontainers.image.base.name"]}}}

.PHONY: fetch-att
fetch-att: clean-input ## Fetches attestation data and metadata for IMAGE, use `make fetch-att IMAGE=<ref>`
	jq -s '.[0] * .[1] * .[2] * .[3]' \
	  <( cosign download attestation $(IMAGE)       | jq -s '$(JQ_COSIGN)'     ) \
	  <( skopeo inspect --no-tags docker://$(IMAGE) | jq '$(JQ_SKOPEO)'        ) \
	  <( skopeo inspect --config  docker://$(IMAGE) | jq '$(JQ_SKOPEO_CONFIG)' ) \
	  <( skopeo inspect --raw     docker://$(IMAGE) | jq '$(JQ_SKOPEO_RAW)'    ) \
	  > $(INPUT_FILE)

#--------------------------------------------------------------------

# A convenient way to populate input/input.json with a pipeline definition
# Specify PIPELINE as an environment var to use something other than the default.
#
ifndef PIPELINE
  PIPELINE=quay.io/redhat-appstudio-tekton-catalog/pipeline-docker-build:devel
endif

.PHONY: fetch-pipeline
fetch-pipeline: clean-input ## Fetches pipeline data for PIPELINE from your local cluster, use `make fetch-pipeline PIPELINE=<name>`
	@$(TKN) bundle list $(PIPELINE) -o json > $(INPUT_FILE)

#--------------------------------------------------------------------

##@ Running

INPUT_DIR=./input
INPUT_FILE=$(INPUT_DIR)/input.json

.PHONY: check-release
check-release: ## Run policy evaluation for release
	@$(CONFTEST) test $(INPUT_FILE) \
	  --all-namespaces \
	  --policy $(POLICY_DIR) \
	  --data $(DATA_DIR) \
	  --no-fail \
	  --output json

.PHONY: check-pipeline
check-pipeline: ## Run policy evaluation for pipeline definition
	@$(CONFTEST) test $(INPUT_FILE) \
	  --all-namespaces \
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

##@ Acceptance Tests

.PHONY: acceptance
acceptance: ## Run acceptance tests
	@cd acceptance && go test ./...

#--------------------------------------------------------------------
