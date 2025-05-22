#!/bin/env bash
# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Updates the JSON sample files used by acceptance tests in /acceptance/samples

set -o errexit
set -o pipefail
set -o nounset

ROOT_DIR=$(git rev-parse --show-toplevel)
IMAGE=quay.io/konflux-ci/ec-golden-image:latest
# If $IMAGE is released to a different repo, some of the attachments may not get copied over, e.g.
# CVE scan report. Set $ORIGINAL_IMAGE_REPO to the repo in which the image was originally built into
# which should contain all the attachments.
ORIGINAL_IMAGE_REPO='quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container'
REPOSITORY=https://github.com/conforma/golden-container.git
PUBLIC_KEY='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZP/0htjhVt2y0ohjgtIIgICOtQtA
naYJRuLprwIv6FDhZ5yFjYUEtsmoNcW7rx2KM6FOXGsCX3BNc7qhHELT+g==
-----END PUBLIC KEY-----'
INPUT_FILE="${ROOT_DIR}/acceptance/samples/policy-input-golden-container.json"
TRUSTED_TASKS_FILE="${ROOT_DIR}/example/data/trusted_tekton_tasks.yml"

trap 'rm -f "${TRUSTED_TASKS_FILE}-update"' EXIT

DIGEST="$(skopeo inspect --no-tags "docker://${IMAGE}" --format '{{index .Digest}}')"
ORIGINAL_IMAGE_REF="${ORIGINAL_IMAGE_REPO}@${DIGEST}"
REVISION="$(skopeo inspect --no-tags "docker://${ORIGINAL_IMAGE_REF}" --format '{{index .Labels "vcs-ref"}}')"

IMAGES="{
  "components": [
    {
      "containerImage": "${ORIGINAL_IMAGE_REF}",
      "source": {
        "git": {
          "revision": "${REVISION}",
          "url": "${REPOSITORY}"
        }
      }
    }
  ]
}"

POLICY='{
  "sources": [
    {
      "policy": [
        "'${ROOT_DIR}'/policy/lib",
        "'${ROOT_DIR}'/policy/release"
      ],
      "data": [
        "github.com/release-engineering/rhtap-ec-policy//data",
        "oci::quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles:latest"
      ],
      "config": {
        "include": [
          "@redhat"
        ],
        "exclude": [
          "source_image"
        ]
      }
    }
  ]
}'

go run -modfile "${ROOT_DIR}/go.mod" github.com/enterprise-contract/ec-cli validate image \
    --images "${IMAGES}" \
    --public-key "${PUBLIC_KEY}" \
    --ignore-rekor \
    --policy "${POLICY}" \
    --output policy-input="${INPUT_FILE}" \
    --output data="${TRUSTED_TASKS_FILE}-update" \
    --output text

# shellcheck disable=SC2094
# we have one attestation per CPU architecture, so we pick the first one
cat <<< "$(jq --slurp --sort-keys '.[0]' "${INPUT_FILE}")" > "${INPUT_FILE}"

# shellcheck disable=SC2094
cat <<< "$(yq eval-all 'select(fileIndex==0).trusted_tasks = (select(fileIndex==1) | .[0].[0].trusted_tasks) | select(fileIndex==0)' \
  "${TRUSTED_TASKS_FILE}" \
  "${TRUSTED_TASKS_FILE}-update")" > "${TRUSTED_TASKS_FILE}"
