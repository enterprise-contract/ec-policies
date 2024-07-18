#!/bin/env bash
# Copyright The Enterprise Contract Contributors
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
IMAGE=quay.io/redhat-appstudio/ec-golden-image:latest
REPOSITORY=https://github.com/enterprise-contract/golden-container.git
PUBLIC_KEY='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZP/0htjhVt2y0ohjgtIIgICOtQtA
naYJRuLprwIv6FDhZ5yFjYUEtsmoNcW7rx2KM6FOXGsCX3BNc7qhHELT+g==
-----END PUBLIC KEY-----'
INPUT_FILE="${ROOT_DIR}/acceptance/samples/policy-input-golden-container.json"
TRUSTED_TASKS_FILE="${ROOT_DIR}/example/data/trusted_tekton_tasks.yml"

trap 'rm "${TRUSTED_TASKS_FILE}-update"' EXIT

go run -modfile "${ROOT_DIR}/go.mod" github.com/enterprise-contract/ec-cli validate image \
    --images <(cat << EOF
{
  "components": [
    {
      "containerImage": "${IMAGE}",
      "source": {
        "git": {
          "revision": "$(skopeo inspect "docker://${IMAGE}" --format '{{index .Labels "vcs-ref"}}')",
          "url": "${REPOSITORY}"
        }
      }
    }
  ]
}
EOF
) \
    --public-key <(echo "${PUBLIC_KEY}") \
    --ignore-rekor \
    --policy "$(printf '{
    "sources": [
        {
            "policy": [
                "%s/policy/lib",
                "%s/policy/release"
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
                    "cve.deprecated_cve_result_name",
                    "source_image"
                ]
            }
        }
    ]
}' "${ROOT_DIR}" "${ROOT_DIR}"
)" \
    --output policy-input="${INPUT_FILE}" \
    --output data="${TRUSTED_TASKS_FILE}-update" \

# shellcheck disable=SC2094
# we have one attestation per CPU architecture, so we pick the first one
cat <<< "$(jq --slurp --sort-keys '.[0]' "${INPUT_FILE}")" > "${INPUT_FILE}"

# shellcheck disable=SC2094
cat <<< "$(yq eval-all 'select(fileIndex==0).trusted_tasks = (select(fileIndex==1) | .[0].[0].trusted_tasks) | select(fileIndex==0)' \
  "${TRUSTED_TASKS_FILE}" \
  "${TRUSTED_TASKS_FILE}-update")" > "${TRUSTED_TASKS_FILE}"
