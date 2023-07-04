#!/usr/bin/env bash
# Copyright 2023 Red Hat, Inc.
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

# Use the Enterprise Contract to validate the Tekton pipeline bundles being added to
# data/acceptable_tekton_bundles.yml. The list of bundles to verify is a computed by
# diff'ing against the list of bundles in origin/main. If there's no difference, this
# script succeeds.
# Usage:
#   hack/validate-acceptable-bundles.sh

set -o errexit
set -o pipefail
set -o nounset

if [ "${RUNNER_DEBUG:-}" == "1" ]; then
  set -x
fi

if ! command -v ec > /dev/null 2>&1; then
    # this is most likely on GitHub Actions, which runs on 64bit Linux
    curl -o ec -sSL https://github.com/enterprise-contract/ec-cli/releases/download/snapshot/ec_linux_amd64
    chmod +x ec
    PATH=$PATH:$PWD
    trap "rm ec" EXIT
fi

bundles_file='data/acceptable_tekton_bundles.yml'

function list_pipeline_bundles() {
    < "${1}" yq \
        '."pipeline-bundles" | to_entries | .[] | [.key + "@" + .value[].digest] | .[]' | sort -u
}

origin_bundles="$(list_pipeline_bundles <(curl -s "https://raw.githubusercontent.com/enterprise-contract/ec-policies/main/${bundles_file}"))"
pr_bundles="$(list_pipeline_bundles "${bundles_file}")"
new_bundles="$(comm -13 <(echo "${origin_bundles}") <(echo "${pr_bundles}"))"

all_success=true
for ref in ${new_bundles}; do
    # Verify the image is accessible
    set +e
    skopeo_error="$(skopeo inspect --raw "docker://${ref}" 2>&1 >/dev/null)"
    accessbile="$?"
    set -e
    if [[ $accessbile -ne 0 ]]; then
        all_success=false
        echo "❌ ${ref}"
        echo "${skopeo_error}"
        echo
        continue
    fi

    # Evaluate the pipeline definition
    report="$(ec validate definition \
        --policy git::https://github.com/enterprise-contract/ec-policies//policy/lib?ref=main \
        --policy git::https://github.com/enterprise-contract/ec-policies//policy/pipeline?ref=main \
        --data git::https://github.com/enterprise-contract/ec-policies//data?ref=main \
        --file <(tkn bundle list -o json "${ref}" 2> /dev/null) \
        || true)"

    # Process evaluation result
    ref_success="$(echo -n "${report}" | jq -r '.success')"
    if [[ "$ref_success" == "true" ]]; then
        echo "✅ ${ref}"
    else
        all_success=false
        echo "❌ ${ref}"
        echo "${report}" | jq '.definitions[].violations[]'
        echo
    fi
done

if [[ "$all_success" == false ]]; then
    echo "😭 Validation failed!"
    exit 1
fi
echo "🎉 Great success!"
