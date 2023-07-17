#!/bin/env bash
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

# Checks if the latest entries in acceptable_tekton_bundles.yml are in fact the latest entries
# in the registry for them.
#
set -o errexit
set -o pipefail
set -o nounset

BUNDLES_FILE="$(git rev-parse --show-toplevel)/data/acceptable_tekton_bundles.yml"

bundles="$(< "${BUNDLES_FILE}" \
    yq '."task-bundles" + ."pipeline-bundles" | to_entries | map(.key + ":" + .value[0].tag + "@" + .value[0].digest) | .[]')"


echo '🕵️ Looking for untracked acceptable bundles...'
new_bundles=''
for b in $bundles; do
    digest="$(echo -n $b | cut -d '@' -f 2)"

    repo="$(echo -n $b | cut -d '@' -f 1 | cut -d ':' -f 1)"
    tag="$(echo -n $b | cut -d '@' -f 1 | cut -d ':' -f 2)"

    new_digest="$(skopeo inspect --no-tags "docker://${repo}:$tag" | jq -r .Digest)"

    if [[ "${new_digest}" == "${digest}" ]]; then
        continue
    fi

    new_bundle="${repo}:${tag}@${new_digest}"
    echo "🫢 ${new_bundle}"

    new_bundles="${new_bundles} --bundle=${new_bundle}"  # Intentional leading white-space
done

if [[ -z "${new_bundles}" ]]; then
    echo '🥳 Latest acceptable bundles are being tracked'
    exit 0
fi

ec track bundle --input "${BUNDLES_FILE}" --replace ${new_bundles} > /dev/null

git diff -- "${BUNDLES_FILE}"
