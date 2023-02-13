#!/bin/env bash
# Copyright 2022 Red Hat, Inc.
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

# Creates a pull request with updates to the redhat-appstudio/infra-deployments
# repository. Usually run upon release.

set -o errexit
set -o pipefail
set -o nounset

GIT_REPO_NAME=infra-deployments
GIT_ORIGIN=hacbs-contract/${GIT_REPO_NAME}
GIT_UPSTREAM=redhat-appstudio/${GIT_REPO_NAME}

# Clone repo to a temp dir
WORKDIR=$(mktemp -d)
trap 'rm -rf "${WORKDIR}"' EXIT
cd "${WORKDIR}" || exit 1
gh repo clone "$GIT_ORIGIN"
cd infra-deployments || exit 1

# Setup key for access in the GH workflow
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  git remote set-url origin git@github.com:${GIT_ORIGIN}.git
  git config --global user.email "${GITHUB_ACTOR}@users.noreply.github.com"
  git config --global user.name "${GITHUB_ACTOR}"
  mkdir -p "${HOME}/.ssh"
  echo "${DEPLOY_KEY}" > "${HOME}/.ssh/id_ed25519"
  chmod 600 "${HOME}/.ssh/id_ed25519"
  trap 'rm -rf "${WORKDIR}" "${HOME}/.ssh/id_rsa"' EXIT
  export GITHUB_USER="$GITHUB_ACTOR"
fi

# Create the branch
BRANCH_NAME=ec-policy-bundle-update
git checkout -b ${BRANCH_NAME} --track upstream/main

# Loop over params in pairs
while [ $# -gt 0 ]; do
  KEY=$1
  NEW_BUNDLE=$2
  shift
  shift

  # Find the digest
  NEW_DIGEST="$(skopeo manifest-digest <(skopeo inspect --raw "docker://${NEW_BUNDLE}"))"
  SOURCE_URL="oci::https://${NEW_BUNDLE}@${NEW_DIGEST}"

  # Update the default EnterpriseContractPolicy resource with the new source URLs
  SOURCE_KEY="$KEY" SOURCE_URL="$SOURCE_URL" yq e -i \
    '(
        select(.kind == "EnterpriseContractPolicy" and .metadata.name == "default") |
        .spec.sources[0][env(SOURCE_KEY)][0] |= env(SOURCE_URL) |
        .
     ) // .' \
    components/enterprise-contract/default-ecp.yaml
done

# commit & push
git commit -a -m "enterprise contract policy update"
git push --force -u origin ${BRANCH_NAME}

# create pull request, don't fail if it already exists
gh pr create --fill --no-maintainer-edit --repo ${GIT_UPSTREAM} || true
