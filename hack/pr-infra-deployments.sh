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

RELEASE_BUNDLE_TAG="git-$(git rev-parse --short HEAD)"
RELEASE_BUNDLE_TAG="git-d47b70d"
RELEASE_BUNDLE_DIGEST="$(skopeo manifest-digest <(skopeo inspect --raw "docker://quay.io/hacbs-contract/ec-release-policy:${RELEASE_BUNDLE_TAG}"))"
RELEASE_BUNDLE_REF="quay.io/hacbs-contract/ec-release-policy:${RELEASE_BUNDLE_TAG}@${RELEASE_BUNDLE_DIGEST}"

GIT_REF="$(git rev-parse HEAD)"

# setup
WORKDIR=$(mktemp -d)
trap 'rm -rf "${WORKDIR}"' EXIT
cd "${WORKDIR}" || exit 1

gh repo clone hacbs-contract/infra-deployments
cd infra-deployments || exit 1
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  git remote set-url origin git@github.com:hacbs-contract/infra-deployments.git
  git config --global user.email "${GITHUB_ACTOR}@users.noreply.github.com"
  git config --global user.name "${GITHUB_ACTOR}"
  mkdir -p "${HOME}/.ssh"
  echo "${DEPLOY_KEY}" > "${HOME}/.ssh/id_ed25519"
  chmod 600 "${HOME}/.ssh/id_ed25519"
  trap 'rm -rf "${WORKDIR}" "${HOME}/.ssh/id_rsa"' EXIT
  export GITHUB_USER="$GITHUB_ACTOR"
fi
git checkout -b ec-policy-update --track upstream/main

# replacements
yq e -i '.configMapGenerator[] |= select(.name == "ec-defaults").literals[] |= select(. == "ec_policy_source=*") = "ec_policy_source='"oci::https://${RELEASE_BUNDLE_REF}"'"' components/enterprise-contract/kustomization.yaml
yq e -i '.configMapGenerator[] |= select(.name == "ec_data_source").literals[] |= select(. == "ec_data_source=*") = "ec_data_source='"git::https://github.com/hacbs-contract/ec-policies.git//data?ref=${GIT_REF}"'"' components/enterprise-contract/kustomization.yaml

# commit & push
git commit -a -m "enterprise contract policy update"
git push --force -u origin ec-policy-update

# create pull request, don't fail if it already exists
gh pr create --fill --no-maintainer-edit --repo redhat-appstudio/infra-deployments || true
