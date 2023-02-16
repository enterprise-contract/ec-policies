#!/usr/bin/env bash
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

# Updates a local clone of redhat-appstudio/infra-deployments to use the latest
# packages produced by this repository.
# Usage:
#   update-infra-deployments.sh <PATH_TO_INFRA_DEPLOYMENTS>

set -o errexit
set -o pipefail
set -o nounset

TARGET_DIR="${1}"
cd "${TARGET_DIR}" || exit 1

POLICY_DATA_REF='quay.io/hacbs-contract/ec-policy-data:latest'
RELEASE_POLICY_REF='quay.io/hacbs-contract/ec-release-policy:latest'

function oci_source() {
  img="${1}"
  # Must use --raw because skopeo cannot handle an OPA bundle image format.
  digest="$(skopeo inspect --raw  "docker://${img}" | sha256sum | awk '{print $1}')"
  echo "oci::https://${img}@sha256:${digest}"
}

function update_default_ecp() {
  SOURCE_KEY="${1}" SOURCE_URL="${2}" yq e -i \
    '(
        select(.kind == "EnterpriseContractPolicy" and .metadata.name == "default") |
        .spec.sources[0][env(SOURCE_KEY)][0] |= env(SOURCE_URL) |
        .
      ) // .' \
    components/enterprise-contract/default-ecp.yaml
}

echo 'Resolving bundle image references...'
POLICY_DATA_REF_OCI="$(oci_source ${POLICY_DATA_REF})"
echo "Resolved policy data is ${POLICY_DATA_REF_OCI}"
RELEASE_POLICY_REF_OCI="$(oci_source ${RELEASE_POLICY_REF})"
echo "Resolved release policy is ${RELEASE_POLICY_REF_OCI}"

echo 'Updating infra-deployments...'
update_default_ecp data "${POLICY_DATA_REF_OCI}"
update_default_ecp policy "${RELEASE_POLICY_REF_OCI}"
echo 'infra-deployments updated successfully'
