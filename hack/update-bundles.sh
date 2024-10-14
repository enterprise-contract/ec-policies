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

# Pushes policy bundles to quay.io, but only if anything changed since
# the last bundle was pushed.
#
set -o errexit
set -o pipefail
set -o nounset

REPO_PREFIX="${REPO_PREFIX-quay.io/enterprise-contract/}"
ROOT_DIR=$( git rev-parse --show-toplevel )
BUNDLES="release pipeline task build_task"
OPA="go run github.com/enterprise-contract/ec-cli opa"
ORAS="go run oras.land/oras/cmd/oras"

DRY_RUN=${DRY_RUN:-""}
DRY_RUN_ECHO=""
[ "$DRY_RUN" == "1" ] && DRY_RUN_ECHO="echo #"

function bundle_src_dirs() {
  echo policy/lib
  echo "policy/$1"
}

function bundle_subdir() {
  echo "policy"
}

function exclusions() {
  echo "artifacthub-pkg.yml"
}

function repo_name() {
  echo "ec-$1-policy"
}

tmp_oci_dirs=()
function cleanup() {
  rm -rf "${tmp_oci_dirs[@]}"
}
trap cleanup EXIT


for b in $BUNDLES; do
  # Find the git sha where the source files were last updated
  mapfile -t src_dirs < <(bundle_src_dirs "$b")
  last_update_sha=$(git log -n 1 --pretty=format:%h -- "${src_dirs[@]}")

  # Check if the bundle for that git sha exists already
  repo=$(repo_name "$b")
  tag=git-$last_update_sha
  push_repo="${REPO_PREFIX}$repo"

  skopeo_args=()
  skopeo_cp_args=()
  if [[ $push_repo == *'localhost:'* ]]; then
    skopeo_args+=(--tls-verify=false)
    skopeo_cp_args+=(--dest-tls-verify=false --src-tls-verify=false)
  fi

  tag_found="$(
    {
      skopeo list-tags "${skopeo_args[@]}" "docker://${push_repo}" |
      jq --arg tag "${tag}" -r 'any(.Tags[]; . == $tag)';
    } || echo false
  )"
  if [[ "$tag_found" == 'true' ]]; then
    # No push needed
    echo "Policy bundle $push_repo:$tag exists already, no push needed"
  else
    # Push needed
    echo "Pushing policy bundle $push_repo:$tag now"

    # Prepare a temp dir with the bundle's content
    tmp_dir=$(mktemp -d -t "ec-bundle-$b.XXXXXXXXXX")
    tmp_oci_dirs+=("${tmp_dir}")
    content_dir=$tmp_dir/$(bundle_subdir "$b")
    mkdir "${content_dir}"
    for d in "${src_dirs[@]}"; do
      cp -r "$d" "${content_dir}"
    done

    # Remove some files
    exclude_files=$(exclusions "$b")
    for f in $exclude_files; do
      find "${content_dir}" -name "$f" -delete
    done

    # Show the content
    cd "${tmp_dir}" || exit 1
    find . -type f

    # go.mod/go.sum files needs to be copied for go run to function
    cp "${ROOT_DIR}/go.mod" "${ROOT_DIR}/go.sum" "$tmp_dir"

    # Verify the selected sources can be compiled as one unit, e.g. "policy/lib" is included
    ${OPA} build "${src_dirs[@]}" --output /dev/null

    # Now push
    ${ORAS} push "$push_repo:$tag" "${src_dirs[@]}" \
      --annotation "org.opencontainers.image.revision=${last_update_sha}"

    # Set the 'latest' tag
    $DRY_RUN_ECHO skopeo copy --quiet "docker://$push_repo:$tag" "docker://$push_repo:latest" "${skopeo_cp_args[@]}"

    cd "${ROOT_DIR}"
  fi

done
