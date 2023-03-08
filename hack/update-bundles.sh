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

# Pushes policy bundles to quay.io, but only if anything changed since
# the last bundle was pushed.
#
set -o errexit
set -o pipefail
set -o nounset

REPO_ORG=hacbs-contract
QUAY_API_URL=https://quay.io/api/v1/repository/$REPO_ORG
ROOT_DIR=$( git rev-parse --show-toplevel )
BUNDLES="release pipeline data"

# For example:
#   ENSURE_UNIQUE=1 DRY_RUN=1 hack/update-bundles.sh
#
ENSURE_UNIQUE=${ENSURE_UNIQUE:-""}
DRY_RUN=${DRY_RUN:-""}
DRY_RUN_ECHO=""
[ "$DRY_RUN" == "1" ] && DRY_RUN_ECHO="echo #"

# The data bundle is a little different to the other two.
# Encapsulate the differences these little functions.
#
function bundle_src_dirs() {
  [ $1 == "data" ] && echo "data" || echo "policy/lib policy/$1"
}

function bundle_subdir() {
  [ $1 == "data" ] && echo "data" || echo "policy"
}

function exclusions() {
  [ $1 == "data" ] && echo "config.json" || echo "artifacthub-pkg.yml"
}

function repo_name() {
  [ $1 == "data" ] && echo "ec-policy-data" || echo "ec-$1-policy"
}

function conftest_push() {
  if [ $1 == "data" ]; then
    $DRY_RUN_ECHO conftest push --policy '' --data data $2
  else
    $DRY_RUN_ECHO conftest push --policy policy $2
  fi
}

function ensure_unique_file() {
  if [ $1 == "data" ]; then
    # It really is data/data here...
    echo "data/data/rule_data.yml"
  else
    echo "policy/lib/rule_data.rego"
  fi
}

tmp_oci_dirs=()
function cleanup() {
  rm -rf "${tmp_oci_dirs[@]}"
}
trap cleanup EXIT

for b in $BUNDLES; do
  # Find the git sha where the source files were last updated
  src_dirs=$(bundle_src_dirs $b)
  last_update_sha=$(git log -n 1 --pretty=format:%h -- $src_dirs)

  # Check if the bundle for that git sha exists already
  repo=$(repo_name $b)
  tag=git-$last_update_sha
  found_count=$(curl -s $QUAY_API_URL/$repo/tag/?specificTag=$tag | jq '.tags | length')
  push_repo=quay.io/$REPO_ORG/$repo

  if [ "$found_count" == "1" -a "$ENSURE_UNIQUE" == "1" ]; then
    # No push needed
    echo "Policy bundle $push_repo:$tag exists already, no push needed"

  else
    # Push needed
    echo "Pushing policy bundle $push_repo:$tag now"

    # Prepare a temp dir with the bundle's content
    tmp_dir=$(mktemp -d -t ec-bundle-$b.XXXXXXXXXX)
    tmp_oci_dirs+=("${tmp_dir}")
    content_dir=$tmp_dir/$(bundle_subdir $b)
    mkdir $content_dir
    for d in $src_dirs; do
      cp -r $d $content_dir
    done

    # Remove some files
    exclude_files=$(exclusions $b)
    for f in $exclude_files; do
      find $content_dir -name $f -delete
    done

    if [ "$ENSURE_UNIQUE" == "1" ]; then
      # Ensure the bundle has a brand new unique digest
      unique_timestamp=$(date +%s%N)
      timestamp_file=$(ensure_unique_file $b)
      echo Adding timestamp ${unique_timestamp} to ${timestamp_file}
      echo -e "\n# ${unique_timestamp}" >> $tmp_dir/$timestamp_file
    fi

    # Show the content
    cd $tmp_dir || exit 1
    find . -type f

    # Now push
    conftest_push $b "$push_repo:$tag"

    # Add OCI annotations to the bundle image
    tmp_oci_dir="$(mktemp -d --tmpdir)"
    tmp_oci_dirs+=("${tmp_oci_dir}")
    skopeo copy docker://"$push_repo:$tag" dir:"${tmp_oci_dir}"
    manifest="$(jq -c '. += { "annotations": { "org.opencontainers.image.revision": "'"${last_update_sha}"'" } }' "${tmp_oci_dir}/manifest.json")"
    echo "${manifest}" > "${tmp_oci_dir}/manifest.json"
    skopeo copy dir:"${tmp_oci_dir}" docker://"$push_repo:$tag"

    # Set the 'latest' tag
    $DRY_RUN_ECHO skopeo copy --quiet docker://$push_repo:$tag docker://$push_repo:latest

    cd $ROOT_DIR
  fi

done
