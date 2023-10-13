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

# Given an active connection to a kubernetes cluster configured with Tekton Pipelines and Tekton
# Chains, execute a set of PipelineRuns to demonstrate the different ways Chains generates
# SLSA Provenance.
#
# This script has been tested against a kind cluster, but it should technically work against any
# kubernetes cluster. To setup a kind cluster:
#
#   kind create cluster
#   kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
#   kubectl apply --filename https://storage.googleapis.com/tekton-releases/chains/latest/release.yaml
#   cosign generate-key-pair k8s://tekton-chains/signing-secrets
#
# The ServiceAccount responsible for running Tasks/Pipelines should have the proper secrets linked
# so Chains can push contents to the OCI repository. When using a kind cluster, the ServiceAccount
# used is called "default". Below is one way to just upload your current credentials to the cluster
# and link to the ServiceAccount:
#
#   kubectl -n default create secret docker-registry $USER \
#     --from-file=.dockerconfigjson=$HOME/.docker/config.json
#   kubectl patch serviceaccount default -p '{"imagePullSecrets": [{"name": "'$USER'"}]}'
#   kubectl patch serviceaccount default -p '{"secrets": [{"name": "'$USER'"}]}'
#
#
# Usage: ./integration/record.sh
#   The environment variable IMAGE_URL must point to an OCI repository, e.g. quay.io/lucarval/spam
#   You must have write access to the repository.
#
set -o errexit
set -o pipefail
set -o nounset

function log() {
  echo "$@" 1>&2;
}

function rand_string() {
    local size
    local s

    size="${1-5}"
    set +o pipefail
    s="$(tr -dc a-z </dev/urandom | head -c ${size})"
    set -o pipefail
    echo -n "${s}"
}

# Update the Chains configuration and restart the controller.
# https://github.com/tektoncd/chains/blob/main/docs/config.md#chains-configuration-1
function configure_chains() {
    local data
    data="${1}"
    # Make sure Chains is setup how we want it.
    oc patch -n tekton-chains configmap/chains-config --type merge --patch \
        "{\"data\": ${data}}"

    # Bounce the Chains controller to make sure the changes take effect right away.
    oc delete pod -n tekton-chains -l app=tekton-chains-controller

    log "✅ Configured Chains:"
    oc -n tekton-chains get configmap chains-config -o yaml | yq '.data'
}

# Build a little image with a unique digest every time
function build_image() {
    local container
    local image
    local digestfile
    local digest

    container="$(buildah from scratch)"
    image="$(buildah commit "${container}")"
    digestfile="$(mktemp)"
    buildah push --digestfile "${digestfile}" "${image}" "docker://${IMAGE_URL}:latest"
    digest="$(cat "${digestfile}")"
    log "✅ Created image ${IMAGE_URL}@${digest}"
    echo -n "${digest}"
}

function render_pipeline() {
  local bundle_ref
  local git_remote
  local git_url
  local git_rev
  local pipeline

  bundle_ref="$(
      tkn bundle push "${IMAGE_URL}:buildah-task" -f integration/task/mock-build.yaml |
      grep 'Pushed' | rev | cut -d' ' -f 1 | rev)"

  log "Pushed Tekton bundle image ${bundle_ref}"

  # This is a bit hacky, but it is needed in order to use the git resolver.
  git_remote="$(git for-each-ref --format='%(upstream:short)' "$(git symbolic-ref -q HEAD)" | cut -d/ -f1)"
  git_url="$(git remote get-url --push ${git_remote} | sed 's_git@github.com:_https://github.com/_')"
  git_rev="$(git rev-parse HEAD)"

  # Make these available as environment variables to the yq command.
  export bundle_ref
  export git_url
  export git_rev

  pipeline="$(< integration/pipeline/simple-build.yaml yq '
    (.spec.tasks[] | select(.name == "build") | .taskRef.params[] | select(.name == "bundle")) .value |= strenv(bundle_ref) |
    (.spec.tasks[] | select(.name == "git-clone") | .taskRef.params[] | select(.name == "url")) .value |= strenv(git_url) |
    (.spec.tasks[] | select(.name == "git-clone") | .taskRef.params[] | select(.name == "revision")) .value |= strenv(git_rev)
  ')"

  echo "${pipeline}"
}

function render_pipelinerun() {
  local name
  local image_digest
  local git_commit_id
  local git_committer_date
  local git_url

  name="$1"
  image_digest="$2"

  git_commit_id="$(rand_string | sha1sum | cut -d' ' -f1)"
  git_committer_date="$(date +%s)"
  git_url='gitspam.spam/spam/spam'

  echo "
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  name: ${name}
spec:
  params:
  - name: IMAGE_DIGEST
    value: ${image_digest}
  - name: IMAGE_URL
    value: ${IMAGE_URL}
  - name: TEST_OUTPUT
    value: missing
  - name: commit
    value: ${git_commit_id}
  - name: committer-date
    value: ${git_committer_date}
  - name: url
    value: ${git_url}
"
}

function wait_for_pipelinerun() {
  local pr_name
  local value

  pr_name="$1"

  log "Waiting for PipelineRun ${pr_name} to finish"
  tkn pipelinerun logs "${pr_name}"

  log "Waiting for Chains to process the PipelineRun ${pr_name} ..."
  while :
  do
      value="$(oc get pr "${pr_name}" -o yaml | yq '.metadata.annotations."chains.tekton.dev/signed"')"
      if [[ "$value" == "true" ]]; then
          break
      fi
      if [[ "$value" == "false" ]]; then
          log "❌ Uh oh! Chains was not able to sign PipelineRun ${pr_name}"
          exit 1
      fi
      sleep 1
  done

  log "✅ PipelineRun ${pr_name} completed and processed by Chains"
}

function download_attestation() {
  local image_digest
  image_digest="$1"

  cosign download attestation "${IMAGE_URL}@${image_digest}" \
    | jq '.payload | @base64d | fromjson'
}

function setup_scenario() {
  local name
  local output_dir

  name="$1"
  log "🏃 Executing scenario ${name}"

  output_dir="integration/recordings/${name}"
  mkdir -p "${output_dir}"

  echo -n "${output_dir}"
}

function run_in_cluster_pipeline() {
  local output_dir
  local image_digest
  local pr_name

  output_dir="$1"

  render_pipeline | tee "${output_dir}/pipeline.yaml" | oc apply -f -

  image_digest="$(build_image)"

  pr_name="simple-build-run-$(rand_string)"

  render_pipelinerun "${pr_name}" "${image_digest}" | \
    yq '.spec.pipelineRef |= {"name": "simple-build"}' | \
    oc create -f -

  wait_for_pipelinerun "${pr_name}"

  oc get pipelinerun "${pr_name}" -o yaml > "${output_dir}/pipelinerun.yaml"

  download_attestation "${image_digest}" > "${output_dir}/attestation.json"
}

function run_inline_pipeline() {
  local output_dir
  local pipeline_spec
  local image_digest
  local pr_name

  output_dir="$1"

  pipeline_spec="$(render_pipeline | yq '.spec' -o json | jq -c )"

  image_digest="$(build_image)"

  pr_name="simple-build-run-$(rand_string)"

  render_pipelinerun "${pr_name}" "${image_digest}" \
    | yq ".spec.pipelineSpec |= ${pipeline_spec}" \
    | oc create -f -

  wait_for_pipelinerun "${pr_name}"

  oc get pipelinerun "${pr_name}" -o yaml > "${output_dir}/pipelinerun.yaml"

  download_attestation "${image_digest}" > "${output_dir}/attestation.json"
}

#########
# Setup #
#########
log "Using repository ${IMAGE_URL}"
cd "$(git root)"
# Just a quick check to make sure there is an active connection to the cluster.
oc get serviceaccount > /dev/null

##############
# SCENARIO 1 #
##############
configure_chains '{
    "artifacts.oci.storage": "oci",
    "artifacts.pipelinerun.format": "slsa/v1",
    "artifacts.pipelinerun.storage": "oci",
    "artifacts.taskrun.storage": ""
}'
run_in_cluster_pipeline "$(setup_scenario "01-SLSA-v0-2-Pipeline-in-cluster")"

##############
# SCENARIO 2 #
##############
configure_chains '{
    "artifacts.oci.storage": "oci",
    "artifacts.pipelinerun.format": "slsa/v1",
    "artifacts.pipelinerun.storage": "oci",
    "artifacts.taskrun.storage": ""
}'
run_inline_pipeline "$(setup_scenario "02-SLSA-v0-2-Pipeline-inline")"

##############
# SCENARIO 3 #
##############
configure_chains '{
    "builddefinition.buildtype": "https://tekton.dev/chains/v2/slsa",
    "artifacts.oci.storage": "oci",
    "artifacts.pipelinerun.format": "slsa/v2alpha2",
    "artifacts.pipelinerun.storage": "oci",
    "artifacts.taskrun.storage": ""
}'
run_in_cluster_pipeline "$(setup_scenario "03-SLSA-v1-0-plain-build-type-Pipeline-in-cluster")"

##############
# SCENARIO 4 #
##############
configure_chains '{
    "builddefinition.buildtype": "https://tekton.dev/chains/v2/slsa",
    "artifacts.oci.storage": "oci",
    "artifacts.pipelinerun.format": "slsa/v2alpha2",
    "artifacts.pipelinerun.storage": "oci",
    "artifacts.taskrun.storage": ""
}'
run_inline_pipeline "$(setup_scenario "04-SLSA-v1-0-plain-build-type-Pipeline-inline")"

##############
# SCENARIO 5 #
##############
configure_chains '{
    "builddefinition.buildtype": "https://tekton.dev/chains/v2/slsa-tekton",
    "artifacts.oci.storage": "oci",
    "artifacts.pipelinerun.format": "slsa/v2alpha2",
    "artifacts.pipelinerun.storage": "oci",
    "artifacts.taskrun.storage": ""
}'
run_in_cluster_pipeline "$(setup_scenario "05-SLSA-v1-0-tekton-build-type-Pipeline-in-cluster")"

##############
# SCENARIO 6 #
##############
configure_chains '{
    "builddefinition.buildtype": "https://tekton.dev/chains/v2/slsa-tekton",
    "artifacts.oci.storage": "oci",
    "artifacts.pipelinerun.format": "slsa/v2alpha2",
    "artifacts.pipelinerun.storage": "oci",
    "artifacts.taskrun.storage": ""
}'
run_inline_pipeline "$(setup_scenario "06-SLSA-v1-0-tekton-build-type-Pipeline-inline")"
