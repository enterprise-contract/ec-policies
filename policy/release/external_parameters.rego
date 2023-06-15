#
# METADATA
# title: external parameters
# description: >-
#   Verify the attribute .predicate.buildDefinition.externalParameters of a
#   SLSA Provenance v1.0 matches the expectation.
#
package policy.release.external_parameters

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: pipeline run params
# description: >-
#   Verify the PipelineRun was initialized with a set of expected parameters.
#   By default it asserts git-repo, git-revision, and otuput-image are provided
#   with non-empty values. This is configurable by the rule data key
#   "pipeline_run_params". Any additional parameters are NOT allowed.
# custom:
#   short_name: pipeline_run_params
#   failure_msg: PipelineRun params, %v, do not match expectation, %v.
#
deny contains result if {
	some provenance in lib.pipelinerun_slsa_provenance_v1
	param_names := {name |
		some p in provenance.predicate.buildDefinition.externalParameters.runSpec.params
		p.value != ""
		name := p.name
	}
	expected_names := {n | some n in lib.rule_data("pipeline_run_params")}
	expected_names != param_names
	result := lib.result_helper(rego.metadata.chain(), [param_names, expected_names])
}

# METADATA
# title: restrict shared volumes
# description: >-
#   Verify the PipelineRun did not use any pre-existing PersistentVolumeClaim
#   workspaces.
# custom:
#   short_name: restrict_shared_volumes
#   failure_msg: PipelineRun uses shared volumes, %v.
#
deny contains result if {
	some provenance in lib.pipelinerun_slsa_provenance_v1
	shared_workspaces := {w |
		some w in provenance.predicate.buildDefinition.externalParameters.runSpec.workspaces
		w.persistentVolumeClaim
	}
	count(shared_workspaces) > 0
	result := lib.result_helper(rego.metadata.chain(), [shared_workspaces])
}
