#
# METADATA
# title: Trusted Task checks
# description: >-
#   This package is used to verify all the Tekton Tasks involved in building the image are trusted.
#   Trust is established by comparing the Task references found in the SLSA Provenance with the
#   pre-defined list of trusted Tasks. The list is customized via the `trusted_tasks` rule data key.
#
package policy.release.trusted_task

import rego.v1

import data.lib
import data.lib.refs
import data.lib.tkn

_supported_ta_uris_reg := {"oci:.*@sha256:[0-9a-f]{64}"}

# METADATA
# title: Pinned
# description: >-
#   Check if all Tekton Tasks use a Task definition by a pinned reference. When using the git
#   resolver, a commit ID is expected for the revision parameter. When using the bundles resolver,
#   the bundle parameter is expected to include an image reference with a digest.
# custom:
#   short_name: pinned
#   failure_msg: Pipeline task %q uses an unpinned task reference, %s
#   solution: >-
#     Update the Pipeline definition so that all Task references have a pinned value as mentioned
#     in the description.
#   collections:
#   - redhat
#   effective_on: 2024-05-07T00:00:00Z
#
warn contains result if {
	some task in tkn.unpinned_task_references(lib.tasks_from_pipelinerun)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[tkn.pipeline_task_name(task), _task_info(task)],
		tkn.task_name(task),
	)
}

# METADATA
# title: Current
# description: >-
#   Check if all Tekton Tasks use the latest known Task reference.
# custom:
#   short_name: current
#   failure_msg: Pipeline task %q uses an out of date task reference, %s
#   solution: >-
#     Update the Task reference to a newer version.
#   collections:
#   - redhat
#   effective_on: 2024-05-07T00:00:00Z
#
warn contains result if {
	some task in tkn.out_of_date_task_refs(lib.tasks_from_pipelinerun)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[tkn.pipeline_task_name(task), _task_info(task)],
		tkn.task_name(task),
	)
}

# METADATA
# title: Trusted
# description: >-
#   Check the trust of the Tekton Tasks used in the build Pipeline. There are two modes in which
#   trust is verified. The first mode is used if Trusted Artifacts are enabled. In this case, a
#   chain of trust is established for all the Tasks involved in creating an artifact. If the chain
#   contains an untrusted Task, then a violation is emitted. The second mode is used as a fallback
#   when Trusted Artifacts are not enabled. In this case, **all** Tasks in the build Pipeline must
#   be trusted.
# custom:
#   short_name: trusted
#   failure_msg: "%s"
#   solution: >-
#     If using Trusted Artifacts, be sure every Task in the build Pipeline responsible for producing
#     a Trusted Artifact is trusted. Otherwise, ensure **all** Tasks in the build Pipeline are
#     trusted. Note that trust is eventually revoked from Tasks when newer versions are made
#     available.
#   collections:
#   - redhat
#   effective_on: 2024-05-07T00:00:00Z
#
deny contains result if {
	some err in _trust_errors
	result := lib.result_helper_with_term(rego.metadata.chain(), [err.msg], err.term)
}

_trust_errors contains error if {
	_uses_trusted_artifacts
	some attestation in lib.pipelinerun_attestations
	build_tasks := tkn.build_tasks(attestation)
	some build_task in build_tasks

	dependency_chain := graph.reachable(_artifact_chain[attestation], {tkn.pipeline_task_name(build_task)})
	chain := [task |
		some link in dependency_chain
		some task in tkn.tasks(attestation)

		link == tkn.pipeline_task_name(task)
	]

	some untrusted_task in tkn.untrusted_task_refs(chain)
	untrusted_task_name := tkn.pipeline_task_name(untrusted_task)

	error := {
		"msg": sprintf(
			"Code tampering detected, untrusted task %q was included in build chain comprised of: %s",
			[untrusted_task_name, concat(", ", dependency_chain)],
		),
		"term": untrusted_task_name,
	}
}

_trust_errors contains error if {
	not _uses_trusted_artifacts
	some task in tkn.untrusted_task_refs(lib.tasks_from_pipelinerun)
	error := {
		"msg": sprintf(
			"Pipeline task %q uses an untrusted task reference, %s",
			[tkn.pipeline_task_name(task), _task_info(task)],
		),
		"term": tkn.task_name(task),
	}
}

# METADATA
# title: Trusted Artifact produced in pipeline
# description: >-
#   All input trusted artifacts must be produced on the pipeline. If they are not
#   the artifact could have been injected by a rouge task.
# custom:
#   short_name: valid_trusted_artifact_inputs
#   failure_msg: >-
#     Code tampering detected, input %q for task %q was not produced by the
#     pipeline as attested.
#   solution: >-
#     Audit the pipeline to make sure all inputs are produced by the pipeline.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some task in tkn.tasks(attestation)
	some invalid_input in _trusted_artifact_inputs(task)
	count({o |
		some t in tkn.tasks(attestation)
		some o in _trusted_artifact_outputs(t)

		o == invalid_input
	}) == 0

	task_name = tkn.pipeline_task_name(task)

	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[invalid_input, task_name],
		invalid_input,
	)
}

_artifact_chain[attestation][name] := dependencies if {
	some attestation in lib.pipelinerun_attestations
	some task in tkn.tasks(attestation)
	name := tkn.pipeline_task_name(task)
	dependencies := {dep |
		some t in tkn.tasks(attestation)
		some i in _trusted_artifact_inputs(task)
		some o in _trusted_artifact_outputs(t)
		i == o
		dep := tkn.pipeline_task_name(t)
	}
}

_trusted_artifact_inputs(task) := {value |
	some key, value in tkn.task_params(task)
	endswith(key, "_ARTIFACT")
	count({b |
		some supported_uri_ta_reg in _supported_ta_uris_reg
		b = regex.match(supported_uri_ta_reg, value)
		b
	}) == 1
}

_trusted_artifact_outputs(task) := {value |
	some result in tkn.task_results(task)
	result.type == "string"
	endswith(result.name, "_ARTIFACT")
	count({b |
		some supported_uri_ta_reg in _supported_ta_uris_reg
		b = regex.match(supported_uri_ta_reg, result.value)
		b
	}) == 1

	value := result.value
}

_uses_trusted_artifacts if {
	ta_tasks := {task |
		some task in lib.tasks_from_pipelinerun
		total := count(_trusted_artifact_inputs(task)) + count(_trusted_artifact_outputs(task))
		total > 0
	}
	count(ta_tasks) > 0
}

# METADATA
# title: Data
# description: >-
#   Confirm the `trusted_tasks` rule data was provided, since it's required by the policy rules in
#   this package.
# custom:
#   short_name: data
#   failure_msg: Missing required trusted_tasks data
#   solution: >-
#     Create a, or use an existing, trusted tasks list as a data source.
#   collections:
#   - redhat
#   effective_on: 2024-05-07T00:00:00Z
#
deny contains result if {
	tkn.missing_trusted_tasks_data
	result := lib.result_helper(rego.metadata.chain(), [])
}

_task_info(task) := info if {
	ref := refs.task_ref(task)
	info := sprintf("%s@%s", [object.get(ref, "key", ""), object.get(ref, "pinned_ref", "")])
}
