#
# METADATA
# title: Trusted Task checks
# description: >-
#   This package is used to verify all the Tekton Tasks involved in building the image are trusted.
#   Trust is established by comparing the Task references found in the SLSA Provenance with a
#   pre-defined list of trusted Tasks, which is expected to be provided as a data source that
#   creates the `data.trusted_tasks` in the format demonstrated at
#   https://github.com/enterprise-contract/ec-policies/blob/main/example/data/trusted_tekton_tasks.yml.
#   The list can be extended or customized using the `trusted_tasks` rule data key which is merged
#   into the `trusted_tasks` data.
#
package policy.release.trusted_task

import rego.v1

import data.lib
import data.lib.refs
import data.lib.tkn

_supported_ta_uris_reg := {"oci:.*@sha256:[0-9a-f]{64}"}

_digest_patterns := {`sha256:[0-9a-f]{64}`}

# METADATA
# title: Task references are pinned
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
# title: Tasks using the latest versions
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
# title: Tasks are trusted
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

# METADATA
# title: Task tracking data was provided
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

# METADATA
# title: Trusted parameters
# description: >-
#   Confirm certain parameters provided to each builder Task have come from trusted Tasks.
# custom:
#   short_name: trusted_parameters
#   failure_msg: 'The %q parameter of the %q PipelineTask includes an untrusted digest: %s'
#   solution: >-
#     Update your build Pipeline to ensure all the parameters provided to your builder Tasks come
#     from trusted Tasks.
#   collections:
#   - redhat
#   effective_on: 2021-07-04T00:00:00Z
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some build_task in tkn.build_tasks(attestation)

	some param_name, param_value in tkn.task_params(build_task)

	# Trusted Artifacts are handled differently. Here we are concerned with all other parameters.
	not endswith(param_name, "_ARTIFACT")
	params_digests := _digests_from_values(lib.param_values(param_value))

	some untrusted_digest in (params_digests - _trusted_build_digests)
	result := lib.result_helper(
		rego.metadata.chain(),
		[param_name, tkn.pipeline_task_name(build_task), untrusted_digest],
	)
}

_trust_errors contains error if {
	_uses_trusted_artifacts
	some attestation in lib.pipelinerun_attestations
	build_tasks := tkn.build_tasks(attestation)
	test_tasks := tkn.tasks_output_result(attestation)
	some build_or_test_task in array.concat(build_tasks, test_tasks)

	dependency_chain := graph.reachable(_artifact_chain[attestation], {tkn.pipeline_task_name(build_or_test_task)})

	chain := [task |
		some link in dependency_chain
		some task in tkn.tasks(attestation)

		link == tkn.pipeline_task_name(task)
	]

	some untrusted_task in tkn.untrusted_task_refs(chain)
	untrusted_pipeline_task_name := tkn.pipeline_task_name(untrusted_task)
	untrusted_task_name := tkn.task_name(untrusted_task)

	error := {
		"msg": sprintf(
			"Code tampering detected, untrusted PipelineTask %q (Task %q) was included in build chain comprised of: %s",
			[untrusted_pipeline_task_name, untrusted_task_name, concat(", ", dependency_chain)],
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

_task_info(task) := info if {
	ref := refs.task_ref(task)
	info := sprintf("%s@%s", [object.get(ref, "key", ""), object.get(ref, "pinned_ref", "")])
}

# _trusted_build_digest is a set containing any digest found in one of the trusted builder Tasks.
_trusted_build_digests contains digest if {
	some attestation in lib.pipelinerun_attestations
	some build_task in tkn.build_tasks(attestation)
	tkn.is_trusted_task(build_task)
	some result in tkn.task_results(build_task)
	some digest in _digests_from_values(lib.result_values(result))
}

_digests_from_values(values) := {digest |
	some value in values
	some pattern in _digest_patterns
	some digest in regex.find_n(pattern, value, -1)
}
