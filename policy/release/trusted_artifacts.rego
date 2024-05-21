#
# METADATA
# title: Trusted Artifacts
# description: >-
#   Trusted Artifacts ensure that only trusted Tasks were used from the
#   origin of the source code to the produced image. The chain is
#   constructed by linking specific parameters with results -- ones that
#   are named `*_ARTIFACT` and have values in the form of
#   `sha-256:<digest>`. If a chain of same-valued digests can be formed
#   from the first Task result to the last Task by correlating the
#   digest values of those and any tasks inbetween.
#
#   Trusted Tasks should be producing and using only the files with the
#   same digest. Given this assurance any code injection should be
#   detected by observing a modified digest.
#
#   This allows addition of Tasks on the Pipeline that do not need to be
#   trusted, i.e. custom tasks.
#
package policy.release.trusted_artifacts

import rego.v1

import data.lib
import data.lib.tkn

_supported_uris_reg := {"oci:.*@sha256:[0-9a-f]{64}"}

# METADATA
# title: Valid Trusted Artifact chain
# description: >-
#   The chain of Trusted Artifacts from the origin of the first artifact to
#   the built artifact flows through trusted Tasks.
# custom:
#   short_name: valid_trusted_artifact_chain
#   failure_msg: >-
#     Code tampering detected, untrusted task %q was included in build
#     chain comprised of: %s
#   solution: >-
#     Audit the pipeline to make sure no untrusted Tasks were added to the
#     artifact-producing chain of Tasks.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
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

	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[untrusted_task_name, concat(", ", dependency_chain)],
		untrusted_task_name,
	)
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
	some invalid_input in _inputs(task)
	count({o |
		some t in tkn.tasks(attestation)
		some o in _outputs(t)

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
		some i in _inputs(task)
		some o in _outputs(t)
		i == o
		dep := tkn.pipeline_task_name(t)
	}
}

_inputs(task) := {value |
	some key, value in tkn.task_params(task)
	endswith(key, "_ARTIFACT")
	count({b |
		some supported_uri_reg in _supported_uris_reg
		b = regex.match(supported_uri_reg, value)
		b
	}) == 1
}

_outputs(task) := {value |
	some result in tkn.task_results(task)
	result.type == "string"
	endswith(result.name, "_ARTIFACT")
	count({b |
		some supported_uri_reg in _supported_uris_reg
		b = regex.match(supported_uri_reg, result.value)
		b
	}) == 1

	value := result.value
}
