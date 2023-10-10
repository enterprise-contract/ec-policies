package lib.tkn

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.time

pipeline_label := "pipelines.openshift.io/runtime"

task_label := "build.appstudio.redhat.com/build_type"

latest_required_pipeline_tasks(pipeline) := pipeline_tasks if {
	pipeline_data := required_task_list(pipeline)
	pipeline_tasks := time.newest(pipeline_data).tasks
}

current_required_pipeline_tasks(pipeline) := pipeline_tasks if {
	pipeline_data := required_task_list(pipeline)
	pipeline_tasks := time.most_current(pipeline_data).tasks
}

# get the label from the pipelineRun attestation and return the
# required task list FOR that pipeline
required_task_list(pipeline) := pipeline_data if {
	pipeline_selector := pipeline_label_selector(pipeline)
	pipeline_data := data["pipeline-required-tasks"][pipeline_selector]
}

# pipeline_label_selector is a specialized function that returns the name of the
# required tasks list that should be used.
pipeline_label_selector(pipeline) := value if {
	# Labels of the build Task from the SLSA Provenance v1.0 of a PipelineRun
	value := build_task(pipeline).metadata.labels[task_label]
} else := value if {
	# Labels of the build Task from the SLSA Provenance v0.2 of a PipelineRun
	value := build_task(pipeline).invocation.environment.labels[task_label]
} else := value if {
	# PipelineRun labels found in the SLSA Provenance v1.0
	value := lib.statement(pipeline).predicate.buildDefinition.internalParameters.labels[pipeline_label]
} else := value if {
	# PipelineRun labels found in the SLSA Provenance v0.2
	value := lib.statement(pipeline).predicate.invocation.environment.labels[pipeline_label]
} else := value if {
	# Labels from a Tekton Pipeline definition
	value := pipeline.metadata.labels[pipeline_label]
}

pipeline_name := input.metadata.name
