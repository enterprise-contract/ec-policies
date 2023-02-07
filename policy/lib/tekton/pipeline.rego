package lib.tkn

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib.refs
import data.lib.time

pipeline_label := "pipelines.openshift.io/runtime"

latest_required_pipeline_tasks(pipeline) := pipeline_tasks if {
    pipeline_data := required_task_list_exists(pipeline)
	pipeline_tasks := time.newest(pipeline_data).tasks
}

current_required_pipeline_tasks(pipeline) := pipeline_tasks if {
    pipeline_data := required_task_list_exists(pipeline)
    pipeline_tasks := time.most_current(pipeline_data).tasks
}

required_task_list_exists(pipeline) := pipeline_data {
    pipeline_selector := pipeline_label_selector(pipeline, pipeline_label)
    pipeline_data := data["pipeline-required-tasks"][pipeline_selector]
}

pipeline_label_selector(pipeline, selector) := value if {
	some label, value in pipeline.metadata.labels
	label == selector
}

pipeline_name := name if {
    name := input.metadata.name
}
