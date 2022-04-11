package test_data

# Generated automatically with `make data-to-rego`
data := {
	"cluster": {
		"ConfigMap": {"chains-config": {
			"apiVersion": "v1",
			"data": {
				"artifacts.oci.storage": "oci",
				"artifacts.taskrun.format": "in-toto",
				"artifacts.taskrun.storage": "oci",
				"transparency.enabled": "true",
			},
			"kind": "ConfigMap",
			"metadata": {
				"annotations": {
					"argocd.argoproj.io/sync-options": "SkipDryRunOnMissingResource=true",
					"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"data\":{\"artifacts.oci.storage\":\"oci\",\"artifacts.taskrun.format\":\"in-toto\",\"artifacts.taskrun.storage\":\"oci\",\"transparency.enabled\":\"true\"},\"kind\":\"ConfigMap\",\"metadata\":{\"annotations\":{\"argocd.argoproj.io/sync-options\":\"SkipDryRunOnMissingResource=true\"},\"labels\":{\"app.kubernetes.io/component\":\"chains\",\"app.kubernetes.io/instance\":\"build\",\"app.kubernetes.io/part-of\":\"tekton-pipelines\",\"pipeline.tekton.dev/release\":\"devel\",\"version\":\"v0.8.0\"},\"name\":\"chains-config\",\"namespace\":\"tekton-chains\"}}\n",
				},
				"creationTimestamp": "2022-04-11T18:53:36Z",
				"labels": {
					"app.kubernetes.io/component": "chains",
					"app.kubernetes.io/instance": "build",
					"app.kubernetes.io/part-of": "tekton-pipelines",
					"pipeline.tekton.dev/release": "devel",
					"version": "v0.8.0",
				},
				"name": "chains-config",
				"namespace": "tekton-chains",
				"resourceVersion": "39261",
				"uid": "cd72f771-fb6d-48d9-9e44-c955f0cc62ea",
			},
		}},
		"PipelineRun": {"nodejs-builder-2022-04-12-002742": {
			"apiVersion": "tekton.dev/v1beta1",
			"kind": "PipelineRun",
			"metadata": {
				"annotations": {
					"build.appstudio.openshift.io/build": "true",
					"build.appstudio.openshift.io/deploy": "",
					"build.appstudio.openshift.io/image": "image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d",
					"build.appstudio.openshift.io/repo": "https://github.com/simonbaird/single-nodejs-app",
					"build.appstudio.openshift.io/type": "build",
					"build.appstudio.openshift.io/version": "0.1",
					"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"tekton.dev/v1beta1\",\"kind\":\"PipelineRun\",\"metadata\":{\"annotations\":{\"build.appstudio.openshift.io/build\":\"true\",\"build.appstudio.openshift.io/deploy\":\"\",\"build.appstudio.openshift.io/type\":\"build\",\"build.appstudio.openshift.io/version\":\"0.1\"},\"name\":\"nodejs-builder-2022-04-12-002742\",\"namespace\":\"tekton-chains\"},\"spec\":{\"params\":[{\"name\":\"git-url\",\"value\":\"https://github.com/simonbaird/single-nodejs-app\"},{\"name\":\"output-image\",\"value\":\"image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d\"},{\"name\":\"dockerfile\",\"value\":\"Dockerfile\"},{\"name\":\"path-context\",\"value\":\".\"}],\"pipelineRef\":{\"bundle\":\"quay.io/sbaird/build-templates-bundle:50730521ebb891d6c7495a536ba6b473bf5025a9\",\"name\":\"nodejs-builder\"},\"workspaces\":[{\"name\":\"workspace\",\"persistentVolumeClaim\":{\"claimName\":\"app-studio-default-workspace\"},\"subPath\":\"pv-nodejs-builder-2022-04-12-002742\"}]}}\n",
					"results.tekton.dev/record": "tekton-chains/results/f84fad5c-22e5-4f11-99fb-6aed21acdfc9/records/f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
					"results.tekton.dev/result": "tekton-chains/results/f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
				},
				"creationTimestamp": "2022-04-12T04:27:44Z",
				"generation": 1,
				"labels": {
					"pipelines.openshift.io/runtime": "nodejs",
					"pipelines.openshift.io/strategy": "s2i",
					"pipelines.openshift.io/used-by": "build-cloud",
					"tekton.dev/pipeline": "nodejs-builder",
				},
				"name": "nodejs-builder-2022-04-12-002742",
				"namespace": "tekton-chains",
				"resourceVersion": "610120",
				"uid": "f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
			},
			"spec": {
				"params": [
					{
						"name": "git-url",
						"value": "https://github.com/simonbaird/single-nodejs-app",
					},
					{
						"name": "output-image",
						"value": "image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d",
					},
					{
						"name": "dockerfile",
						"value": "Dockerfile",
					},
					{
						"name": "path-context",
						"value": ".",
					},
				],
				"pipelineRef": {
					"bundle": "quay.io/sbaird/build-templates-bundle:50730521ebb891d6c7495a536ba6b473bf5025a9",
					"name": "nodejs-builder",
				},
				"serviceAccountName": "pipeline",
				"timeout": "1h0m0s",
				"workspaces": [{
					"name": "workspace",
					"persistentVolumeClaim": {"claimName": "app-studio-default-workspace"},
					"subPath": "pv-nodejs-builder-2022-04-12-002742",
				}],
			},
			"status": {
				"completionTime": "2022-04-12T04:29:16Z",
				"conditions": [{
					"lastTransitionTime": "2022-04-12T04:29:16Z",
					"message": "Tasks Completed: 5 (Failed: 0, Cancelled 0), Skipped: 0",
					"reason": "Succeeded",
					"status": "True",
					"type": "Succeeded",
				}],
				"pipelineSpec": {
					"finally": [{
						"name": "show-summary",
						"params": [
							{
								"name": "pipeline-run-name",
								"value": "$(context.pipelineRun.name)",
							},
							{
								"name": "git-url",
								"value": "$(params.git-url)",
							},
							{
								"name": "image-url",
								"value": "$(params.output-image)",
							},
						],
						"taskRef": {
							"bundle": "quay.io/sbaird/appstudio-tasks:50730521ebb891d6c7495a536ba6b473bf5025a9-2",
							"kind": "Task",
							"name": "summary",
						},
					}],
					"params": [
						{
							"description": "Source Repository URL",
							"name": "git-url",
							"type": "string",
						},
						{
							"default": "main",
							"description": "Revision of the Source Repository",
							"name": "revision",
							"type": "string",
						},
						{
							"description": "Fully Qualified Output Image",
							"name": "output-image",
							"type": "string",
						},
						{
							"default": ".",
							"description": "The path to your source code",
							"name": "path-context",
							"type": "string",
						},
						{
							"default": "Dockerfile",
							"description": "Path to the Dockerfile",
							"name": "dockerfile",
							"type": "string",
						},
						{
							"default": "false",
							"description": "Force rebuild image",
							"name": "rebuild",
							"type": "string",
						},
					],
					"tasks": [
						{
							"name": "appstudio-init",
							"params": [
								{
									"name": "image-url",
									"value": "$(params.output-image)",
								},
								{
									"name": "rebuild",
									"value": "$(params.rebuild)",
								},
							],
							"taskRef": {
								"bundle": "quay.io/sbaird/appstudio-tasks:50730521ebb891d6c7495a536ba6b473bf5025a9-1",
								"kind": "Task",
								"name": "init",
							},
						},
						{
							"name": "git-clone",
							"params": [
								{
									"name": "url",
									"value": "$(params.git-url)",
								},
								{
									"name": "revision",
									"value": "$(params.revision)",
								},
							],
							"runAfter": ["appstudio-init"],
							"taskRef": {
								"bundle": "quay.io/sbaird/appstudio-tasks:50730521ebb891d6c7495a536ba6b473bf5025a9-1",
								"kind": "Task",
								"name": "git-clone",
							},
							"when": [{
								"input": "$(tasks.appstudio-init.results.build)",
								"operator": "in",
								"values": ["true"],
							}],
							"workspaces": [
								{
									"name": "output",
									"workspace": "workspace",
								},
								{
									"name": "basic-auth",
									"workspace": "git-auth",
								},
							],
						},
						{
							"name": "appstudio-configure-build",
							"runAfter": ["git-clone"],
							"taskRef": {
								"bundle": "quay.io/sbaird/appstudio-tasks:50730521ebb891d6c7495a536ba6b473bf5025a9-1",
								"kind": "Task",
								"name": "configure-build",
							},
							"when": [{
								"input": "$(tasks.appstudio-init.results.build)",
								"operator": "in",
								"values": ["true"],
							}],
							"workspaces": [
								{
									"name": "source",
									"workspace": "workspace",
								},
								{
									"name": "registry-auth",
									"workspace": "registry-auth",
								},
							],
						},
						{
							"name": "build-container",
							"params": [
								{
									"name": "PATH_CONTEXT",
									"value": "$(params.path-context)",
								},
								{
									"name": "IMAGE",
									"value": "$(params.output-image)",
								},
								{
									"name": "PUSH_EXTRA_ARGS",
									"value": "$(tasks.appstudio-configure-build.results.buildah-auth-param)",
								},
							],
							"runAfter": ["appstudio-configure-build"],
							"taskRef": {
								"bundle": "quay.io/sbaird/appstudio-tasks:50730521ebb891d6c7495a536ba6b473bf5025a9-1",
								"kind": "Task",
								"name": "s2i-nodejs",
							},
							"when": [{
								"input": "$(tasks.appstudio-init.results.build)",
								"operator": "in",
								"values": ["true"],
							}],
							"workspaces": [{
								"name": "source",
								"workspace": "workspace",
							}],
						},
					],
					"workspaces": [
						{"name": "workspace"},
						{
							"name": "registry-auth",
							"optional": true,
						},
						{
							"name": "git-auth",
							"optional": true,
						},
					],
				},
				"startTime": "2022-04-12T04:27:44Z",
				"taskRuns": {
					"nodejs-builder-2022-04-12-002742-appstudio-configure-buil-6nx2k": {
						"pipelineTaskName": "appstudio-configure-build",
						"status": {
							"completionTime": "2022-04-12T04:28:12Z",
							"conditions": [{
								"lastTransitionTime": "2022-04-12T04:28:12Z",
								"message": "All Steps have completed executing",
								"reason": "Succeeded",
								"status": "True",
								"type": "Succeeded",
							}],
							"podName": "nodejs-builder-2022-04-12-002742-appstudio-configure-buil-r8bx2",
							"startTime": "2022-04-12T04:28:04Z",
							"steps": [{
								"container": "step-appstudio-configure-build",
								"imageID": "registry.access.redhat.com/ubi8-minimal@sha256:574f201d7ed185a9932c91cef5d397f5298dff9df08bc2ebb266c6d1e6284cd1",
								"name": "appstudio-configure-build",
								"terminated": {
									"containerID": "cri-o://82b9806211fb9230611efb8be59f995bde4bb77d898ce61767e8471539f2f38f",
									"exitCode": 0,
									"finishedAt": "2022-04-12T04:28:11Z",
									"message": "[{\"key\":\"buildah-auth-param\",\"value\":\" \",\"type\":1},{\"key\":\"registry-auth\",\"value\":\" \",\"type\":1}]",
									"reason": "Completed",
									"startedAt": "2022-04-12T04:28:11Z",
								},
							}],
							"taskResults": [
								{
									"name": "buildah-auth-param",
									"value": " ",
								},
								{
									"name": "registry-auth",
									"value": " ",
								},
							],
							"taskSpec": {
								"description": "App Studio Configure Build Secrets in Source. ",
								"results": [
									{
										"description": "docker config location",
										"name": "registry-auth",
									},
									{
										"description": "pass this to the build optional params to conifigure secrets",
										"name": "buildah-auth-param",
									},
								],
								"steps": [{
									"image": "registry.access.redhat.com/ubi8-minimal@sha256:574f201d7ed185a9932c91cef5d397f5298dff9df08bc2ebb266c6d1e6284cd1",
									"name": "appstudio-configure-build",
									"resources": {},
									"script": "#!/usr/bin/env bash    \necho \"App Studio Configure Build\" \n\nAUTH=/workspace/registry-auth/.dockerconfigjson\nDEST=/workspace/source/.dockerconfigjson\necho \"Looking for Registry Auth Config: $AUTH\"\nif [ -f \"$AUTH\" ]; then\n  echo \"$AUTH found\" \n  echo\n\n  cp $AUTH $DEST\n\n  echo -n $DEST > /tekton/results/registry-auth  \n  echo -n \"--authfile $DEST\"  >  /tekton/results/buildah-auth-param\n  echo \nelse  \n  echo \"No $AUTH found.\" \n  echo -n \" \" > /tekton/results/registry-auth  \n  echo -n \" \" > /tekton/results/buildah-auth-param\n  echo \nfi\n",
								}],
								"workspaces": [
									{"name": "source"},
									{
										"name": "registry-auth",
										"optional": true,
									},
								],
							},
						},
					},
					"nodejs-builder-2022-04-12-002742-appstudio-init-jr82h": {
						"pipelineTaskName": "appstudio-init",
						"status": {
							"completionTime": "2022-04-12T04:27:53Z",
							"conditions": [{
								"lastTransitionTime": "2022-04-12T04:27:53Z",
								"message": "All Steps have completed executing",
								"reason": "Succeeded",
								"status": "True",
								"type": "Succeeded",
							}],
							"podName": "nodejs-builder-2022-04-12-002742-appstudio-init-jr82h-pod-4bldr",
							"startTime": "2022-04-12T04:27:47Z",
							"steps": [{
								"container": "step-appstudio-init",
								"imageID": "registry.access.redhat.com/ubi8/skopeo@sha256:cc58da50c3842f5f2a4ba8781b60f6052919a5555a000cb4eb18a0bd0241b2b3",
								"name": "appstudio-init",
								"terminated": {
									"containerID": "cri-o://2b7c10f2a756060f12fc91ee181ba57ce9feaa3d5aabc5240a3d91bf6c39edf8",
									"exitCode": 0,
									"finishedAt": "2022-04-12T04:27:53Z",
									"message": "[{\"key\":\"build\",\"value\":\"true\",\"type\":1}]",
									"reason": "Completed",
									"startedAt": "2022-04-12T04:27:53Z",
								},
							}],
							"taskResults": [{
								"name": "build",
								"value": "true",
							}],
							"taskSpec": {
								"description": "App Studio Initialize Pipeline Task, include flags for rebuild and auth.",
								"params": [
									{
										"description": "Image URL for testing",
										"name": "image-url",
										"type": "string",
									},
									{
										"default": "false",
										"description": "Rebuild the image if exists",
										"name": "rebuild",
										"type": "string",
									},
								],
								"results": [{
									"description": "",
									"name": "build",
								}],
								"steps": [{
									"image": "registry.access.redhat.com/ubi8/skopeo@sha256:cc58da50c3842f5f2a4ba8781b60f6052919a5555a000cb4eb18a0bd0241b2b3",
									"name": "appstudio-init",
									"resources": {},
									"script": "#!/bin/bash    \necho \"App Studio Build Initialize: $(params.image-url)\" \necho \necho \"Determine if Image Already Exists\"\n# Build the image when image does not exists or rebuild is set to true\nif ! skopeo inspect --no-tags docker://$(params.image-url) &>/dev/null || [ \"$(params.rebuild)\" == \"true\" ]; then\n  echo -n \"true\" > $(results.build.path)\nelse\n  echo -n \"false\" > $(results.build.path)\nfi\n",
								}],
							},
						},
					},
					"nodejs-builder-2022-04-12-002742-build-container-mqf5p": {
						"pipelineTaskName": "build-container",
						"status": {
							"completionTime": "2022-04-12T04:29:09Z",
							"conditions": [{
								"lastTransitionTime": "2022-04-12T04:29:09Z",
								"message": "All Steps have completed executing",
								"reason": "Succeeded",
								"status": "True",
								"type": "Succeeded",
							}],
							"podName": "nodejs-builder-2022-04-12-002742-build-container-mqf5p-po-l9mk6",
							"startTime": "2022-04-12T04:28:12Z",
							"steps": [
								{
									"container": "step-generate",
									"imageID": "registry.redhat.io/ocp-tools-4-tech-preview/source-to-image-rhel8@sha256:cd4996fba88519ec21499da63d8c3e26cc4552429b949da76914d0666c27872d",
									"name": "generate",
									"terminated": {
										"containerID": "cri-o://355ef4c97822013c7c45ce805a31cf830dd399d2e56c6419148e4f59766e9422",
										"exitCode": 0,
										"finishedAt": "2022-04-12T04:28:18Z",
										"reason": "Completed",
										"startedAt": "2022-04-12T04:28:18Z",
									},
								},
								{
									"container": "step-build",
									"imageID": "registry.access.redhat.com/ubi8/buildah@sha256:31f84b19a0774be7cfad751be38fc97f5e86cefd26e0abaec8047ddc650b00bf",
									"name": "build",
									"terminated": {
										"containerID": "cri-o://cad49cadf9047bd7096ee3fa20ea28af7736672470e5eef13b7624acbb0b35db",
										"exitCode": 0,
										"finishedAt": "2022-04-12T04:29:07Z",
										"reason": "Completed",
										"startedAt": "2022-04-12T04:28:18Z",
									},
								},
								{
									"container": "step-push",
									"imageID": "registry.access.redhat.com/ubi8/buildah@sha256:31f84b19a0774be7cfad751be38fc97f5e86cefd26e0abaec8047ddc650b00bf",
									"name": "push",
									"terminated": {
										"containerID": "cri-o://1f4aa0f343765f198d81aadee4ebbe7feb5cbfb139bdce2552caef88244c2c29",
										"exitCode": 0,
										"finishedAt": "2022-04-12T04:29:08Z",
										"reason": "Completed",
										"startedAt": "2022-04-12T04:29:07Z",
									},
								},
								{
									"container": "step-digest-to-results",
									"imageID": "registry.access.redhat.com/ubi8/buildah@sha256:31f84b19a0774be7cfad751be38fc97f5e86cefd26e0abaec8047ddc650b00bf",
									"name": "digest-to-results",
									"terminated": {
										"containerID": "cri-o://5adc0caabdf0c5b11a02878a77b4524ccf70844c67878033156aa3d7ce19ee2f",
										"exitCode": 0,
										"finishedAt": "2022-04-12T04:29:09Z",
										"message": "[{\"key\":\"IMAGE_DIGEST\",\"value\":\"sha256:2d4dbf45c3f9dcfe19bb3297d06c799cd2f616e111593fbf70645c4929b45fde\",\"type\":1},{\"key\":\"IMAGE_URL\",\"value\":\"image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d\\n\",\"type\":1}]",
										"reason": "Completed",
										"startedAt": "2022-04-12T04:29:09Z",
									},
								},
							],
							"taskResults": [
								{
									"name": "IMAGE_DIGEST",
									"value": "sha256:2d4dbf45c3f9dcfe19bb3297d06c799cd2f616e111593fbf70645c4929b45fde",
								},
								{
									"name": "IMAGE_URL",
									"value": "image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d\n",
								},
							],
							"taskSpec": {
								"description": "s2i-nodejs task clones a Git repository and builds and pushes a container image using S2I and a nodejs builder image.",
								"params": [
									{
										"default": "14-ubi8",
										"description": "The tag of nodejs imagestream for nodejs version",
										"name": "VERSION",
										"type": "string",
									},
									{
										"default": ".",
										"description": "The location of the path to run s2i from.",
										"name": "PATH_CONTEXT",
										"type": "string",
									},
									{
										"default": "true",
										"description": "Verify the TLS on the registry endpoint (for push/pull to a non-TLS registry)",
										"name": "TLSVERIFY",
										"type": "string",
									},
									{
										"description": "Location of the repo where image has to be pushed",
										"name": "IMAGE",
										"type": "string",
									},
									{
										"default": "registry.access.redhat.com/ubi8/buildah@sha256:31f84b19a0774be7cfad751be38fc97f5e86cefd26e0abaec8047ddc650b00bf",
										"description": "The location of the buildah builder image.",
										"name": "BUILDER_IMAGE",
										"type": "string",
									},
									{
										"default": "",
										"description": "Extra parameters passed for the push command when pushing images.",
										"name": "PUSH_EXTRA_ARGS",
										"type": "string",
									},
								],
								"results": [
									{
										"description": "Digest of the image just built",
										"name": "IMAGE_DIGEST",
									},
									{
										"description": "Image repository where the built image was pushed",
										"name": "IMAGE_URL",
									},
								],
								"steps": [
									{
										"command": [
											"s2i",
											"build",
											"$(params.PATH_CONTEXT)",
											"image-registry.openshift-image-registry.svc:5000/openshift/nodejs:$(params.VERSION)",
											"--as-dockerfile",
											"/gen-source/Dockerfile.gen",
										],
										"env": [{
											"name": "HOME",
											"value": "/tekton/home",
										}],
										"image": "registry.redhat.io/ocp-tools-4-tech-preview/source-to-image-rhel8@sha256:e518e05a730ae066e371a4bd36a5af9cedc8686fd04bd59648d20ea0a486d7e5",
										"name": "generate",
										"resources": {},
										"volumeMounts": [{
											"mountPath": "/gen-source",
											"name": "gen-source",
										}],
										"workingDir": "$(workspaces.source.path)",
									},
									{
										"command": [
											"buildah",
											"bud",
											"--storage-driver=vfs",
											"--tls-verify=$(params.TLSVERIFY)",
											"--layers",
											"-f",
											"/gen-source/Dockerfile.gen",
											"-t",
											"$(params.IMAGE)",
											".",
										],
										"image": "$(params.BUILDER_IMAGE)",
										"name": "build",
										"resources": {},
										"volumeMounts": [
											{
												"mountPath": "/var/lib/containers",
												"name": "varlibcontainers",
											},
											{
												"mountPath": "/gen-source",
												"name": "gen-source",
											},
										],
										"workingDir": "/gen-source",
									},
									{
										"image": "$(params.BUILDER_IMAGE)",
										"name": "push",
										"resources": {},
										"script": "buildah push --storage-driver=vfs --tls-verify=$(params.TLSVERIFY) --digestfile=$(workspaces.source.path)/image-digest $(params.PUSH_EXTRA_ARGS) $(params.IMAGE) docker://$(params.IMAGE)\n",
										"volumeMounts": [{
											"mountPath": "/var/lib/containers",
											"name": "varlibcontainers",
										}],
										"workingDir": "$(workspaces.source.path)",
									},
									{
										"image": "$(params.BUILDER_IMAGE)",
										"name": "digest-to-results",
										"resources": {},
										"script": "cat \"$(workspaces.source.path)\"/image-digest | tee $(results.IMAGE_DIGEST.path)\necho \"$(params.IMAGE)\" | tee $(results.IMAGE_URL.path)\n",
									},
								],
								"volumes": [
									{
										"emptyDir": {},
										"name": "varlibcontainers",
									},
									{
										"emptyDir": {},
										"name": "gen-source",
									},
								],
								"workspaces": [{
									"mountPath": "/workspace/source",
									"name": "source",
								}],
							},
						},
						"whenExpressions": [{
							"input": "true",
							"operator": "in",
							"values": ["true"],
						}],
					},
					"nodejs-builder-2022-04-12-002742-git-clone-c4gb5": {
						"pipelineTaskName": "git-clone",
						"status": {
							"completionTime": "2022-04-12T04:28:04Z",
							"conditions": [{
								"lastTransitionTime": "2022-04-12T04:28:04Z",
								"message": "All Steps have completed executing",
								"reason": "Succeeded",
								"status": "True",
								"type": "Succeeded",
							}],
							"podName": "nodejs-builder-2022-04-12-002742-git-clone-c4gb5-pod-5trnf",
							"startTime": "2022-04-12T04:27:55Z",
							"steps": [{
								"container": "step-clone",
								"imageID": "registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b1598a980f17d5f5d3d8a4b11ab4f5184677f7f17ad302baa36bd3c1",
								"name": "clone",
								"terminated": {
									"containerID": "cri-o://c3195de100f33147557935cc3eb9bc0b3cadce8c51911e3fc81945abd5097910",
									"exitCode": 0,
									"finishedAt": "2022-04-12T04:28:03Z",
									"message": "[{\"key\":\"commit\",\"value\":\"36bd40d499ef3fff8aaff27ee770960e1aa63b9f\",\"type\":1},{\"key\":\"url\",\"value\":\"https://github.com/simonbaird/single-nodejs-app\",\"type\":1}]",
									"reason": "Completed",
									"startedAt": "2022-04-12T04:28:02Z",
								},
							}],
							"taskResults": [
								{
									"name": "commit",
									"value": "36bd40d499ef3fff8aaff27ee770960e1aa63b9f",
								},
								{
									"name": "url",
									"value": "https://github.com/simonbaird/single-nodejs-app",
								},
							],
							"taskSpec": {
								"description": "These Tasks are Git tasks to work with repositories used by other tasks in your Pipeline.\nThe git-clone Task will clone a repo from the provided url into the output Workspace. By default the repo will be cloned into the root of your Workspace. You can clone into a subdirectory by setting this Task's subdirectory param. This Task also supports sparse checkouts. To perform a sparse checkout, pass a list of comma separated directory patterns to this Task's sparseCheckoutDirectories param.",
								"params": [
									{
										"description": "Repository URL to clone from.",
										"name": "url",
										"type": "string",
									},
									{
										"default": "",
										"description": "Revision to checkout. (branch, tag, sha, ref, etc...)",
										"name": "revision",
										"type": "string",
									},
									{
										"default": "",
										"description": "Refspec to fetch before checking out revision.",
										"name": "refspec",
										"type": "string",
									},
									{
										"default": "true",
										"description": "Initialize and fetch git submodules.",
										"name": "submodules",
										"type": "string",
									},
									{
										"default": "1",
										"description": "Perform a shallow clone, fetching only the most recent N commits.",
										"name": "depth",
										"type": "string",
									},
									{
										"default": "true",
										"description": "Set the `http.sslVerify` global git config. Setting this to `false` is not advised unless you are sure that you trust your git remote.",
										"name": "sslVerify",
										"type": "string",
									},
									{
										"default": "",
										"description": "Subdirectory inside the `output` Workspace to clone the repo into.",
										"name": "subdirectory",
										"type": "string",
									},
									{
										"default": "",
										"description": "Define the directory patterns to match or exclude when performing a sparse checkout.",
										"name": "sparseCheckoutDirectories",
										"type": "string",
									},
									{
										"default": "true",
										"description": "Clean out the contents of the destination directory if it already exists before cloning.",
										"name": "deleteExisting",
										"type": "string",
									},
									{
										"default": "",
										"description": "HTTP proxy server for non-SSL requests.",
										"name": "httpProxy",
										"type": "string",
									},
									{
										"default": "",
										"description": "HTTPS proxy server for SSL requests.",
										"name": "httpsProxy",
										"type": "string",
									},
									{
										"default": "",
										"description": "Opt out of proxying HTTP/HTTPS requests.",
										"name": "noProxy",
										"type": "string",
									},
									{
										"default": "true",
										"description": "Log the commands that are executed during `git-clone`'s operation.",
										"name": "verbose",
										"type": "string",
									},
									{
										"default": "registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b1598a980f17d5f5d3d8a4b11ab4f5184677f7f17ad302baa36bd3c1",
										"description": "The image providing the git-init binary that this Task runs.",
										"name": "gitInitImage",
										"type": "string",
									},
									{
										"default": "/tekton/home",
										"description": "Absolute path to the user's home directory. Set this explicitly if you are running the image as a non-root user or have overridden\nthe gitInitImage param with an image containing custom user configuration.\n",
										"name": "userHome",
										"type": "string",
									},
								],
								"results": [
									{
										"description": "The precise commit SHA that was fetched by this Task.",
										"name": "commit",
									},
									{
										"description": "The precise URL that was fetched by this Task.",
										"name": "url",
									},
								],
								"steps": [{
									"env": [
										{
											"name": "HOME",
											"value": "$(params.userHome)",
										},
										{
											"name": "PARAM_URL",
											"value": "$(params.url)",
										},
										{
											"name": "PARAM_REVISION",
											"value": "$(params.revision)",
										},
										{
											"name": "PARAM_REFSPEC",
											"value": "$(params.refspec)",
										},
										{
											"name": "PARAM_SUBMODULES",
											"value": "$(params.submodules)",
										},
										{
											"name": "PARAM_DEPTH",
											"value": "$(params.depth)",
										},
										{
											"name": "PARAM_SSL_VERIFY",
											"value": "$(params.sslVerify)",
										},
										{
											"name": "PARAM_SUBDIRECTORY",
											"value": "$(params.subdirectory)",
										},
										{
											"name": "PARAM_DELETE_EXISTING",
											"value": "$(params.deleteExisting)",
										},
										{
											"name": "PARAM_HTTP_PROXY",
											"value": "$(params.httpProxy)",
										},
										{
											"name": "PARAM_HTTPS_PROXY",
											"value": "$(params.httpsProxy)",
										},
										{
											"name": "PARAM_NO_PROXY",
											"value": "$(params.noProxy)",
										},
										{
											"name": "PARAM_VERBOSE",
											"value": "$(params.verbose)",
										},
										{
											"name": "PARAM_SPARSE_CHECKOUT_DIRECTORIES",
											"value": "$(params.sparseCheckoutDirectories)",
										},
										{
											"name": "PARAM_USER_HOME",
											"value": "$(params.userHome)",
										},
										{
											"name": "WORKSPACE_OUTPUT_PATH",
											"value": "$(workspaces.output.path)",
										},
										{
											"name": "WORKSPACE_SSH_DIRECTORY_BOUND",
											"value": "$(workspaces.ssh-directory.bound)",
										},
										{
											"name": "WORKSPACE_SSH_DIRECTORY_PATH",
											"value": "$(workspaces.ssh-directory.path)",
										},
										{
											"name": "WORKSPACE_BASIC_AUTH_DIRECTORY_BOUND",
											"value": "$(workspaces.basic-auth.bound)",
										},
										{
											"name": "WORKSPACE_BASIC_AUTH_DIRECTORY_PATH",
											"value": "$(workspaces.basic-auth.path)",
										},
									],
									"image": "$(params.gitInitImage)",
									"name": "clone",
									"resources": {},
									"script": "#!/usr/bin/env sh\nset -eu\n\nif [ \"${PARAM_VERBOSE}\" = \"true\" ] ; then\n  set -x\nfi\n\nif [ \"${WORKSPACE_BASIC_AUTH_DIRECTORY_BOUND}\" = \"true\" ] ; then\n  cp \"${WORKSPACE_BASIC_AUTH_DIRECTORY_PATH}/.git-credentials\" \"${PARAM_USER_HOME}/.git-credentials\"\n  cp \"${WORKSPACE_BASIC_AUTH_DIRECTORY_PATH}/.gitconfig\" \"${PARAM_USER_HOME}/.gitconfig\"\n  chmod 400 \"${PARAM_USER_HOME}/.git-credentials\"\n  chmod 400 \"${PARAM_USER_HOME}/.gitconfig\"\nfi\n\nif [ \"${WORKSPACE_SSH_DIRECTORY_BOUND}\" = \"true\" ] ; then\n  cp -R \"${WORKSPACE_SSH_DIRECTORY_PATH}\" \"${PARAM_USER_HOME}\"/.ssh\n  chmod 700 \"${PARAM_USER_HOME}\"/.ssh\n  chmod -R 400 \"${PARAM_USER_HOME}\"/.ssh/*\nfi\n\nCHECKOUT_DIR=\"${WORKSPACE_OUTPUT_PATH}/${PARAM_SUBDIRECTORY}\"\n\ncleandir() {\n  # Delete any existing contents of the repo directory if it exists.\n  #\n  # We don't just \"rm -rf ${CHECKOUT_DIR}\" because ${CHECKOUT_DIR} might be \"/\"\n  # or the root of a mounted volume.\n  if [ -d \"${CHECKOUT_DIR}\" ] ; then\n    # Delete non-hidden files and directories\n    rm -rf \"${CHECKOUT_DIR:?}\"/*\n    # Delete files and directories starting with . but excluding ..\n    rm -rf \"${CHECKOUT_DIR}\"/.[!.]*\n    # Delete files and directories starting with .. plus any other character\n    rm -rf \"${CHECKOUT_DIR}\"/..?*\n  fi\n}\n\nif [ \"${PARAM_DELETE_EXISTING}\" = \"true\" ] ; then\n  cleandir\nfi\n\ntest -z \"${PARAM_HTTP_PROXY}\" || export HTTP_PROXY=\"${PARAM_HTTP_PROXY}\"\ntest -z \"${PARAM_HTTPS_PROXY}\" || export HTTPS_PROXY=\"${PARAM_HTTPS_PROXY}\"\ntest -z \"${PARAM_NO_PROXY}\" || export NO_PROXY=\"${PARAM_NO_PROXY}\"\n\n/ko-app/git-init \\\n  -url=\"${PARAM_URL}\" \\\n  -revision=\"${PARAM_REVISION}\" \\\n  -refspec=\"${PARAM_REFSPEC}\" \\\n  -path=\"${CHECKOUT_DIR}\" \\\n  -sslVerify=\"${PARAM_SSL_VERIFY}\" \\\n  -submodules=\"${PARAM_SUBMODULES}\" \\\n  -depth=\"${PARAM_DEPTH}\" \\\n  -sparseCheckoutDirectories=\"${PARAM_SPARSE_CHECKOUT_DIRECTORIES}\"\ncd \"${CHECKOUT_DIR}\"\nRESULT_SHA=\"$(git rev-parse HEAD)\"\nEXIT_CODE=\"$?\"\nif [ \"${EXIT_CODE}\" != 0 ] ; then\n  exit \"${EXIT_CODE}\"\nfi\nprintf \"%s\" \"${RESULT_SHA}\" > \"$(results.commit.path)\"\nprintf \"%s\" \"${PARAM_URL}\" > \"$(results.url.path)\"\n",
								}],
								"workspaces": [
									{
										"description": "The git repo will be cloned onto the volume backing this Workspace.",
										"name": "output",
									},
									{
										"description": "A .ssh directory with private key, known_hosts, config, etc. Copied to\nthe user's home before git commands are executed. Used to authenticate\nwith the git remote when performing the clone. Binding a Secret to this\nWorkspace is strongly recommended over other volume types.\n",
										"name": "ssh-directory",
										"optional": true,
									},
									{
										"description": "A Workspace containing a .gitconfig and .git-credentials file. These\nwill be copied to the user's home before any git commands are run. Any\nother files in this Workspace are ignored. It is strongly recommended\nto use ssh-directory over basic-auth whenever possible and to bind a\nSecret to this Workspace over other volume types.\n",
										"name": "basic-auth",
										"optional": true,
									},
								],
							},
						},
						"whenExpressions": [{
							"input": "true",
							"operator": "in",
							"values": ["true"],
						}],
					},
					"nodejs-builder-2022-04-12-002742-show-summary-g9vz2": {
						"pipelineTaskName": "show-summary",
						"status": {
							"completionTime": "2022-04-12T04:29:16Z",
							"conditions": [{
								"lastTransitionTime": "2022-04-12T04:29:16Z",
								"message": "All Steps have completed executing",
								"reason": "Succeeded",
								"status": "True",
								"type": "Succeeded",
							}],
							"podName": "nodejs-builder-2022-04-12-002742-show-summary-g9vz2-pod-8flbc",
							"startTime": "2022-04-12T04:29:10Z",
							"steps": [{
								"container": "step-appstudio-summary",
								"imageID": "registry.redhat.io/openshift4/ose-cli@sha256:9a1ca7a36cfdd6c69398b35a7311db662ca7c652e6e8bd440a6331c12f89703a",
								"name": "appstudio-summary",
								"terminated": {
									"containerID": "cri-o://9f79be8442ac634b40841477b5475079480c7a0cc90793d91bf7ccbf8395843d",
									"exitCode": 0,
									"finishedAt": "2022-04-12T04:29:16Z",
									"reason": "Completed",
									"startedAt": "2022-04-12T04:29:15Z",
								},
							}],
							"taskSpec": {
								"description": "App Studio Summary Pipeline Task.",
								"params": [
									{
										"description": "pipeline-run to annotate",
										"name": "pipeline-run-name",
										"type": "string",
									},
									{
										"description": "Git URL",
										"name": "git-url",
										"type": "string",
									},
									{
										"description": "Image URL",
										"name": "image-url",
										"type": "string",
									},
								],
								"steps": [{
									"image": "registry.redhat.io/openshift4/ose-cli@sha256:e6b307c51374607294d1756b871d3c702251c396efdd44d4ef8db68e239339d3",
									"name": "appstudio-summary",
									"resources": {},
									"script": "#!/usr/bin/env bash    \necho  \necho \"App Studio Build Summary:\"\necho\necho \"Build repository: $(params.git-url)\" \necho \"Generated Image is in : $(params.image-url)\"  \necho  \noc annotate pipelinerun $(params.pipeline-run-name) build.appstudio.openshift.io/repo=$(params.git-url)\noc annotate pipelinerun $(params.pipeline-run-name) build.appstudio.openshift.io/image=$(params.image-url)\n\necho \"Output is in the following annotations:\"\n\necho \"Build Repo is in 'build.appstudio.openshift.io/repo' \"\necho 'oc get pr $(params.pipeline-run-name) -o jsonpath=\"{.metadata.annotations.build\\.appstudio\\.openshift\\.io/repo}\"' \n\necho \"Build Image is in 'build.appstudio.openshift.io/image' \"\necho 'oc get pr $(params.pipeline-run-name) -o jsonpath=\"{.metadata.annotations.build\\.appstudio\\.openshift\\.io/image}\"' \n\necho End Summary\n",
								}],
							},
						},
					},
				},
			},
		}},
		"TaskRun": {
			"nodejs-builder-2022-04-12-002742-appstudio-configure-buil-6nx2k": {
				"apiVersion": "tekton.dev/v1beta1",
				"kind": "TaskRun",
				"metadata": {
					"annotations": {
						"build.appstudio.openshift.io/build": "true",
						"build.appstudio.openshift.io/deploy": "",
						"build.appstudio.openshift.io/type": "build",
						"build.appstudio.openshift.io/version": "0.1",
						"chains.tekton.dev/signed": "true",
						"chains.tekton.dev/transparency": "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=1977959",
						"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"tekton.dev/v1beta1\",\"kind\":\"PipelineRun\",\"metadata\":{\"annotations\":{\"build.appstudio.openshift.io/build\":\"true\",\"build.appstudio.openshift.io/deploy\":\"\",\"build.appstudio.openshift.io/type\":\"build\",\"build.appstudio.openshift.io/version\":\"0.1\"},\"name\":\"nodejs-builder-2022-04-12-002742\",\"namespace\":\"tekton-chains\"},\"spec\":{\"params\":[{\"name\":\"git-url\",\"value\":\"https://github.com/simonbaird/single-nodejs-app\"},{\"name\":\"output-image\",\"value\":\"image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d\"},{\"name\":\"dockerfile\",\"value\":\"Dockerfile\"},{\"name\":\"path-context\",\"value\":\".\"}],\"pipelineRef\":{\"bundle\":\"quay.io/sbaird/build-templates-bundle:50730521ebb891d6c7495a536ba6b473bf5025a9\",\"name\":\"nodejs-builder\"},\"workspaces\":[{\"name\":\"workspace\",\"persistentVolumeClaim\":{\"claimName\":\"app-studio-default-workspace\"},\"subPath\":\"pv-nodejs-builder-2022-04-12-002742\"}]}}\n",
						"pipeline.tekton.dev/release": "79a0395",
						"results.tekton.dev/record": "tekton-chains/results/f84fad5c-22e5-4f11-99fb-6aed21acdfc9/records/f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
						"results.tekton.dev/result": "tekton-chains/results/f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
					},
					"creationTimestamp": "2022-04-12T04:28:04Z",
					"finalizers": ["chains.tekton.dev"],
					"generation": 1,
					"labels": {
						"app.kubernetes.io/managed-by": "tekton-pipelines",
						"pipelines.openshift.io/runtime": "nodejs",
						"pipelines.openshift.io/strategy": "s2i",
						"pipelines.openshift.io/used-by": "build-cloud",
						"tekton.dev/memberOf": "tasks",
						"tekton.dev/pipeline": "nodejs-builder",
						"tekton.dev/pipelineRun": "nodejs-builder-2022-04-12-002742",
						"tekton.dev/pipelineTask": "appstudio-configure-build",
						"tekton.dev/task": "configure-build",
					},
					"name": "nodejs-builder-2022-04-12-002742-appstudio-configure-buil-6nx2k",
					"namespace": "tekton-chains",
					"ownerReferences": [{
						"apiVersion": "tekton.dev/v1beta1",
						"blockOwnerDeletion": true,
						"controller": true,
						"kind": "PipelineRun",
						"name": "nodejs-builder-2022-04-12-002742",
						"uid": "f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
					}],
					"resourceVersion": "1639085",
					"uid": "47e7e779-b1bf-4e73-a8ed-9a74210fdc8b",
				},
				"spec": {
					"resources": {},
					"serviceAccountName": "pipeline",
					"taskRef": {
						"bundle": "quay.io/sbaird/appstudio-tasks:50730521ebb891d6c7495a536ba6b473bf5025a9-1",
						"kind": "Task",
						"name": "configure-build",
					},
					"timeout": "1h0m0s",
					"workspaces": [{
						"name": "source",
						"persistentVolumeClaim": {"claimName": "app-studio-default-workspace"},
						"subPath": "pv-nodejs-builder-2022-04-12-002742",
					}],
				},
				"status": {
					"completionTime": "2022-04-12T04:28:12Z",
					"conditions": [{
						"lastTransitionTime": "2022-04-12T04:28:12Z",
						"message": "All Steps have completed executing",
						"reason": "Succeeded",
						"status": "True",
						"type": "Succeeded",
					}],
					"podName": "nodejs-builder-2022-04-12-002742-appstudio-configure-buil-r8bx2",
					"startTime": "2022-04-12T04:28:04Z",
					"steps": [{
						"container": "step-appstudio-configure-build",
						"imageID": "registry.access.redhat.com/ubi8-minimal@sha256:574f201d7ed185a9932c91cef5d397f5298dff9df08bc2ebb266c6d1e6284cd1",
						"name": "appstudio-configure-build",
						"terminated": {
							"containerID": "cri-o://82b9806211fb9230611efb8be59f995bde4bb77d898ce61767e8471539f2f38f",
							"exitCode": 0,
							"finishedAt": "2022-04-12T04:28:11Z",
							"message": "[{\"key\":\"buildah-auth-param\",\"value\":\" \",\"type\":1},{\"key\":\"registry-auth\",\"value\":\" \",\"type\":1}]",
							"reason": "Completed",
							"startedAt": "2022-04-12T04:28:11Z",
						},
					}],
					"taskResults": [
						{
							"name": "buildah-auth-param",
							"value": " ",
						},
						{
							"name": "registry-auth",
							"value": " ",
						},
					],
					"taskSpec": {
						"description": "App Studio Configure Build Secrets in Source. ",
						"results": [
							{
								"description": "docker config location",
								"name": "registry-auth",
							},
							{
								"description": "pass this to the build optional params to conifigure secrets",
								"name": "buildah-auth-param",
							},
						],
						"steps": [{
							"image": "registry.access.redhat.com/ubi8-minimal@sha256:574f201d7ed185a9932c91cef5d397f5298dff9df08bc2ebb266c6d1e6284cd1",
							"name": "appstudio-configure-build",
							"resources": {},
							"script": "#!/usr/bin/env bash    \necho \"App Studio Configure Build\" \n\nAUTH=/workspace/registry-auth/.dockerconfigjson\nDEST=/workspace/source/.dockerconfigjson\necho \"Looking for Registry Auth Config: $AUTH\"\nif [ -f \"$AUTH\" ]; then\n  echo \"$AUTH found\" \n  echo\n\n  cp $AUTH $DEST\n\n  echo -n $DEST > /tekton/results/registry-auth  \n  echo -n \"--authfile $DEST\"  >  /tekton/results/buildah-auth-param\n  echo \nelse  \n  echo \"No $AUTH found.\" \n  echo -n \" \" > /tekton/results/registry-auth  \n  echo -n \" \" > /tekton/results/buildah-auth-param\n  echo \nfi\n",
						}],
						"workspaces": [
							{"name": "source"},
							{
								"name": "registry-auth",
								"optional": true,
							},
						],
					},
				},
			},
			"nodejs-builder-2022-04-12-002742-appstudio-init-jr82h": {
				"apiVersion": "tekton.dev/v1beta1",
				"kind": "TaskRun",
				"metadata": {
					"annotations": {
						"build.appstudio.openshift.io/build": "true",
						"build.appstudio.openshift.io/deploy": "",
						"build.appstudio.openshift.io/type": "build",
						"build.appstudio.openshift.io/version": "0.1",
						"chains.tekton.dev/signed": "true",
						"chains.tekton.dev/transparency": "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=1977956",
						"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"tekton.dev/v1beta1\",\"kind\":\"PipelineRun\",\"metadata\":{\"annotations\":{\"build.appstudio.openshift.io/build\":\"true\",\"build.appstudio.openshift.io/deploy\":\"\",\"build.appstudio.openshift.io/type\":\"build\",\"build.appstudio.openshift.io/version\":\"0.1\"},\"name\":\"nodejs-builder-2022-04-12-002742\",\"namespace\":\"tekton-chains\"},\"spec\":{\"params\":[{\"name\":\"git-url\",\"value\":\"https://github.com/simonbaird/single-nodejs-app\"},{\"name\":\"output-image\",\"value\":\"image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d\"},{\"name\":\"dockerfile\",\"value\":\"Dockerfile\"},{\"name\":\"path-context\",\"value\":\".\"}],\"pipelineRef\":{\"bundle\":\"quay.io/sbaird/build-templates-bundle:50730521ebb891d6c7495a536ba6b473bf5025a9\",\"name\":\"nodejs-builder\"},\"workspaces\":[{\"name\":\"workspace\",\"persistentVolumeClaim\":{\"claimName\":\"app-studio-default-workspace\"},\"subPath\":\"pv-nodejs-builder-2022-04-12-002742\"}]}}\n",
						"pipeline.tekton.dev/release": "79a0395",
						"results.tekton.dev/record": "tekton-chains/results/f84fad5c-22e5-4f11-99fb-6aed21acdfc9/records/2ceb151b-946a-4320-93ba-368716c698d6",
						"results.tekton.dev/result": "tekton-chains/results/f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
					},
					"creationTimestamp": "2022-04-12T04:27:47Z",
					"finalizers": ["chains.tekton.dev"],
					"generation": 1,
					"labels": {
						"app.kubernetes.io/managed-by": "tekton-pipelines",
						"pipelines.openshift.io/runtime": "nodejs",
						"pipelines.openshift.io/strategy": "s2i",
						"pipelines.openshift.io/used-by": "build-cloud",
						"tekton.dev/memberOf": "tasks",
						"tekton.dev/pipeline": "nodejs-builder",
						"tekton.dev/pipelineRun": "nodejs-builder-2022-04-12-002742",
						"tekton.dev/pipelineTask": "appstudio-init",
						"tekton.dev/task": "init",
					},
					"name": "nodejs-builder-2022-04-12-002742-appstudio-init-jr82h",
					"namespace": "tekton-chains",
					"ownerReferences": [{
						"apiVersion": "tekton.dev/v1beta1",
						"blockOwnerDeletion": true,
						"controller": true,
						"kind": "PipelineRun",
						"name": "nodejs-builder-2022-04-12-002742",
						"uid": "f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
					}],
					"resourceVersion": "608589",
					"uid": "2ceb151b-946a-4320-93ba-368716c698d6",
				},
				"spec": {
					"params": [
						{
							"name": "image-url",
							"value": "image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d",
						},
						{
							"name": "rebuild",
							"value": "false",
						},
					],
					"resources": {},
					"serviceAccountName": "pipeline",
					"taskRef": {
						"bundle": "quay.io/sbaird/appstudio-tasks:50730521ebb891d6c7495a536ba6b473bf5025a9-1",
						"kind": "Task",
						"name": "init",
					},
					"timeout": "1h0m0s",
				},
				"status": {
					"completionTime": "2022-04-12T04:27:53Z",
					"conditions": [{
						"lastTransitionTime": "2022-04-12T04:27:53Z",
						"message": "All Steps have completed executing",
						"reason": "Succeeded",
						"status": "True",
						"type": "Succeeded",
					}],
					"podName": "nodejs-builder-2022-04-12-002742-appstudio-init-jr82h-pod-4bldr",
					"startTime": "2022-04-12T04:27:47Z",
					"steps": [{
						"container": "step-appstudio-init",
						"imageID": "registry.access.redhat.com/ubi8/skopeo@sha256:cc58da50c3842f5f2a4ba8781b60f6052919a5555a000cb4eb18a0bd0241b2b3",
						"name": "appstudio-init",
						"terminated": {
							"containerID": "cri-o://2b7c10f2a756060f12fc91ee181ba57ce9feaa3d5aabc5240a3d91bf6c39edf8",
							"exitCode": 0,
							"finishedAt": "2022-04-12T04:27:53Z",
							"message": "[{\"key\":\"build\",\"value\":\"true\",\"type\":1}]",
							"reason": "Completed",
							"startedAt": "2022-04-12T04:27:53Z",
						},
					}],
					"taskResults": [{
						"name": "build",
						"value": "true",
					}],
					"taskSpec": {
						"description": "App Studio Initialize Pipeline Task, include flags for rebuild and auth.",
						"params": [
							{
								"description": "Image URL for testing",
								"name": "image-url",
								"type": "string",
							},
							{
								"default": "false",
								"description": "Rebuild the image if exists",
								"name": "rebuild",
								"type": "string",
							},
						],
						"results": [{
							"description": "",
							"name": "build",
						}],
						"steps": [{
							"image": "registry.access.redhat.com/ubi8/skopeo@sha256:cc58da50c3842f5f2a4ba8781b60f6052919a5555a000cb4eb18a0bd0241b2b3",
							"name": "appstudio-init",
							"resources": {},
							"script": "#!/bin/bash    \necho \"App Studio Build Initialize: $(params.image-url)\" \necho \necho \"Determine if Image Already Exists\"\n# Build the image when image does not exists or rebuild is set to true\nif ! skopeo inspect --no-tags docker://$(params.image-url) &>/dev/null || [ \"$(params.rebuild)\" == \"true\" ]; then\n  echo -n \"true\" > $(results.build.path)\nelse\n  echo -n \"false\" > $(results.build.path)\nfi\n",
						}],
					},
				},
			},
			"nodejs-builder-2022-04-12-002742-build-container-mqf5p": {
				"apiVersion": "tekton.dev/v1beta1",
				"kind": "TaskRun",
				"metadata": {
					"annotations": {
						"build.appstudio.openshift.io/build": "true",
						"build.appstudio.openshift.io/deploy": "",
						"build.appstudio.openshift.io/type": "build",
						"build.appstudio.openshift.io/version": "0.1",
						"chains.tekton.dev/signed": "true",
						"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"tekton.dev/v1beta1\",\"kind\":\"PipelineRun\",\"metadata\":{\"annotations\":{\"build.appstudio.openshift.io/build\":\"true\",\"build.appstudio.openshift.io/deploy\":\"\",\"build.appstudio.openshift.io/type\":\"build\",\"build.appstudio.openshift.io/version\":\"0.1\"},\"name\":\"nodejs-builder-2022-04-12-002742\",\"namespace\":\"tekton-chains\"},\"spec\":{\"params\":[{\"name\":\"git-url\",\"value\":\"https://github.com/simonbaird/single-nodejs-app\"},{\"name\":\"output-image\",\"value\":\"image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d\"},{\"name\":\"dockerfile\",\"value\":\"Dockerfile\"},{\"name\":\"path-context\",\"value\":\".\"}],\"pipelineRef\":{\"bundle\":\"quay.io/sbaird/build-templates-bundle:50730521ebb891d6c7495a536ba6b473bf5025a9\",\"name\":\"nodejs-builder\"},\"workspaces\":[{\"name\":\"workspace\",\"persistentVolumeClaim\":{\"claimName\":\"app-studio-default-workspace\"},\"subPath\":\"pv-nodejs-builder-2022-04-12-002742\"}]}}\n",
						"pipeline.tekton.dev/release": "79a0395",
						"results.tekton.dev/record": "tekton-chains/results/f84fad5c-22e5-4f11-99fb-6aed21acdfc9/records/f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
						"results.tekton.dev/result": "tekton-chains/results/f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
						"tekton.dev/displayName": "s2i nodejs",
						"tekton.dev/pipelines.minVersion": "0.19",
						"tekton.dev/tags": "s2i, nodejs, workspace",
					},
					"creationTimestamp": "2022-04-12T04:28:12Z",
					"finalizers": ["chains.tekton.dev"],
					"generation": 1,
					"labels": {
						"app.kubernetes.io/managed-by": "tekton-pipelines",
						"pipelines.openshift.io/runtime": "nodejs",
						"pipelines.openshift.io/strategy": "s2i",
						"pipelines.openshift.io/used-by": "build-cloud",
						"tekton.dev/memberOf": "tasks",
						"tekton.dev/pipeline": "nodejs-builder",
						"tekton.dev/pipelineRun": "nodejs-builder-2022-04-12-002742",
						"tekton.dev/pipelineTask": "build-container",
						"tekton.dev/task": "s2i-nodejs",
					},
					"name": "nodejs-builder-2022-04-12-002742-build-container-mqf5p",
					"namespace": "tekton-chains",
					"ownerReferences": [{
						"apiVersion": "tekton.dev/v1beta1",
						"blockOwnerDeletion": true,
						"controller": true,
						"kind": "PipelineRun",
						"name": "nodejs-builder-2022-04-12-002742",
						"uid": "f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
					}],
					"resourceVersion": "2605438",
					"uid": "e954fc4b-1432-4541-9dbb-12fa3a7998c0",
				},
				"spec": {
					"params": [
						{
							"name": "PATH_CONTEXT",
							"value": ".",
						},
						{
							"name": "IMAGE",
							"value": "image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d",
						},
						{
							"name": "PUSH_EXTRA_ARGS",
							"value": " ",
						},
					],
					"resources": {},
					"serviceAccountName": "pipeline",
					"taskRef": {
						"bundle": "quay.io/sbaird/appstudio-tasks:50730521ebb891d6c7495a536ba6b473bf5025a9-1",
						"kind": "Task",
						"name": "s2i-nodejs",
					},
					"timeout": "1h0m0s",
					"workspaces": [{
						"name": "source",
						"persistentVolumeClaim": {"claimName": "app-studio-default-workspace"},
						"subPath": "pv-nodejs-builder-2022-04-12-002742",
					}],
				},
				"status": {
					"completionTime": "2022-04-12T04:29:09Z",
					"conditions": [{
						"lastTransitionTime": "2022-04-12T04:29:09Z",
						"message": "All Steps have completed executing",
						"reason": "Succeeded",
						"status": "True",
						"type": "Succeeded",
					}],
					"podName": "nodejs-builder-2022-04-12-002742-build-container-mqf5p-po-l9mk6",
					"startTime": "2022-04-12T04:28:12Z",
					"steps": [
						{
							"container": "step-generate",
							"imageID": "registry.redhat.io/ocp-tools-4-tech-preview/source-to-image-rhel8@sha256:cd4996fba88519ec21499da63d8c3e26cc4552429b949da76914d0666c27872d",
							"name": "generate",
							"terminated": {
								"containerID": "cri-o://355ef4c97822013c7c45ce805a31cf830dd399d2e56c6419148e4f59766e9422",
								"exitCode": 0,
								"finishedAt": "2022-04-12T04:28:18Z",
								"reason": "Completed",
								"startedAt": "2022-04-12T04:28:18Z",
							},
						},
						{
							"container": "step-build",
							"imageID": "registry.access.redhat.com/ubi8/buildah@sha256:31f84b19a0774be7cfad751be38fc97f5e86cefd26e0abaec8047ddc650b00bf",
							"name": "build",
							"terminated": {
								"containerID": "cri-o://cad49cadf9047bd7096ee3fa20ea28af7736672470e5eef13b7624acbb0b35db",
								"exitCode": 0,
								"finishedAt": "2022-04-12T04:29:07Z",
								"reason": "Completed",
								"startedAt": "2022-04-12T04:28:18Z",
							},
						},
						{
							"container": "step-push",
							"imageID": "registry.access.redhat.com/ubi8/buildah@sha256:31f84b19a0774be7cfad751be38fc97f5e86cefd26e0abaec8047ddc650b00bf",
							"name": "push",
							"terminated": {
								"containerID": "cri-o://1f4aa0f343765f198d81aadee4ebbe7feb5cbfb139bdce2552caef88244c2c29",
								"exitCode": 0,
								"finishedAt": "2022-04-12T04:29:08Z",
								"reason": "Completed",
								"startedAt": "2022-04-12T04:29:07Z",
							},
						},
						{
							"container": "step-digest-to-results",
							"imageID": "registry.access.redhat.com/ubi8/buildah@sha256:31f84b19a0774be7cfad751be38fc97f5e86cefd26e0abaec8047ddc650b00bf",
							"name": "digest-to-results",
							"terminated": {
								"containerID": "cri-o://5adc0caabdf0c5b11a02878a77b4524ccf70844c67878033156aa3d7ce19ee2f",
								"exitCode": 0,
								"finishedAt": "2022-04-12T04:29:09Z",
								"message": "[{\"key\":\"IMAGE_DIGEST\",\"value\":\"sha256:2d4dbf45c3f9dcfe19bb3297d06c799cd2f616e111593fbf70645c4929b45fde\",\"type\":1},{\"key\":\"IMAGE_URL\",\"value\":\"image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d\\n\",\"type\":1}]",
								"reason": "Completed",
								"startedAt": "2022-04-12T04:29:09Z",
							},
						},
					],
					"taskResults": [
						{
							"name": "IMAGE_DIGEST",
							"value": "sha256:2d4dbf45c3f9dcfe19bb3297d06c799cd2f616e111593fbf70645c4929b45fde",
						},
						{
							"name": "IMAGE_URL",
							"value": "image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d\n",
						},
					],
					"taskSpec": {
						"description": "s2i-nodejs task clones a Git repository and builds and pushes a container image using S2I and a nodejs builder image.",
						"params": [
							{
								"default": "14-ubi8",
								"description": "The tag of nodejs imagestream for nodejs version",
								"name": "VERSION",
								"type": "string",
							},
							{
								"default": ".",
								"description": "The location of the path to run s2i from.",
								"name": "PATH_CONTEXT",
								"type": "string",
							},
							{
								"default": "true",
								"description": "Verify the TLS on the registry endpoint (for push/pull to a non-TLS registry)",
								"name": "TLSVERIFY",
								"type": "string",
							},
							{
								"description": "Location of the repo where image has to be pushed",
								"name": "IMAGE",
								"type": "string",
							},
							{
								"default": "registry.access.redhat.com/ubi8/buildah@sha256:31f84b19a0774be7cfad751be38fc97f5e86cefd26e0abaec8047ddc650b00bf",
								"description": "The location of the buildah builder image.",
								"name": "BUILDER_IMAGE",
								"type": "string",
							},
							{
								"default": "",
								"description": "Extra parameters passed for the push command when pushing images.",
								"name": "PUSH_EXTRA_ARGS",
								"type": "string",
							},
						],
						"results": [
							{
								"description": "Digest of the image just built",
								"name": "IMAGE_DIGEST",
							},
							{
								"description": "Image repository where the built image was pushed",
								"name": "IMAGE_URL",
							},
						],
						"steps": [
							{
								"command": [
									"s2i",
									"build",
									"$(params.PATH_CONTEXT)",
									"image-registry.openshift-image-registry.svc:5000/openshift/nodejs:$(params.VERSION)",
									"--as-dockerfile",
									"/gen-source/Dockerfile.gen",
								],
								"env": [{
									"name": "HOME",
									"value": "/tekton/home",
								}],
								"image": "registry.redhat.io/ocp-tools-4-tech-preview/source-to-image-rhel8@sha256:e518e05a730ae066e371a4bd36a5af9cedc8686fd04bd59648d20ea0a486d7e5",
								"name": "generate",
								"resources": {},
								"volumeMounts": [{
									"mountPath": "/gen-source",
									"name": "gen-source",
								}],
								"workingDir": "$(workspaces.source.path)",
							},
							{
								"command": [
									"buildah",
									"bud",
									"--storage-driver=vfs",
									"--tls-verify=$(params.TLSVERIFY)",
									"--layers",
									"-f",
									"/gen-source/Dockerfile.gen",
									"-t",
									"$(params.IMAGE)",
									".",
								],
								"image": "$(params.BUILDER_IMAGE)",
								"name": "build",
								"resources": {},
								"volumeMounts": [
									{
										"mountPath": "/var/lib/containers",
										"name": "varlibcontainers",
									},
									{
										"mountPath": "/gen-source",
										"name": "gen-source",
									},
								],
								"workingDir": "/gen-source",
							},
							{
								"image": "$(params.BUILDER_IMAGE)",
								"name": "push",
								"resources": {},
								"script": "buildah push --storage-driver=vfs --tls-verify=$(params.TLSVERIFY) --digestfile=$(workspaces.source.path)/image-digest $(params.PUSH_EXTRA_ARGS) $(params.IMAGE) docker://$(params.IMAGE)\n",
								"volumeMounts": [{
									"mountPath": "/var/lib/containers",
									"name": "varlibcontainers",
								}],
								"workingDir": "$(workspaces.source.path)",
							},
							{
								"image": "$(params.BUILDER_IMAGE)",
								"name": "digest-to-results",
								"resources": {},
								"script": "cat \"$(workspaces.source.path)\"/image-digest | tee $(results.IMAGE_DIGEST.path)\necho \"$(params.IMAGE)\" | tee $(results.IMAGE_URL.path)\n",
							},
						],
						"volumes": [
							{
								"emptyDir": {},
								"name": "varlibcontainers",
							},
							{
								"emptyDir": {},
								"name": "gen-source",
							},
						],
						"workspaces": [{
							"mountPath": "/workspace/source",
							"name": "source",
						}],
					},
				},
			},
			"nodejs-builder-2022-04-12-002742-git-clone-c4gb5": {
				"apiVersion": "tekton.dev/v1beta1",
				"kind": "TaskRun",
				"metadata": {
					"annotations": {
						"build.appstudio.openshift.io/build": "true",
						"build.appstudio.openshift.io/deploy": "",
						"build.appstudio.openshift.io/type": "build",
						"build.appstudio.openshift.io/version": "0.1",
						"chains.tekton.dev/signed": "true",
						"chains.tekton.dev/transparency": "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=1977957",
						"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"tekton.dev/v1beta1\",\"kind\":\"PipelineRun\",\"metadata\":{\"annotations\":{\"build.appstudio.openshift.io/build\":\"true\",\"build.appstudio.openshift.io/deploy\":\"\",\"build.appstudio.openshift.io/type\":\"build\",\"build.appstudio.openshift.io/version\":\"0.1\"},\"name\":\"nodejs-builder-2022-04-12-002742\",\"namespace\":\"tekton-chains\"},\"spec\":{\"params\":[{\"name\":\"git-url\",\"value\":\"https://github.com/simonbaird/single-nodejs-app\"},{\"name\":\"output-image\",\"value\":\"image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d\"},{\"name\":\"dockerfile\",\"value\":\"Dockerfile\"},{\"name\":\"path-context\",\"value\":\".\"}],\"pipelineRef\":{\"bundle\":\"quay.io/sbaird/build-templates-bundle:50730521ebb891d6c7495a536ba6b473bf5025a9\",\"name\":\"nodejs-builder\"},\"workspaces\":[{\"name\":\"workspace\",\"persistentVolumeClaim\":{\"claimName\":\"app-studio-default-workspace\"},\"subPath\":\"pv-nodejs-builder-2022-04-12-002742\"}]}}\n",
						"pipeline.tekton.dev/release": "79a0395",
						"results.tekton.dev/record": "tekton-chains/results/f84fad5c-22e5-4f11-99fb-6aed21acdfc9/records/f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
						"results.tekton.dev/result": "tekton-chains/results/f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
						"tekton.dev/categories": "Git",
						"tekton.dev/displayName": "git clone",
						"tekton.dev/pipelines.minVersion": "0.21.0",
						"tekton.dev/platforms": "linux/amd64,linux/s390x,linux/ppc64le,linux/arm64",
						"tekton.dev/tags": "git",
					},
					"creationTimestamp": "2022-04-12T04:27:55Z",
					"finalizers": ["chains.tekton.dev"],
					"generation": 1,
					"labels": {
						"app.kubernetes.io/managed-by": "tekton-pipelines",
						"pipelines.openshift.io/runtime": "nodejs",
						"pipelines.openshift.io/strategy": "s2i",
						"pipelines.openshift.io/used-by": "build-cloud",
						"tekton.dev/memberOf": "tasks",
						"tekton.dev/pipeline": "nodejs-builder",
						"tekton.dev/pipelineRun": "nodejs-builder-2022-04-12-002742",
						"tekton.dev/pipelineTask": "git-clone",
						"tekton.dev/task": "git-clone",
					},
					"name": "nodejs-builder-2022-04-12-002742-git-clone-c4gb5",
					"namespace": "tekton-chains",
					"ownerReferences": [{
						"apiVersion": "tekton.dev/v1beta1",
						"blockOwnerDeletion": true,
						"controller": true,
						"kind": "PipelineRun",
						"name": "nodejs-builder-2022-04-12-002742",
						"uid": "f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
					}],
					"resourceVersion": "608804",
					"uid": "b0b7b7df-12e6-4d56-b385-f530cb99affe",
				},
				"spec": {
					"params": [
						{
							"name": "url",
							"value": "https://github.com/simonbaird/single-nodejs-app",
						},
						{
							"name": "revision",
							"value": "main",
						},
					],
					"resources": {},
					"serviceAccountName": "pipeline",
					"taskRef": {
						"bundle": "quay.io/sbaird/appstudio-tasks:50730521ebb891d6c7495a536ba6b473bf5025a9-1",
						"kind": "Task",
						"name": "git-clone",
					},
					"timeout": "1h0m0s",
					"workspaces": [{
						"name": "output",
						"persistentVolumeClaim": {"claimName": "app-studio-default-workspace"},
						"subPath": "pv-nodejs-builder-2022-04-12-002742",
					}],
				},
				"status": {
					"completionTime": "2022-04-12T04:28:04Z",
					"conditions": [{
						"lastTransitionTime": "2022-04-12T04:28:04Z",
						"message": "All Steps have completed executing",
						"reason": "Succeeded",
						"status": "True",
						"type": "Succeeded",
					}],
					"podName": "nodejs-builder-2022-04-12-002742-git-clone-c4gb5-pod-5trnf",
					"startTime": "2022-04-12T04:27:55Z",
					"steps": [{
						"container": "step-clone",
						"imageID": "registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b1598a980f17d5f5d3d8a4b11ab4f5184677f7f17ad302baa36bd3c1",
						"name": "clone",
						"terminated": {
							"containerID": "cri-o://c3195de100f33147557935cc3eb9bc0b3cadce8c51911e3fc81945abd5097910",
							"exitCode": 0,
							"finishedAt": "2022-04-12T04:28:03Z",
							"message": "[{\"key\":\"commit\",\"value\":\"36bd40d499ef3fff8aaff27ee770960e1aa63b9f\",\"type\":1},{\"key\":\"url\",\"value\":\"https://github.com/simonbaird/single-nodejs-app\",\"type\":1}]",
							"reason": "Completed",
							"startedAt": "2022-04-12T04:28:02Z",
						},
					}],
					"taskResults": [
						{
							"name": "commit",
							"value": "36bd40d499ef3fff8aaff27ee770960e1aa63b9f",
						},
						{
							"name": "url",
							"value": "https://github.com/simonbaird/single-nodejs-app",
						},
					],
					"taskSpec": {
						"description": "These Tasks are Git tasks to work with repositories used by other tasks in your Pipeline.\nThe git-clone Task will clone a repo from the provided url into the output Workspace. By default the repo will be cloned into the root of your Workspace. You can clone into a subdirectory by setting this Task's subdirectory param. This Task also supports sparse checkouts. To perform a sparse checkout, pass a list of comma separated directory patterns to this Task's sparseCheckoutDirectories param.",
						"params": [
							{
								"description": "Repository URL to clone from.",
								"name": "url",
								"type": "string",
							},
							{
								"default": "",
								"description": "Revision to checkout. (branch, tag, sha, ref, etc...)",
								"name": "revision",
								"type": "string",
							},
							{
								"default": "",
								"description": "Refspec to fetch before checking out revision.",
								"name": "refspec",
								"type": "string",
							},
							{
								"default": "true",
								"description": "Initialize and fetch git submodules.",
								"name": "submodules",
								"type": "string",
							},
							{
								"default": "1",
								"description": "Perform a shallow clone, fetching only the most recent N commits.",
								"name": "depth",
								"type": "string",
							},
							{
								"default": "true",
								"description": "Set the `http.sslVerify` global git config. Setting this to `false` is not advised unless you are sure that you trust your git remote.",
								"name": "sslVerify",
								"type": "string",
							},
							{
								"default": "",
								"description": "Subdirectory inside the `output` Workspace to clone the repo into.",
								"name": "subdirectory",
								"type": "string",
							},
							{
								"default": "",
								"description": "Define the directory patterns to match or exclude when performing a sparse checkout.",
								"name": "sparseCheckoutDirectories",
								"type": "string",
							},
							{
								"default": "true",
								"description": "Clean out the contents of the destination directory if it already exists before cloning.",
								"name": "deleteExisting",
								"type": "string",
							},
							{
								"default": "",
								"description": "HTTP proxy server for non-SSL requests.",
								"name": "httpProxy",
								"type": "string",
							},
							{
								"default": "",
								"description": "HTTPS proxy server for SSL requests.",
								"name": "httpsProxy",
								"type": "string",
							},
							{
								"default": "",
								"description": "Opt out of proxying HTTP/HTTPS requests.",
								"name": "noProxy",
								"type": "string",
							},
							{
								"default": "true",
								"description": "Log the commands that are executed during `git-clone`'s operation.",
								"name": "verbose",
								"type": "string",
							},
							{
								"default": "registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b1598a980f17d5f5d3d8a4b11ab4f5184677f7f17ad302baa36bd3c1",
								"description": "The image providing the git-init binary that this Task runs.",
								"name": "gitInitImage",
								"type": "string",
							},
							{
								"default": "/tekton/home",
								"description": "Absolute path to the user's home directory. Set this explicitly if you are running the image as a non-root user or have overridden\nthe gitInitImage param with an image containing custom user configuration.\n",
								"name": "userHome",
								"type": "string",
							},
						],
						"results": [
							{
								"description": "The precise commit SHA that was fetched by this Task.",
								"name": "commit",
							},
							{
								"description": "The precise URL that was fetched by this Task.",
								"name": "url",
							},
						],
						"steps": [{
							"env": [
								{
									"name": "HOME",
									"value": "$(params.userHome)",
								},
								{
									"name": "PARAM_URL",
									"value": "$(params.url)",
								},
								{
									"name": "PARAM_REVISION",
									"value": "$(params.revision)",
								},
								{
									"name": "PARAM_REFSPEC",
									"value": "$(params.refspec)",
								},
								{
									"name": "PARAM_SUBMODULES",
									"value": "$(params.submodules)",
								},
								{
									"name": "PARAM_DEPTH",
									"value": "$(params.depth)",
								},
								{
									"name": "PARAM_SSL_VERIFY",
									"value": "$(params.sslVerify)",
								},
								{
									"name": "PARAM_SUBDIRECTORY",
									"value": "$(params.subdirectory)",
								},
								{
									"name": "PARAM_DELETE_EXISTING",
									"value": "$(params.deleteExisting)",
								},
								{
									"name": "PARAM_HTTP_PROXY",
									"value": "$(params.httpProxy)",
								},
								{
									"name": "PARAM_HTTPS_PROXY",
									"value": "$(params.httpsProxy)",
								},
								{
									"name": "PARAM_NO_PROXY",
									"value": "$(params.noProxy)",
								},
								{
									"name": "PARAM_VERBOSE",
									"value": "$(params.verbose)",
								},
								{
									"name": "PARAM_SPARSE_CHECKOUT_DIRECTORIES",
									"value": "$(params.sparseCheckoutDirectories)",
								},
								{
									"name": "PARAM_USER_HOME",
									"value": "$(params.userHome)",
								},
								{
									"name": "WORKSPACE_OUTPUT_PATH",
									"value": "$(workspaces.output.path)",
								},
								{
									"name": "WORKSPACE_SSH_DIRECTORY_BOUND",
									"value": "$(workspaces.ssh-directory.bound)",
								},
								{
									"name": "WORKSPACE_SSH_DIRECTORY_PATH",
									"value": "$(workspaces.ssh-directory.path)",
								},
								{
									"name": "WORKSPACE_BASIC_AUTH_DIRECTORY_BOUND",
									"value": "$(workspaces.basic-auth.bound)",
								},
								{
									"name": "WORKSPACE_BASIC_AUTH_DIRECTORY_PATH",
									"value": "$(workspaces.basic-auth.path)",
								},
							],
							"image": "$(params.gitInitImage)",
							"name": "clone",
							"resources": {},
							"script": "#!/usr/bin/env sh\nset -eu\n\nif [ \"${PARAM_VERBOSE}\" = \"true\" ] ; then\n  set -x\nfi\n\nif [ \"${WORKSPACE_BASIC_AUTH_DIRECTORY_BOUND}\" = \"true\" ] ; then\n  cp \"${WORKSPACE_BASIC_AUTH_DIRECTORY_PATH}/.git-credentials\" \"${PARAM_USER_HOME}/.git-credentials\"\n  cp \"${WORKSPACE_BASIC_AUTH_DIRECTORY_PATH}/.gitconfig\" \"${PARAM_USER_HOME}/.gitconfig\"\n  chmod 400 \"${PARAM_USER_HOME}/.git-credentials\"\n  chmod 400 \"${PARAM_USER_HOME}/.gitconfig\"\nfi\n\nif [ \"${WORKSPACE_SSH_DIRECTORY_BOUND}\" = \"true\" ] ; then\n  cp -R \"${WORKSPACE_SSH_DIRECTORY_PATH}\" \"${PARAM_USER_HOME}\"/.ssh\n  chmod 700 \"${PARAM_USER_HOME}\"/.ssh\n  chmod -R 400 \"${PARAM_USER_HOME}\"/.ssh/*\nfi\n\nCHECKOUT_DIR=\"${WORKSPACE_OUTPUT_PATH}/${PARAM_SUBDIRECTORY}\"\n\ncleandir() {\n  # Delete any existing contents of the repo directory if it exists.\n  #\n  # We don't just \"rm -rf ${CHECKOUT_DIR}\" because ${CHECKOUT_DIR} might be \"/\"\n  # or the root of a mounted volume.\n  if [ -d \"${CHECKOUT_DIR}\" ] ; then\n    # Delete non-hidden files and directories\n    rm -rf \"${CHECKOUT_DIR:?}\"/*\n    # Delete files and directories starting with . but excluding ..\n    rm -rf \"${CHECKOUT_DIR}\"/.[!.]*\n    # Delete files and directories starting with .. plus any other character\n    rm -rf \"${CHECKOUT_DIR}\"/..?*\n  fi\n}\n\nif [ \"${PARAM_DELETE_EXISTING}\" = \"true\" ] ; then\n  cleandir\nfi\n\ntest -z \"${PARAM_HTTP_PROXY}\" || export HTTP_PROXY=\"${PARAM_HTTP_PROXY}\"\ntest -z \"${PARAM_HTTPS_PROXY}\" || export HTTPS_PROXY=\"${PARAM_HTTPS_PROXY}\"\ntest -z \"${PARAM_NO_PROXY}\" || export NO_PROXY=\"${PARAM_NO_PROXY}\"\n\n/ko-app/git-init \\\n  -url=\"${PARAM_URL}\" \\\n  -revision=\"${PARAM_REVISION}\" \\\n  -refspec=\"${PARAM_REFSPEC}\" \\\n  -path=\"${CHECKOUT_DIR}\" \\\n  -sslVerify=\"${PARAM_SSL_VERIFY}\" \\\n  -submodules=\"${PARAM_SUBMODULES}\" \\\n  -depth=\"${PARAM_DEPTH}\" \\\n  -sparseCheckoutDirectories=\"${PARAM_SPARSE_CHECKOUT_DIRECTORIES}\"\ncd \"${CHECKOUT_DIR}\"\nRESULT_SHA=\"$(git rev-parse HEAD)\"\nEXIT_CODE=\"$?\"\nif [ \"${EXIT_CODE}\" != 0 ] ; then\n  exit \"${EXIT_CODE}\"\nfi\nprintf \"%s\" \"${RESULT_SHA}\" > \"$(results.commit.path)\"\nprintf \"%s\" \"${PARAM_URL}\" > \"$(results.url.path)\"\n",
						}],
						"workspaces": [
							{
								"description": "The git repo will be cloned onto the volume backing this Workspace.",
								"name": "output",
							},
							{
								"description": "A .ssh directory with private key, known_hosts, config, etc. Copied to\nthe user's home before git commands are executed. Used to authenticate\nwith the git remote when performing the clone. Binding a Secret to this\nWorkspace is strongly recommended over other volume types.\n",
								"name": "ssh-directory",
								"optional": true,
							},
							{
								"description": "A Workspace containing a .gitconfig and .git-credentials file. These\nwill be copied to the user's home before any git commands are run. Any\nother files in this Workspace are ignored. It is strongly recommended\nto use ssh-directory over basic-auth whenever possible and to bind a\nSecret to this Workspace over other volume types.\n",
								"name": "basic-auth",
								"optional": true,
							},
						],
					},
				},
			},
			"nodejs-builder-2022-04-12-002742-show-summary-g9vz2": {
				"apiVersion": "tekton.dev/v1beta1",
				"kind": "TaskRun",
				"metadata": {
					"annotations": {
						"build.appstudio.openshift.io/build": "true",
						"build.appstudio.openshift.io/deploy": "",
						"build.appstudio.openshift.io/type": "build",
						"build.appstudio.openshift.io/version": "0.1",
						"chains.tekton.dev/signed": "true",
						"chains.tekton.dev/transparency": "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=1977978",
						"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"tekton.dev/v1beta1\",\"kind\":\"PipelineRun\",\"metadata\":{\"annotations\":{\"build.appstudio.openshift.io/build\":\"true\",\"build.appstudio.openshift.io/deploy\":\"\",\"build.appstudio.openshift.io/type\":\"build\",\"build.appstudio.openshift.io/version\":\"0.1\"},\"name\":\"nodejs-builder-2022-04-12-002742\",\"namespace\":\"tekton-chains\"},\"spec\":{\"params\":[{\"name\":\"git-url\",\"value\":\"https://github.com/simonbaird/single-nodejs-app\"},{\"name\":\"output-image\",\"value\":\"image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d\"},{\"name\":\"dockerfile\",\"value\":\"Dockerfile\"},{\"name\":\"path-context\",\"value\":\".\"}],\"pipelineRef\":{\"bundle\":\"quay.io/sbaird/build-templates-bundle:50730521ebb891d6c7495a536ba6b473bf5025a9\",\"name\":\"nodejs-builder\"},\"workspaces\":[{\"name\":\"workspace\",\"persistentVolumeClaim\":{\"claimName\":\"app-studio-default-workspace\"},\"subPath\":\"pv-nodejs-builder-2022-04-12-002742\"}]}}\n",
						"pipeline.tekton.dev/release": "79a0395",
						"results.tekton.dev/record": "tekton-chains/results/f84fad5c-22e5-4f11-99fb-6aed21acdfc9/records/f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
						"results.tekton.dev/result": "tekton-chains/results/f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
					},
					"creationTimestamp": "2022-04-12T04:29:09Z",
					"finalizers": ["chains.tekton.dev"],
					"generation": 1,
					"labels": {
						"app.kubernetes.io/managed-by": "tekton-pipelines",
						"pipelines.openshift.io/runtime": "nodejs",
						"pipelines.openshift.io/strategy": "s2i",
						"pipelines.openshift.io/used-by": "build-cloud",
						"tekton.dev/memberOf": "finally",
						"tekton.dev/pipeline": "nodejs-builder",
						"tekton.dev/pipelineRun": "nodejs-builder-2022-04-12-002742",
						"tekton.dev/pipelineTask": "show-summary",
						"tekton.dev/task": "summary",
					},
					"name": "nodejs-builder-2022-04-12-002742-show-summary-g9vz2",
					"namespace": "tekton-chains",
					"ownerReferences": [{
						"apiVersion": "tekton.dev/v1beta1",
						"blockOwnerDeletion": true,
						"controller": true,
						"kind": "PipelineRun",
						"name": "nodejs-builder-2022-04-12-002742",
						"uid": "f84fad5c-22e5-4f11-99fb-6aed21acdfc9",
					}],
					"resourceVersion": "1260480",
					"uid": "b4d3c66d-db83-4dac-a433-c1cf8a324a9f",
				},
				"spec": {
					"params": [
						{
							"name": "pipeline-run-name",
							"value": "nodejs-builder-2022-04-12-002742",
						},
						{
							"name": "git-url",
							"value": "https://github.com/simonbaird/single-nodejs-app",
						},
						{
							"name": "image-url",
							"value": "image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d",
						},
					],
					"resources": {},
					"serviceAccountName": "pipeline",
					"taskRef": {
						"bundle": "quay.io/sbaird/appstudio-tasks:50730521ebb891d6c7495a536ba6b473bf5025a9-2",
						"kind": "Task",
						"name": "summary",
					},
					"timeout": "1h0m0s",
				},
				"status": {
					"completionTime": "2022-04-12T04:29:16Z",
					"conditions": [{
						"lastTransitionTime": "2022-04-12T04:29:16Z",
						"message": "All Steps have completed executing",
						"reason": "Succeeded",
						"status": "True",
						"type": "Succeeded",
					}],
					"podName": "nodejs-builder-2022-04-12-002742-show-summary-g9vz2-pod-8flbc",
					"startTime": "2022-04-12T04:29:10Z",
					"steps": [{
						"container": "step-appstudio-summary",
						"imageID": "registry.redhat.io/openshift4/ose-cli@sha256:9a1ca7a36cfdd6c69398b35a7311db662ca7c652e6e8bd440a6331c12f89703a",
						"name": "appstudio-summary",
						"terminated": {
							"containerID": "cri-o://9f79be8442ac634b40841477b5475079480c7a0cc90793d91bf7ccbf8395843d",
							"exitCode": 0,
							"finishedAt": "2022-04-12T04:29:16Z",
							"reason": "Completed",
							"startedAt": "2022-04-12T04:29:15Z",
						},
					}],
					"taskSpec": {
						"description": "App Studio Summary Pipeline Task.",
						"params": [
							{
								"description": "pipeline-run to annotate",
								"name": "pipeline-run-name",
								"type": "string",
							},
							{
								"description": "Git URL",
								"name": "git-url",
								"type": "string",
							},
							{
								"description": "Image URL",
								"name": "image-url",
								"type": "string",
							},
						],
						"steps": [{
							"image": "registry.redhat.io/openshift4/ose-cli@sha256:e6b307c51374607294d1756b871d3c702251c396efdd44d4ef8db68e239339d3",
							"name": "appstudio-summary",
							"resources": {},
							"script": "#!/usr/bin/env bash    \necho  \necho \"App Studio Build Summary:\"\necho\necho \"Build repository: $(params.git-url)\" \necho \"Generated Image is in : $(params.image-url)\"  \necho  \noc annotate pipelinerun $(params.pipeline-run-name) build.appstudio.openshift.io/repo=$(params.git-url)\noc annotate pipelinerun $(params.pipeline-run-name) build.appstudio.openshift.io/image=$(params.image-url)\n\necho \"Output is in the following annotations:\"\n\necho \"Build Repo is in 'build.appstudio.openshift.io/repo' \"\necho 'oc get pr $(params.pipeline-run-name) -o jsonpath=\"{.metadata.annotations.build\\.appstudio\\.openshift\\.io/repo}\"' \n\necho \"Build Image is in 'build.appstudio.openshift.io/image' \"\necho 'oc get pr $(params.pipeline-run-name) -o jsonpath=\"{.metadata.annotations.build\\.appstudio\\.openshift\\.io/image}\"' \n\necho End Summary\n",
						}],
					},
				},
			},
		},
	},
	"config": {"policy": {"non_blocking_checks": ["not_useful"]}},
	"rekor": {"rekor.sigstore.dev": {"index": {
		"1977956": {
			"attestation": {
				"_type": "https://in-toto.io/Statement/v0.1",
				"predicate": {
					"buildConfig": {"steps": [{
						"annotations": null,
						"arguments": null,
						"entryPoint": "#!/bin/bash    \necho \"App Studio Build Initialize: $(params.image-url)\" \necho \necho \"Determine if Image Already Exists\"\n# Build the image when image does not exists or rebuild is set to true\nif ! skopeo inspect --no-tags docker://$(params.image-url) &>/dev/null || [ \"$(params.rebuild)\" == \"true\" ]; then\n  echo -n \"true\" > $(results.build.path)\nelse\n  echo -n \"false\" > $(results.build.path)\nfi\n",
						"environment": {
							"container": "appstudio-init",
							"image": "registry.access.redhat.com/ubi8/skopeo@sha256:cc58da50c3842f5f2a4ba8781b60f6052919a5555a000cb4eb18a0bd0241b2b3",
						},
					}]},
					"buildType": "https://tekton.dev/attestations/chains@v2",
					"builder": {"id": "https://tekton.dev/chains/v2"},
					"invocation": {
						"configSource": {},
						"parameters": {
							"image-url": "{string image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d []}",
							"rebuild": "false",
						},
					},
					"metadata": {
						"buildFinishedOn": "2022-04-12T04:27:53Z",
						"buildStartedOn": "2022-04-12T04:27:47Z",
						"completeness": {
							"environment": false,
							"materials": false,
							"parameters": false,
						},
						"reproducible": false,
					},
				},
				"predicateType": "https://slsa.dev/provenance/v0.2",
				"subject": null,
			},
			"entry": {
				"Attestation": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjAuMiIsInN1YmplY3QiOm51bGwsInByZWRpY2F0ZSI6eyJidWlsZGVyIjp7ImlkIjoiaHR0cHM6Ly90ZWt0b24uZGV2L2NoYWlucy92MiJ9LCJidWlsZFR5cGUiOiJodHRwczovL3Rla3Rvbi5kZXYvYXR0ZXN0YXRpb25zL2NoYWluc0B2MiIsImludm9jYXRpb24iOnsiY29uZmlnU291cmNlIjp7fSwicGFyYW1ldGVycyI6eyJpbWFnZS11cmwiOiJ7c3RyaW5nIGltYWdlLXJlZ2lzdHJ5Lm9wZW5zaGlmdC1pbWFnZS1yZWdpc3RyeS5zdmM6NTAwMC90ZWt0b24tY2hhaW5zL3NpbmdsZS1ub2RlanMtYXBwOjM2YmQ0MGQgW119IiwicmVidWlsZCI6ImZhbHNlIn19LCJidWlsZENvbmZpZyI6eyJzdGVwcyI6W3siZW50cnlQb2ludCI6IiMhL2Jpbi9iYXNoICAgIFxuZWNobyBcIkFwcCBTdHVkaW8gQnVpbGQgSW5pdGlhbGl6ZTogJChwYXJhbXMuaW1hZ2UtdXJsKVwiIFxuZWNobyBcbmVjaG8gXCJEZXRlcm1pbmUgaWYgSW1hZ2UgQWxyZWFkeSBFeGlzdHNcIlxuIyBCdWlsZCB0aGUgaW1hZ2Ugd2hlbiBpbWFnZSBkb2VzIG5vdCBleGlzdHMgb3IgcmVidWlsZCBpcyBzZXQgdG8gdHJ1ZVxuaWYgISBza29wZW8gaW5zcGVjdCAtLW5vLXRhZ3MgZG9ja2VyOi8vJChwYXJhbXMuaW1hZ2UtdXJsKSBcdTAwMjZcdTAwM2UvZGV2L251bGwgfHwgWyBcIiQocGFyYW1zLnJlYnVpbGQpXCIgPT0gXCJ0cnVlXCIgXTsgdGhlblxuICBlY2hvIC1uIFwidHJ1ZVwiIFx1MDAzZSAkKHJlc3VsdHMuYnVpbGQucGF0aClcbmVsc2VcbiAgZWNobyAtbiBcImZhbHNlXCIgXHUwMDNlICQocmVzdWx0cy5idWlsZC5wYXRoKVxuZmlcbiIsImFyZ3VtZW50cyI6bnVsbCwiZW52aXJvbm1lbnQiOnsiY29udGFpbmVyIjoiYXBwc3R1ZGlvLWluaXQiLCJpbWFnZSI6InJlZ2lzdHJ5LmFjY2Vzcy5yZWRoYXQuY29tL3ViaTgvc2tvcGVvQHNoYTI1NjpjYzU4ZGE1MGMzODQyZjVmMmE0YmE4NzgxYjYwZjYwNTI5MTlhNTU1NWEwMDBjYjRlYjE4YTBiZDAyNDFiMmIzIn0sImFubm90YXRpb25zIjpudWxsfV19LCJtZXRhZGF0YSI6eyJidWlsZFN0YXJ0ZWRPbiI6IjIwMjItMDQtMTJUMDQ6Mjc6NDdaIiwiYnVpbGRGaW5pc2hlZE9uIjoiMjAyMi0wNC0xMlQwNDoyNzo1M1oiLCJjb21wbGV0ZW5lc3MiOnsicGFyYW1ldGVycyI6ZmFsc2UsImVudmlyb25tZW50IjpmYWxzZSwibWF0ZXJpYWxzIjpmYWxzZX0sInJlcHJvZHVjaWJsZSI6ZmFsc2V9fX0=",
				"AttestationType": "",
				"Body": {"IntotoObj": {
					"content": {"hash": {
						"algorithm": "sha256",
						"value": "f318af079dc670a2446597c145342ad0292699d39d2790e041e8fa10182d4b65",
					}},
					"publicKey": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFR1RHQ0N0RHZFRS9SOHlBV1pCODE1RlppdXV5ZQpGNjY2Q0JWeEgxaExDUG9PWERQNHBYZFc3bzJsOHc3Z05mcndyYzRVWm5MUUdudHBFMDU1OVJ4eUxnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
				}},
				"IntegratedTime": 1649737674,
				"LogID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
				"LogIndex": 1977956,
				"UUID": "cab8cd734eff7b47d8baa56c0955b53b05d5cb927b8248b3fad54673ebfac5bd",
			},
		},
		"1977957": {
			"attestation": {
				"_type": "https://in-toto.io/Statement/v0.1",
				"predicate": {
					"buildConfig": {"steps": [{
						"annotations": null,
						"arguments": null,
						"entryPoint": "#!/usr/bin/env sh\nset -eu\n\nif [ \"${PARAM_VERBOSE}\" = \"true\" ] ; then\n  set -x\nfi\n\nif [ \"${WORKSPACE_BASIC_AUTH_DIRECTORY_BOUND}\" = \"true\" ] ; then\n  cp \"${WORKSPACE_BASIC_AUTH_DIRECTORY_PATH}/.git-credentials\" \"${PARAM_USER_HOME}/.git-credentials\"\n  cp \"${WORKSPACE_BASIC_AUTH_DIRECTORY_PATH}/.gitconfig\" \"${PARAM_USER_HOME}/.gitconfig\"\n  chmod 400 \"${PARAM_USER_HOME}/.git-credentials\"\n  chmod 400 \"${PARAM_USER_HOME}/.gitconfig\"\nfi\n\nif [ \"${WORKSPACE_SSH_DIRECTORY_BOUND}\" = \"true\" ] ; then\n  cp -R \"${WORKSPACE_SSH_DIRECTORY_PATH}\" \"${PARAM_USER_HOME}\"/.ssh\n  chmod 700 \"${PARAM_USER_HOME}\"/.ssh\n  chmod -R 400 \"${PARAM_USER_HOME}\"/.ssh/*\nfi\n\nCHECKOUT_DIR=\"${WORKSPACE_OUTPUT_PATH}/${PARAM_SUBDIRECTORY}\"\n\ncleandir() {\n  # Delete any existing contents of the repo directory if it exists.\n  #\n  # We don't just \"rm -rf ${CHECKOUT_DIR}\" because ${CHECKOUT_DIR} might be \"/\"\n  # or the root of a mounted volume.\n  if [ -d \"${CHECKOUT_DIR}\" ] ; then\n    # Delete non-hidden files and directories\n    rm -rf \"${CHECKOUT_DIR:?}\"/*\n    # Delete files and directories starting with . but excluding ..\n    rm -rf \"${CHECKOUT_DIR}\"/.[!.]*\n    # Delete files and directories starting with .. plus any other character\n    rm -rf \"${CHECKOUT_DIR}\"/..?*\n  fi\n}\n\nif [ \"${PARAM_DELETE_EXISTING}\" = \"true\" ] ; then\n  cleandir\nfi\n\ntest -z \"${PARAM_HTTP_PROXY}\" || export HTTP_PROXY=\"${PARAM_HTTP_PROXY}\"\ntest -z \"${PARAM_HTTPS_PROXY}\" || export HTTPS_PROXY=\"${PARAM_HTTPS_PROXY}\"\ntest -z \"${PARAM_NO_PROXY}\" || export NO_PROXY=\"${PARAM_NO_PROXY}\"\n\n/ko-app/git-init \\\n  -url=\"${PARAM_URL}\" \\\n  -revision=\"${PARAM_REVISION}\" \\\n  -refspec=\"${PARAM_REFSPEC}\" \\\n  -path=\"${CHECKOUT_DIR}\" \\\n  -sslVerify=\"${PARAM_SSL_VERIFY}\" \\\n  -submodules=\"${PARAM_SUBMODULES}\" \\\n  -depth=\"${PARAM_DEPTH}\" \\\n  -sparseCheckoutDirectories=\"${PARAM_SPARSE_CHECKOUT_DIRECTORIES}\"\ncd \"${CHECKOUT_DIR}\"\nRESULT_SHA=\"$(git rev-parse HEAD)\"\nEXIT_CODE=\"$?\"\nif [ \"${EXIT_CODE}\" != 0 ] ; then\n  exit \"${EXIT_CODE}\"\nfi\nprintf \"%s\" \"${RESULT_SHA}\" > \"$(results.commit.path)\"\nprintf \"%s\" \"${PARAM_URL}\" > \"$(results.url.path)\"\n",
						"environment": {
							"container": "clone",
							"image": "registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b1598a980f17d5f5d3d8a4b11ab4f5184677f7f17ad302baa36bd3c1",
						},
					}]},
					"buildType": "https://tekton.dev/attestations/chains@v2",
					"builder": {"id": "https://tekton.dev/chains/v2"},
					"invocation": {
						"configSource": {},
						"parameters": {
							"deleteExisting": "true",
							"depth": "1",
							"gitInitImage": "registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b1598a980f17d5f5d3d8a4b11ab4f5184677f7f17ad302baa36bd3c1",
							"httpProxy": "[]",
							"httpsProxy": "[]",
							"noProxy": "[]",
							"refspec": "[]",
							"revision": "[]",
							"sparseCheckoutDirectories": "[]",
							"sslVerify": "true",
							"subdirectory": "[]",
							"submodules": "true",
							"url": "{string https://github.com/simonbaird/single-nodejs-app []}",
							"userHome": "/tekton/home",
							"verbose": "true",
						},
					},
					"metadata": {
						"buildFinishedOn": "2022-04-12T04:28:04Z",
						"buildStartedOn": "2022-04-12T04:27:55Z",
						"completeness": {
							"environment": false,
							"materials": false,
							"parameters": false,
						},
						"reproducible": false,
					},
				},
				"predicateType": "https://slsa.dev/provenance/v0.2",
				"subject": null,
			},
			"entry": {
				"Attestation": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjAuMiIsInN1YmplY3QiOm51bGwsInByZWRpY2F0ZSI6eyJidWlsZGVyIjp7ImlkIjoiaHR0cHM6Ly90ZWt0b24uZGV2L2NoYWlucy92MiJ9LCJidWlsZFR5cGUiOiJodHRwczovL3Rla3Rvbi5kZXYvYXR0ZXN0YXRpb25zL2NoYWluc0B2MiIsImludm9jYXRpb24iOnsiY29uZmlnU291cmNlIjp7fSwicGFyYW1ldGVycyI6eyJkZWxldGVFeGlzdGluZyI6InRydWUiLCJkZXB0aCI6IjEiLCJnaXRJbml0SW1hZ2UiOiJyZWdpc3RyeS5yZWRoYXQuaW8vb3BlbnNoaWZ0LXBpcGVsaW5lcy9waXBlbGluZXMtZ2l0LWluaXQtcmhlbDhAc2hhMjU2OmFmN2RkNWIzYjE1OThhOTgwZjE3ZDVmNWQzZDhhNGIxMWFiNGY1MTg0Njc3ZjdmMTdhZDMwMmJhYTM2YmQzYzEiLCJodHRwUHJveHkiOiJbXSIsImh0dHBzUHJveHkiOiJbXSIsIm5vUHJveHkiOiJbXSIsInJlZnNwZWMiOiJbXSIsInJldmlzaW9uIjoiW10iLCJzcGFyc2VDaGVja291dERpcmVjdG9yaWVzIjoiW10iLCJzc2xWZXJpZnkiOiJ0cnVlIiwic3ViZGlyZWN0b3J5IjoiW10iLCJzdWJtb2R1bGVzIjoidHJ1ZSIsInVybCI6IntzdHJpbmcgaHR0cHM6Ly9naXRodWIuY29tL3NpbW9uYmFpcmQvc2luZ2xlLW5vZGVqcy1hcHAgW119IiwidXNlckhvbWUiOiIvdGVrdG9uL2hvbWUiLCJ2ZXJib3NlIjoidHJ1ZSJ9fSwiYnVpbGRDb25maWciOnsic3RlcHMiOlt7ImVudHJ5UG9pbnQiOiIjIS91c3IvYmluL2VudiBzaFxuc2V0IC1ldVxuXG5pZiBbIFwiJHtQQVJBTV9WRVJCT1NFfVwiID0gXCJ0cnVlXCIgXSA7IHRoZW5cbiAgc2V0IC14XG5maVxuXG5pZiBbIFwiJHtXT1JLU1BBQ0VfQkFTSUNfQVVUSF9ESVJFQ1RPUllfQk9VTkR9XCIgPSBcInRydWVcIiBdIDsgdGhlblxuICBjcCBcIiR7V09SS1NQQUNFX0JBU0lDX0FVVEhfRElSRUNUT1JZX1BBVEh9Ly5naXQtY3JlZGVudGlhbHNcIiBcIiR7UEFSQU1fVVNFUl9IT01FfS8uZ2l0LWNyZWRlbnRpYWxzXCJcbiAgY3AgXCIke1dPUktTUEFDRV9CQVNJQ19BVVRIX0RJUkVDVE9SWV9QQVRIfS8uZ2l0Y29uZmlnXCIgXCIke1BBUkFNX1VTRVJfSE9NRX0vLmdpdGNvbmZpZ1wiXG4gIGNobW9kIDQwMCBcIiR7UEFSQU1fVVNFUl9IT01FfS8uZ2l0LWNyZWRlbnRpYWxzXCJcbiAgY2htb2QgNDAwIFwiJHtQQVJBTV9VU0VSX0hPTUV9Ly5naXRjb25maWdcIlxuZmlcblxuaWYgWyBcIiR7V09SS1NQQUNFX1NTSF9ESVJFQ1RPUllfQk9VTkR9XCIgPSBcInRydWVcIiBdIDsgdGhlblxuICBjcCAtUiBcIiR7V09SS1NQQUNFX1NTSF9ESVJFQ1RPUllfUEFUSH1cIiBcIiR7UEFSQU1fVVNFUl9IT01FfVwiLy5zc2hcbiAgY2htb2QgNzAwIFwiJHtQQVJBTV9VU0VSX0hPTUV9XCIvLnNzaFxuICBjaG1vZCAtUiA0MDAgXCIke1BBUkFNX1VTRVJfSE9NRX1cIi8uc3NoLypcbmZpXG5cbkNIRUNLT1VUX0RJUj1cIiR7V09SS1NQQUNFX09VVFBVVF9QQVRIfS8ke1BBUkFNX1NVQkRJUkVDVE9SWX1cIlxuXG5jbGVhbmRpcigpIHtcbiAgIyBEZWxldGUgYW55IGV4aXN0aW5nIGNvbnRlbnRzIG9mIHRoZSByZXBvIGRpcmVjdG9yeSBpZiBpdCBleGlzdHMuXG4gICNcbiAgIyBXZSBkb24ndCBqdXN0IFwicm0gLXJmICR7Q0hFQ0tPVVRfRElSfVwiIGJlY2F1c2UgJHtDSEVDS09VVF9ESVJ9IG1pZ2h0IGJlIFwiL1wiXG4gICMgb3IgdGhlIHJvb3Qgb2YgYSBtb3VudGVkIHZvbHVtZS5cbiAgaWYgWyAtZCBcIiR7Q0hFQ0tPVVRfRElSfVwiIF0gOyB0aGVuXG4gICAgIyBEZWxldGUgbm9uLWhpZGRlbiBmaWxlcyBhbmQgZGlyZWN0b3JpZXNcbiAgICBybSAtcmYgXCIke0NIRUNLT1VUX0RJUjo/fVwiLypcbiAgICAjIERlbGV0ZSBmaWxlcyBhbmQgZGlyZWN0b3JpZXMgc3RhcnRpbmcgd2l0aCAuIGJ1dCBleGNsdWRpbmcgLi5cbiAgICBybSAtcmYgXCIke0NIRUNLT1VUX0RJUn1cIi8uWyEuXSpcbiAgICAjIERlbGV0ZSBmaWxlcyBhbmQgZGlyZWN0b3JpZXMgc3RhcnRpbmcgd2l0aCAuLiBwbHVzIGFueSBvdGhlciBjaGFyYWN0ZXJcbiAgICBybSAtcmYgXCIke0NIRUNLT1VUX0RJUn1cIi8uLj8qXG4gIGZpXG59XG5cbmlmIFsgXCIke1BBUkFNX0RFTEVURV9FWElTVElOR31cIiA9IFwidHJ1ZVwiIF0gOyB0aGVuXG4gIGNsZWFuZGlyXG5maVxuXG50ZXN0IC16IFwiJHtQQVJBTV9IVFRQX1BST1hZfVwiIHx8IGV4cG9ydCBIVFRQX1BST1hZPVwiJHtQQVJBTV9IVFRQX1BST1hZfVwiXG50ZXN0IC16IFwiJHtQQVJBTV9IVFRQU19QUk9YWX1cIiB8fCBleHBvcnQgSFRUUFNfUFJPWFk9XCIke1BBUkFNX0hUVFBTX1BST1hZfVwiXG50ZXN0IC16IFwiJHtQQVJBTV9OT19QUk9YWX1cIiB8fCBleHBvcnQgTk9fUFJPWFk9XCIke1BBUkFNX05PX1BST1hZfVwiXG5cbi9rby1hcHAvZ2l0LWluaXQgXFxcbiAgLXVybD1cIiR7UEFSQU1fVVJMfVwiIFxcXG4gIC1yZXZpc2lvbj1cIiR7UEFSQU1fUkVWSVNJT059XCIgXFxcbiAgLXJlZnNwZWM9XCIke1BBUkFNX1JFRlNQRUN9XCIgXFxcbiAgLXBhdGg9XCIke0NIRUNLT1VUX0RJUn1cIiBcXFxuICAtc3NsVmVyaWZ5PVwiJHtQQVJBTV9TU0xfVkVSSUZZfVwiIFxcXG4gIC1zdWJtb2R1bGVzPVwiJHtQQVJBTV9TVUJNT0RVTEVTfVwiIFxcXG4gIC1kZXB0aD1cIiR7UEFSQU1fREVQVEh9XCIgXFxcbiAgLXNwYXJzZUNoZWNrb3V0RGlyZWN0b3JpZXM9XCIke1BBUkFNX1NQQVJTRV9DSEVDS09VVF9ESVJFQ1RPUklFU31cIlxuY2QgXCIke0NIRUNLT1VUX0RJUn1cIlxuUkVTVUxUX1NIQT1cIiQoZ2l0IHJldi1wYXJzZSBIRUFEKVwiXG5FWElUX0NPREU9XCIkP1wiXG5pZiBbIFwiJHtFWElUX0NPREV9XCIgIT0gMCBdIDsgdGhlblxuICBleGl0IFwiJHtFWElUX0NPREV9XCJcbmZpXG5wcmludGYgXCIlc1wiIFwiJHtSRVNVTFRfU0hBfVwiIFx1MDAzZSBcIiQocmVzdWx0cy5jb21taXQucGF0aClcIlxucHJpbnRmIFwiJXNcIiBcIiR7UEFSQU1fVVJMfVwiIFx1MDAzZSBcIiQocmVzdWx0cy51cmwucGF0aClcIlxuIiwiYXJndW1lbnRzIjpudWxsLCJlbnZpcm9ubWVudCI6eyJjb250YWluZXIiOiJjbG9uZSIsImltYWdlIjoicmVnaXN0cnkucmVkaGF0LmlvL29wZW5zaGlmdC1waXBlbGluZXMvcGlwZWxpbmVzLWdpdC1pbml0LXJoZWw4QHNoYTI1NjphZjdkZDViM2IxNTk4YTk4MGYxN2Q1ZjVkM2Q4YTRiMTFhYjRmNTE4NDY3N2Y3ZjE3YWQzMDJiYWEzNmJkM2MxIn0sImFubm90YXRpb25zIjpudWxsfV19LCJtZXRhZGF0YSI6eyJidWlsZFN0YXJ0ZWRPbiI6IjIwMjItMDQtMTJUMDQ6Mjc6NTVaIiwiYnVpbGRGaW5pc2hlZE9uIjoiMjAyMi0wNC0xMlQwNDoyODowNFoiLCJjb21wbGV0ZW5lc3MiOnsicGFyYW1ldGVycyI6ZmFsc2UsImVudmlyb25tZW50IjpmYWxzZSwibWF0ZXJpYWxzIjpmYWxzZX0sInJlcHJvZHVjaWJsZSI6ZmFsc2V9fX0=",
				"AttestationType": "",
				"Body": {"IntotoObj": {
					"content": {"hash": {
						"algorithm": "sha256",
						"value": "129496702986501f3477d476e19d30be95160ebfa6353aaff471f35c46e95829",
					}},
					"publicKey": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFR1RHQ0N0RHZFRS9SOHlBV1pCODE1RlppdXV5ZQpGNjY2Q0JWeEgxaExDUG9PWERQNHBYZFc3bzJsOHc3Z05mcndyYzRVWm5MUUdudHBFMDU1OVJ4eUxnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
				}},
				"IntegratedTime": 1649737684,
				"LogID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
				"LogIndex": 1977957,
				"UUID": "60548dbd4e927736849bfced9a6ae0827811fba1b61195a6a891434ce8113d81",
			},
		},
		"1977959": {
			"attestation": {
				"_type": "https://in-toto.io/Statement/v0.1",
				"predicate": {
					"buildConfig": {"steps": [{
						"annotations": null,
						"arguments": null,
						"entryPoint": "#!/usr/bin/env bash    \necho \"App Studio Configure Build\" \n\nAUTH=/workspace/registry-auth/.dockerconfigjson\nDEST=/workspace/source/.dockerconfigjson\necho \"Looking for Registry Auth Config: $AUTH\"\nif [ -f \"$AUTH\" ]; then\n  echo \"$AUTH found\" \n  echo\n\n  cp $AUTH $DEST\n\n  echo -n $DEST > /tekton/results/registry-auth  \n  echo -n \"--authfile $DEST\"  >  /tekton/results/buildah-auth-param\n  echo \nelse  \n  echo \"No $AUTH found.\" \n  echo -n \" \" > /tekton/results/registry-auth  \n  echo -n \" \" > /tekton/results/buildah-auth-param\n  echo \nfi\n",
						"environment": {
							"container": "appstudio-configure-build",
							"image": "registry.access.redhat.com/ubi8-minimal@sha256:574f201d7ed185a9932c91cef5d397f5298dff9df08bc2ebb266c6d1e6284cd1",
						},
					}]},
					"buildType": "https://tekton.dev/attestations/chains@v2",
					"builder": {"id": "https://tekton.dev/chains/v2"},
					"invocation": {
						"configSource": {},
						"parameters": {},
					},
					"metadata": {
						"buildFinishedOn": "2022-04-12T04:28:12Z",
						"buildStartedOn": "2022-04-12T04:28:04Z",
						"completeness": {
							"environment": false,
							"materials": false,
							"parameters": false,
						},
						"reproducible": false,
					},
				},
				"predicateType": "https://slsa.dev/provenance/v0.2",
				"subject": null,
			},
			"entry": {
				"Attestation": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjAuMiIsInN1YmplY3QiOm51bGwsInByZWRpY2F0ZSI6eyJidWlsZGVyIjp7ImlkIjoiaHR0cHM6Ly90ZWt0b24uZGV2L2NoYWlucy92MiJ9LCJidWlsZFR5cGUiOiJodHRwczovL3Rla3Rvbi5kZXYvYXR0ZXN0YXRpb25zL2NoYWluc0B2MiIsImludm9jYXRpb24iOnsiY29uZmlnU291cmNlIjp7fSwicGFyYW1ldGVycyI6e319LCJidWlsZENvbmZpZyI6eyJzdGVwcyI6W3siZW50cnlQb2ludCI6IiMhL3Vzci9iaW4vZW52IGJhc2ggICAgXG5lY2hvIFwiQXBwIFN0dWRpbyBDb25maWd1cmUgQnVpbGRcIiBcblxuQVVUSD0vd29ya3NwYWNlL3JlZ2lzdHJ5LWF1dGgvLmRvY2tlcmNvbmZpZ2pzb25cbkRFU1Q9L3dvcmtzcGFjZS9zb3VyY2UvLmRvY2tlcmNvbmZpZ2pzb25cbmVjaG8gXCJMb29raW5nIGZvciBSZWdpc3RyeSBBdXRoIENvbmZpZzogJEFVVEhcIlxuaWYgWyAtZiBcIiRBVVRIXCIgXTsgdGhlblxuICBlY2hvIFwiJEFVVEggZm91bmRcIiBcbiAgZWNob1xuXG4gIGNwICRBVVRIICRERVNUXG5cbiAgZWNobyAtbiAkREVTVCBcdTAwM2UgL3Rla3Rvbi9yZXN1bHRzL3JlZ2lzdHJ5LWF1dGggIFxuICBlY2hvIC1uIFwiLS1hdXRoZmlsZSAkREVTVFwiICBcdTAwM2UgIC90ZWt0b24vcmVzdWx0cy9idWlsZGFoLWF1dGgtcGFyYW1cbiAgZWNobyBcbmVsc2UgIFxuICBlY2hvIFwiTm8gJEFVVEggZm91bmQuXCIgXG4gIGVjaG8gLW4gXCIgXCIgXHUwMDNlIC90ZWt0b24vcmVzdWx0cy9yZWdpc3RyeS1hdXRoICBcbiAgZWNobyAtbiBcIiBcIiBcdTAwM2UgL3Rla3Rvbi9yZXN1bHRzL2J1aWxkYWgtYXV0aC1wYXJhbVxuICBlY2hvIFxuZmlcbiIsImFyZ3VtZW50cyI6bnVsbCwiZW52aXJvbm1lbnQiOnsiY29udGFpbmVyIjoiYXBwc3R1ZGlvLWNvbmZpZ3VyZS1idWlsZCIsImltYWdlIjoicmVnaXN0cnkuYWNjZXNzLnJlZGhhdC5jb20vdWJpOC1taW5pbWFsQHNoYTI1Njo1NzRmMjAxZDdlZDE4NWE5OTMyYzkxY2VmNWQzOTdmNTI5OGRmZjlkZjA4YmMyZWJiMjY2YzZkMWU2Mjg0Y2QxIn0sImFubm90YXRpb25zIjpudWxsfV19LCJtZXRhZGF0YSI6eyJidWlsZFN0YXJ0ZWRPbiI6IjIwMjItMDQtMTJUMDQ6Mjg6MDRaIiwiYnVpbGRGaW5pc2hlZE9uIjoiMjAyMi0wNC0xMlQwNDoyODoxMloiLCJjb21wbGV0ZW5lc3MiOnsicGFyYW1ldGVycyI6ZmFsc2UsImVudmlyb25tZW50IjpmYWxzZSwibWF0ZXJpYWxzIjpmYWxzZX0sInJlcHJvZHVjaWJsZSI6ZmFsc2V9fX0=",
				"AttestationType": "",
				"Body": {"IntotoObj": {
					"content": {"hash": {
						"algorithm": "sha256",
						"value": "a5518ef0c889cf3e4d4e46c1b0f99fdd2eccd7d7ca6dae7a90aaa757d34c9a56",
					}},
					"publicKey": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFR1RHQ0N0RHZFRS9SOHlBV1pCODE1RlppdXV5ZQpGNjY2Q0JWeEgxaExDUG9PWERQNHBYZFc3bzJsOHc3Z05mcndyYzRVWm5MUUdudHBFMDU1OVJ4eUxnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
				}},
				"IntegratedTime": 1649737692,
				"LogID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
				"LogIndex": 1977959,
				"UUID": "b9f63e6e243c981053933135ceba5907e495b5eb02e8dca4520cd6635b6939fa",
			},
		},
		"1977978": {
			"attestation": {
				"_type": "https://in-toto.io/Statement/v0.1",
				"predicate": {
					"buildConfig": {"steps": [{
						"annotations": null,
						"arguments": null,
						"entryPoint": "#!/usr/bin/env bash    \necho  \necho \"App Studio Build Summary:\"\necho\necho \"Build repository: $(params.git-url)\" \necho \"Generated Image is in : $(params.image-url)\"  \necho  \noc annotate pipelinerun $(params.pipeline-run-name) build.appstudio.openshift.io/repo=$(params.git-url)\noc annotate pipelinerun $(params.pipeline-run-name) build.appstudio.openshift.io/image=$(params.image-url)\n\necho \"Output is in the following annotations:\"\n\necho \"Build Repo is in 'build.appstudio.openshift.io/repo' \"\necho 'oc get pr $(params.pipeline-run-name) -o jsonpath=\"{.metadata.annotations.build\\.appstudio\\.openshift\\.io/repo}\"' \n\necho \"Build Image is in 'build.appstudio.openshift.io/image' \"\necho 'oc get pr $(params.pipeline-run-name) -o jsonpath=\"{.metadata.annotations.build\\.appstudio\\.openshift\\.io/image}\"' \n\necho End Summary\n",
						"environment": {
							"container": "appstudio-summary",
							"image": "registry.redhat.io/openshift4/ose-cli@sha256:9a1ca7a36cfdd6c69398b35a7311db662ca7c652e6e8bd440a6331c12f89703a",
						},
					}]},
					"buildType": "https://tekton.dev/attestations/chains@v2",
					"builder": {"id": "https://tekton.dev/chains/v2"},
					"invocation": {
						"configSource": {},
						"parameters": {
							"git-url": "{string https://github.com/simonbaird/single-nodejs-app []}",
							"image-url": "{string image-registry.openshift-image-registry.svc:5000/tekton-chains/single-nodejs-app:36bd40d []}",
							"pipeline-run-name": "{string nodejs-builder-2022-04-12-002742 []}",
						},
					},
					"metadata": {
						"buildFinishedOn": "2022-04-12T04:29:16Z",
						"buildStartedOn": "2022-04-12T04:29:10Z",
						"completeness": {
							"environment": false,
							"materials": false,
							"parameters": false,
						},
						"reproducible": false,
					},
				},
				"predicateType": "https://slsa.dev/provenance/v0.2",
				"subject": null,
			},
			"entry": {
				"Attestation": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjAuMiIsInN1YmplY3QiOm51bGwsInByZWRpY2F0ZSI6eyJidWlsZGVyIjp7ImlkIjoiaHR0cHM6Ly90ZWt0b24uZGV2L2NoYWlucy92MiJ9LCJidWlsZFR5cGUiOiJodHRwczovL3Rla3Rvbi5kZXYvYXR0ZXN0YXRpb25zL2NoYWluc0B2MiIsImludm9jYXRpb24iOnsiY29uZmlnU291cmNlIjp7fSwicGFyYW1ldGVycyI6eyJnaXQtdXJsIjoie3N0cmluZyBodHRwczovL2dpdGh1Yi5jb20vc2ltb25iYWlyZC9zaW5nbGUtbm9kZWpzLWFwcCBbXX0iLCJpbWFnZS11cmwiOiJ7c3RyaW5nIGltYWdlLXJlZ2lzdHJ5Lm9wZW5zaGlmdC1pbWFnZS1yZWdpc3RyeS5zdmM6NTAwMC90ZWt0b24tY2hhaW5zL3NpbmdsZS1ub2RlanMtYXBwOjM2YmQ0MGQgW119IiwicGlwZWxpbmUtcnVuLW5hbWUiOiJ7c3RyaW5nIG5vZGVqcy1idWlsZGVyLTIwMjItMDQtMTItMDAyNzQyIFtdfSJ9fSwiYnVpbGRDb25maWciOnsic3RlcHMiOlt7ImVudHJ5UG9pbnQiOiIjIS91c3IvYmluL2VudiBiYXNoICAgIFxuZWNobyAgXG5lY2hvIFwiQXBwIFN0dWRpbyBCdWlsZCBTdW1tYXJ5OlwiXG5lY2hvXG5lY2hvIFwiQnVpbGQgcmVwb3NpdG9yeTogJChwYXJhbXMuZ2l0LXVybClcIiBcbmVjaG8gXCJHZW5lcmF0ZWQgSW1hZ2UgaXMgaW4gOiAkKHBhcmFtcy5pbWFnZS11cmwpXCIgIFxuZWNobyAgXG5vYyBhbm5vdGF0ZSBwaXBlbGluZXJ1biAkKHBhcmFtcy5waXBlbGluZS1ydW4tbmFtZSkgYnVpbGQuYXBwc3R1ZGlvLm9wZW5zaGlmdC5pby9yZXBvPSQocGFyYW1zLmdpdC11cmwpXG5vYyBhbm5vdGF0ZSBwaXBlbGluZXJ1biAkKHBhcmFtcy5waXBlbGluZS1ydW4tbmFtZSkgYnVpbGQuYXBwc3R1ZGlvLm9wZW5zaGlmdC5pby9pbWFnZT0kKHBhcmFtcy5pbWFnZS11cmwpXG5cbmVjaG8gXCJPdXRwdXQgaXMgaW4gdGhlIGZvbGxvd2luZyBhbm5vdGF0aW9uczpcIlxuXG5lY2hvIFwiQnVpbGQgUmVwbyBpcyBpbiAnYnVpbGQuYXBwc3R1ZGlvLm9wZW5zaGlmdC5pby9yZXBvJyBcIlxuZWNobyAnb2MgZ2V0IHByICQocGFyYW1zLnBpcGVsaW5lLXJ1bi1uYW1lKSAtbyBqc29ucGF0aD1cInsubWV0YWRhdGEuYW5ub3RhdGlvbnMuYnVpbGRcXC5hcHBzdHVkaW9cXC5vcGVuc2hpZnRcXC5pby9yZXBvfVwiJyBcblxuZWNobyBcIkJ1aWxkIEltYWdlIGlzIGluICdidWlsZC5hcHBzdHVkaW8ub3BlbnNoaWZ0LmlvL2ltYWdlJyBcIlxuZWNobyAnb2MgZ2V0IHByICQocGFyYW1zLnBpcGVsaW5lLXJ1bi1uYW1lKSAtbyBqc29ucGF0aD1cInsubWV0YWRhdGEuYW5ub3RhdGlvbnMuYnVpbGRcXC5hcHBzdHVkaW9cXC5vcGVuc2hpZnRcXC5pby9pbWFnZX1cIicgXG5cbmVjaG8gRW5kIFN1bW1hcnlcbiIsImFyZ3VtZW50cyI6bnVsbCwiZW52aXJvbm1lbnQiOnsiY29udGFpbmVyIjoiYXBwc3R1ZGlvLXN1bW1hcnkiLCJpbWFnZSI6InJlZ2lzdHJ5LnJlZGhhdC5pby9vcGVuc2hpZnQ0L29zZS1jbGlAc2hhMjU2OjlhMWNhN2EzNmNmZGQ2YzY5Mzk4YjM1YTczMTFkYjY2MmNhN2M2NTJlNmU4YmQ0NDBhNjMzMWMxMmY4OTcwM2EifSwiYW5ub3RhdGlvbnMiOm51bGx9XX0sIm1ldGFkYXRhIjp7ImJ1aWxkU3RhcnRlZE9uIjoiMjAyMi0wNC0xMlQwNDoyOToxMFoiLCJidWlsZEZpbmlzaGVkT24iOiIyMDIyLTA0LTEyVDA0OjI5OjE2WiIsImNvbXBsZXRlbmVzcyI6eyJwYXJhbWV0ZXJzIjpmYWxzZSwiZW52aXJvbm1lbnQiOmZhbHNlLCJtYXRlcmlhbHMiOmZhbHNlfSwicmVwcm9kdWNpYmxlIjpmYWxzZX19fQ==",
				"AttestationType": "",
				"Body": {"IntotoObj": {
					"content": {"hash": {
						"algorithm": "sha256",
						"value": "9d491972ab0c21607a01fca49a892b180ee62c04988a783e742ab4596ae20b23",
					}},
					"publicKey": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFR1RHQ0N0RHZFRS9SOHlBV1pCODE1RlppdXV5ZQpGNjY2Q0JWeEgxaExDUG9PWERQNHBYZFc3bzJsOHc3Z05mcndyYzRVWm5MUUdudHBFMDU1OVJ4eUxnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
				}},
				"IntegratedTime": 1649737756,
				"LogID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
				"LogIndex": 1977978,
				"UUID": "edd9656484cb717fedd6878fa0c13c1850a609b2ae7ba6ff2034c53f92b93516",
			},
		},
	}}},
}
