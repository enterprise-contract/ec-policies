
HACBS Enterprise Contract Policies
==================================

About
-----

The HACBS Enterprise Contract is a Tekton task that can be used to verify the
provenence of container images built in HACBS and validate them against a set of
policies.

Those policies are defined using the
<a href="https://www.openpolicyagent.org/docs/latest/policy-language/">rego policy language</a>
and are described here.

Pipeline Policy
---------------

### Basic Rules

#### `[unexpected_kind]` Check the kind is "Pipeline"

A sanity check to confirm the input data has the expected kind.

* Path: `data.policy.pipeline.basic.deny`
* Failure message: `Unexpected kind '%s'`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policy/pipeline/basic.rego#L19)

Release Policy
---------------

### Attestation Task Bundle Rules

#### `[disallowed_task_reference]` Task bundle was not used or is not defined

Check for existence of a task bundle. Enforcing this rule will
fail the contract if the task is not called from a bundle.

* Path: `data.policy.release.attestation_task_bundle.warn`
* Failure message: `Task '%s' does not contain a bundle reference`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/attestation_task_bundle.rego#L13)

#### `[disallowed_task_bundle]` Task bundle was used that was disallowed

Check for existence of a valid task bundle. Enforcing this rule will
fail the contract if the task is not called using a valid bundle image.

* Path: `data.policy.release.attestation_task_bundle.warn`
* Failure message: `Task '%s' has disallowed bundle image '%s'`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/attestation_task_bundle.rego#L32)

### Attestation Type Rules

#### `[unknown_att_type]` Unknown attestation type found

A sanity check that the attestation found for the image has the expected
attestation type. Currently there is only one attestation type supported,
`https://in-toto.io/Statement/v0.1`.

* Path: `data.policy.release.attestation_type.deny`
* Failure message: `Unknown attestation type '%s'`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/attestation_type.rego#L18)

### Not Useful Rules

#### `[bad_day]` A dummy rule that always fails

It's expected this rule will be skipped by policy configuration.
This rule is for demonstration and test purposes and should be deleted soon.

* Path: `data.policy.release.not_useful.deny`
* Failure message: `It just feels like a bad day to do a release`
* Effective from: `Sat, 01 Jan 2022 00:00:00 +0000`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/not_useful.rego#L15)

### Step Image Registries Rules

#### `[disallowed_task_step_image]` Task steps ran on container images that are disallowed

Enterprise Contract has a list of allowed registry prefixes. Each step in each
each TaskRun must run on a container image with a url that matches one of the
prefixes in the list.

The permitted registry prefixes are:

```
quay.io/redhat-appstudio/
registry.access.redhat.com/
registry.redhat.io/
```

* Path: `data.policy.release.step_image_registries.deny`
* Failure message: `Step %d in task '%s' has disallowed image ref '%s'`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/step_image_registries.rego#L19)

### Test Rules

#### `[test_data_missing]` No test data found

None of the tasks in the pipeline included a HACBS_TEST_OUTPUT
task result, which is where Enterprise Contract expects to find
test result data.

* Path: `data.policy.release.test.deny`
* Failure message: `No test data found`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/test.rego#L15)

#### `[test_results_missing]` Test data is missing the results key

Each test result is expected to have a 'results' key. In at least
one of the HACBS_TEST_OUTPUT task results this key was not present.

* Path: `data.policy.release.test.deny`
* Failure message: `Found tests without results`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/test.rego#L29)

#### `[test_result_failures]` Some tests did not pass

Enterprise Contract requires that all the tests in the
test results have a result of 'SUCCESS'. This will fail if any
of the tests failed and the failure message will list the names
of the failing tests.

* Path: `data.policy.release.test.deny`
* Failure message: `The following tests did not complete successfully: %s`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/test.rego#L46)

See Also
--------

* ["Verify Enterprise Contract" task definition](https://github.com/redhat-appstudio/build-definitions/blob/main/tasks/verify-enterprise-contract.yaml)
* [github.com/hacbs-contract/ec-policies](https://github.com/hacbs-contract/ec-policies)
* [github.com/hacbs-contract](https://github.com/hacbs-contract)
* [github.com/redhat-appstudio](https://github.com/redhat-appstudio)
