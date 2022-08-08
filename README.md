ec-policies
===========

[Rego][rego] policies related to the HACBS Enterprise Contract.


Getting started for developers
------------------------------

### Makefile

The [`Makefile`](Makefile) contains a lot of useful scripts and commands. Run
`make` by itself to see the help.

### Dependencies

Three tools are required, [`conftest`][conftest], [`opa`][opa], and [`gomplate`][gomplate].

You should be able to install them like this:

    make install-tools

If that doesn't work, installing them manually and making sure they're
available in your path should be fine.

An optional but useful tool for running tests while developing, (with `make
live-test`), is [`entr`][entr]. You can install it with `dnf`:

    sudo dnf install entr

And of course you need make if you don't have it already:

    sudo dnf install make

### Formatting

The rego files should be formatted using the standard format. To apply the
standard format run this before committing:

    make fmt

### Building the docs

The documentation is built using Antora. Install Antora as per [the
instructions][antora] and then you should be able to build the docs like
this:

    make docs-refresh

Those docs are published [here][docs] and imported automatically into the
official [HACBS Documentation][hacbsdocs].

### Running tests

From the top level directory you can run all tests and formatting checks, as
well as check that the docs are up to date, like this:

    make ci

You can run a single test like this:

    opa test . -r <test_name_matcher>

The `<test_name_matcher>` is a regex, so you can use it to run more than one
test.

See [`Makefile`](Makefile) for other ways to run the tests.

### Writing tests

Policies must have unit tests validating them.
All test files must adhere to the naming convention:

    file.rego
    file_test.rego

Refer to the [policy testing docs][testing] for more information.

The CI also enforces that there is 100% test coverage. If you're not at 100%
you can use this to show what lines of code are not covered:

    make coverage

### Running policies against real pipline run image build attestations

Fetch an image attestation from a registry:

    make fetch-att
    more input/input.json # to look at it

or:

    make fetch-att IMAGE=<some-image-with-an-attestation-ref>

Create a dummy policy config file:

    make dummy-config
    cat data/config.json # to look at it

Then to verify the build using the defined policies:

    make check-release

### Running policies against real pipeline definitions

For example to fetch a pipeline definition from your local cluster:

    make fetch-pipeline
    make fetch-pipeline PIPELINE=<some-pipeline-name>
    more input/input.json # to look at it

For a realistic HACBS pipeline definition that does't require cluster access,
if you you have the [build-definitions][builddefs] repo checked out nearby you
can do something like this:

    ( cd ../build-definitions && kustomize build pipelines/hacbs | yq 'select(document_index == 2)' -o json ) > input/input.json

Then to verify the pipeline definition using the defined policies:

    make check-pipeline


Getting started for policy authors
----------------------------------

See the [Policy Authoring][authoring] documentation for guidance on
contributing to the definition of policy rules.


See also
--------

* [Policy rule documentation][hacbsdocs]
* ["Verify Enterprise Contract" task definition][taskdef]
* [github.com/hacbs-contract][contract]
* [github.com/redhat-appstudio][appstudio]

[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[conftest]: https://www.conftest.dev/
[opa]: https://www.openpolicyagent.org/docs/latest/
[gomplate]: https://docs.gomplate.ca/
[entr]: https://github.com/eradman/entr
[testing]: https://www.openpolicyagent.org/docs/latest/policy-testing/
[docs]: https://hacbs-contract.github.io/ec-policies/
[hacbsdocs]: https://red-hat-hybrid-application-cloud-build-services-documentation.pages.redhat.com/hacbs-documentation/ec-policies/index.html
[taskdef]: https://github.com/redhat-appstudio/build-definitions/blob/main/tasks/verify-enterprise-contract.yaml
[contract]: https://github.com/hacbs-contract
[appstudio]: https://github.com/redhat-appstudio
[builddefs]: https://github.com/redhat-appstudio/build-definitions
[authoring]: https://hacbs-contract.github.io/ec-policies/ec-policies/authoring.html
[antora]: https://docs.antora.org/antora/latest/install-and-run-quickstart/
