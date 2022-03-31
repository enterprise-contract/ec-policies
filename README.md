ec-policies
===========

[Rego][rego] policies related to the HACBS Enterprise Contract.


Dependencies
------------

You need [opa][opa] which can be installed by following the instructions
[here][opa-download].

If you're using Linux you can install it like this:

    make install-opa


Running tests
-------------

From the top level directory you can run all tests like this:

    make test


See also
--------

* [hacbs/ec-tasks](https://github.com/hacbs-contract/ec-tasks)
* [app-studio/infra-deployments](https://github.com/hacbs-contract/infra-deployments)



[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[opa]: https://www.openpolicyagent.org/docs/latest/
[opa-download]: https://www.openpolicyagent.org/docs/latest/#1-download-opa
