# Samples

This directory contains sample files meant to use in the acceptance test scenarios.

[policy-input-golden-container.json](./policy-input-golden-container.json) holds the
[policy input](https://enterprisecontract.dev/docs/ec-cli/main/policy_input.html) as created by the
the EC CLI. This is the output of executing `ec validate input ... --output policy-input`. If
recreating this file is needed, be sure to provide source information alongside with the image
reference, for example:

```text
$ cat images.json
{
  "components": [
    {
      "containerImage": "quay.io/redhat-appstudio/ec-golden-image:latest",
      "source": {
        "git": {
          "revision": "68b69547cad3c4ba856fe6b06154012f33dd8b5a",
          "url": "https://github.com/enterprise-contract/golden-container.git"
        }
      }
    }
  ]
}

$ ec validate image --images images.json --output policy-input \
    --public-key cosign.pub --ignore-rekor --policy policy.json
```

[clamav-task.json](./clamav-task.json) contains a Task definition. It is a direct copy of the
[ClamAV Task](https://github.com/redhat-appstudio/build-definitions/tree/main/task/clamav-scan)
found in the
[build-definitions](https://github.com/redhat-appstudio/build-definitions) repository. To fetch the
latest:

```text
curl -L https://raw.githubusercontent.com/redhat-appstudio/build-definitions/main/task/clamav-scan/0.1/clamav-scan.yaml | \
  yq '.' -o json  > acceptance/samples/clamav-task.json
```
